use anyhow::{Context, Result, bail};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use hivemind_core::{
    ApiSurface, IntegrityTier, ModelBackendFeature, ModelBackendType, ModelColdStartPolicyV1,
    ModelLifecycleStateKind, ModelLifecycleStateV1, PrivacyTier, ProviderAuthMode,
    ProviderChatReceiptV1, ProviderChatRequestV1, ProviderHealthV1, ProviderIdentityV1,
    ProviderJobCancelRequestV1, ProviderJobCancelResponseV1, ProviderJobCancellationStatus,
    ProviderModelOfferV1, ProviderModelStartRequestV1, ProviderModelStopRequestV1,
    ProviderPaymentMode, ProviderPriceTermsV1, ProviderQuoteRequestV1, ProviderQuoteV1,
    ProviderReadinessLabel, ProviderSecurityMode, ProviderSessionCloseRequestV1,
    ProviderSessionLimitsV1, ProviderSessionOpenRequestV1, ProviderSessionStatus,
    ProviderSessionSummaryV1, ProviderSessionV1, ProviderStatus, ProviderStreamEventType,
    ProviderStreamEventV1, ProviderUsageV1, PseudoLedgerEventType, PseudoLedgerEventV1,
    PseudoPaymentPolicyV1, PseudoPaymentSessionV1, PseudoPaymentStateV1, SignedRequestEnvelopeV1,
    UsageConfidence, apply_pseudo_payment_debit, apply_pseudo_payment_forgiveness,
    apply_pseudo_payment_session_close, hash_canonical_json, provider_chat_usage_cost,
    provider_security_mode_allows_bind, pseudo_payment_state, validate_signed_request_envelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration as StdDuration, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

const PROVIDER_STATE_SCHEMA_VERSION: &str = "hivemind.provider.local_state.v1";

#[derive(Debug, Clone)]
pub struct ServeProviderConfig {
    pub host: String,
    pub port: u16,
    pub security_mode: ProviderSecurityMode,
    pub bearer_token: Option<String>,
    pub provider_id: String,
    pub display_name: String,
    pub model_id: String,
    pub model_display_name: String,
    pub backend_type: ModelBackendType,
    pub backend_model_id: String,
    pub backend_base_url: Option<String>,
    pub backend_api_key: Option<String>,
    pub backend_timeout_seconds: u64,
    pub backend_start_command: Option<String>,
    pub backend_start_args: Vec<String>,
    pub backend_health_url: Option<String>,
    pub max_debt: f64,
    pub forgiveness_per_second: f64,
    pub price_per_input_token: f64,
    pub price_per_output_token: f64,
    pub price_per_model_second: f64,
    pub price_per_request: f64,
    pub state_path: PathBuf,
    pub require_signed_requests: bool,
    pub max_concurrent_sessions: u32,
    pub max_concurrent_jobs: u32,
    pub max_context_tokens: u64,
    pub max_output_tokens: u64,
    pub max_prompt_bytes: usize,
    pub max_prompt_messages: usize,
    pub max_model_starts_per_hour: u32,
    pub max_cold_start_seconds: u64,
    pub initial_model_state: Option<ModelLifecycleStateKind>,
}

#[derive(Debug, Clone)]
struct ProviderState {
    started_at: Instant,
    identity: ProviderIdentityV1,
    offer: ProviderModelOfferV1,
    policy: PseudoPaymentPolicyV1,
    backend: ProviderBackend,
    security_mode: ProviderSecurityMode,
    auth_modes: Vec<ProviderAuthMode>,
    bearer_token: Option<Arc<String>>,
    require_signed_requests: bool,
    state_path: Arc<PathBuf>,
    signed_request_nonces: Arc<Mutex<BTreeMap<String, DateTime<Utc>>>>,
    sessions: Arc<Mutex<BTreeMap<String, StoredProviderSession>>>,
    receipts: Arc<Mutex<BTreeMap<String, ProviderChatReceiptV1>>>,
    model_lifecycle: Arc<Mutex<StoredProviderModelLifecycle>>,
    active_jobs: Arc<AtomicU32>,
    active_job_records: Arc<Mutex<BTreeMap<String, ActiveProviderJob>>>,
    max_prompt_bytes: usize,
    max_prompt_messages: usize,
}

#[derive(Debug, Clone)]
struct ActiveProviderJob {
    session_id: String,
    consumer_id: String,
    started_at: DateTime<Utc>,
    cancel_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredProviderSession {
    #[serde(rename = "providerSession")]
    provider_session: ProviderSessionV1,
    #[serde(rename = "paymentSession")]
    payment_session: PseudoPaymentSessionV1,
    #[serde(default)]
    ledger: Vec<PseudoLedgerEventV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredProviderModelLifecycle {
    pub state: ModelLifecycleStateKind,
    #[serde(
        rename = "lastStartedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_started_at: Option<DateTime<Utc>>,
    #[serde(
        rename = "lastWarmedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_warmed_at: Option<DateTime<Utc>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "recentStartAttempts", default)]
    pub recent_start_attempts: Vec<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderStateSnapshot {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "providerId")]
    provider_id: String,
    #[serde(rename = "modelId")]
    model_id: String,
    #[serde(rename = "storedAt")]
    stored_at: DateTime<Utc>,
    #[serde(default)]
    sessions: BTreeMap<String, StoredProviderSession>,
    #[serde(default)]
    receipts: BTreeMap<String, ProviderChatReceiptV1>,
    #[serde(rename = "modelLifecycle", default)]
    model_lifecycle: Option<StoredProviderModelLifecycle>,
}

#[derive(Debug, Clone, Default)]
struct LoadedProviderState {
    sessions: BTreeMap<String, StoredProviderSession>,
    receipts: BTreeMap<String, ProviderChatReceiptV1>,
    model_lifecycle: Option<StoredProviderModelLifecycle>,
}

#[derive(Debug, Clone)]
enum ProviderBackend {
    Mock,
    OpenAiCompatibleHttp(OpenAiCompatibleHttpBackend),
}

#[derive(Debug, Clone)]
struct OpenAiCompatibleHttpBackend {
    base_url: Arc<String>,
    api_key: Option<Arc<String>>,
    health_url: Option<Arc<String>>,
    managed_process: Option<ManagedBackendProcess>,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
struct ManagedBackendProcess {
    program: Arc<String>,
    args: Arc<Vec<String>>,
    runtime: Arc<ManagedBackendRuntime>,
}

#[derive(Debug)]
struct ManagedBackendRuntime {
    child: Mutex<Option<ManagedBackendChild>>,
}

#[derive(Debug)]
struct ManagedBackendChild {
    child: Child,
    started_at: DateTime<Utc>,
}

impl ManagedBackendProcess {
    fn new(program: String, args: Vec<String>) -> Self {
        Self {
            program: Arc::new(program),
            args: Arc::new(args),
            runtime: Arc::new(ManagedBackendRuntime {
                child: Mutex::new(None),
            }),
        }
    }

    fn ensure_started(&self) -> Result<(), ProviderApiError> {
        let mut child_slot = self.runtime.child.lock().map_err(|_| {
            ProviderApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backend_process_state_poisoned",
                "managed backend process state could not be locked",
            )
        })?;
        if let Some(child) = child_slot.as_mut() {
            match child.child.try_wait() {
                Ok(None) => return Ok(()),
                Ok(Some(_status)) => {
                    *child_slot = None;
                }
                Err(error) => {
                    *child_slot = None;
                    return Err(ProviderApiError::new(
                        StatusCode::BAD_GATEWAY,
                        "backend_process_check_failed",
                        format!("managed backend process status check failed: {error}"),
                    ));
                }
            }
        }

        let mut command = Command::new(self.program.as_str());
        command
            .args(self.args.iter().map(String::as_str))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let child = command.spawn().map_err(|error| {
            ProviderApiError::new(
                StatusCode::BAD_GATEWAY,
                "backend_start_failed",
                format!("failed to start managed backend command: {error}"),
            )
        })?;
        *child_slot = Some(ManagedBackendChild {
            child,
            started_at: Utc::now(),
        });
        Ok(())
    }

    fn exited(&self) -> Result<Option<String>, ProviderApiError> {
        let mut child_slot = self.runtime.child.lock().map_err(|_| {
            ProviderApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backend_process_state_poisoned",
                "managed backend process state could not be locked",
            )
        })?;
        let Some(child) = child_slot.as_mut() else {
            return Ok(None);
        };
        match child.child.try_wait() {
            Ok(None) => Ok(None),
            Ok(Some(status)) => {
                let started_at = child.started_at;
                *child_slot = None;
                Ok(Some(format!(
                    "managed backend process exited with {status} after {} seconds",
                    Utc::now()
                        .signed_duration_since(started_at)
                        .num_seconds()
                        .max(0)
                )))
            }
            Err(error) => {
                *child_slot = None;
                Err(ProviderApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "backend_process_check_failed",
                    format!("managed backend process status check failed: {error}"),
                ))
            }
        }
    }

    fn terminate(&self) -> Result<bool, ProviderApiError> {
        let mut child_slot = self.runtime.child.lock().map_err(|_| {
            ProviderApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backend_process_state_poisoned",
                "managed backend process state could not be locked",
            )
        })?;
        let Some(mut child) = child_slot.take() else {
            return Ok(false);
        };
        terminate_managed_child(&mut child.child);
        Ok(true)
    }
}

impl Drop for ManagedBackendRuntime {
    fn drop(&mut self) {
        if let Ok(mut child_slot) = self.child.lock()
            && let Some(mut child) = child_slot.take()
        {
            terminate_managed_child(&mut child.child);
        }
    }
}

#[cfg(windows)]
fn terminate_managed_child(child: &mut Child) {
    use std::os::windows::process::CommandExt;

    let pid = child.id().to_string();
    let mut command = Command::new("taskkill");
    command
        .args(["/PID", pid.as_str(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000);
    let _ = command.status();
    let _ = child.wait();
}

#[cfg(not(windows))]
fn terminate_managed_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug, Clone)]
struct BackendChatOutput {
    text: String,
    usage: ProviderUsageV1,
    backend_type: ModelBackendType,
}

#[derive(Debug, Deserialize)]
struct OpenAiChatCompletionUsage {
    #[serde(rename = "prompt_tokens", default)]
    prompt_tokens: Option<u64>,
    #[serde(rename = "completion_tokens", default)]
    completion_tokens: Option<u64>,
    #[serde(rename = "total_tokens", default)]
    total_tokens: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ProviderCapabilitiesResponse {
    identity: ProviderIdentityV1,
    offers: Vec<ProviderModelOfferV1>,
    #[serde(rename = "securityMode")]
    security_mode: ProviderSecurityMode,
    #[serde(rename = "authModes")]
    auth_modes: Vec<ProviderAuthMode>,
    #[serde(rename = "readinessLabel")]
    readiness_label: ProviderReadinessLabel,
}

#[derive(Debug, Serialize)]
struct ProviderSessionOpenResponse {
    session: ProviderSessionV1,
    #[serde(rename = "ledgerEvent")]
    ledger_event: PseudoLedgerEventV1,
}

#[derive(Debug, Serialize)]
struct ProviderSessionCloseResponse {
    session: ProviderSessionV1,
    #[serde(rename = "ledgerEvent")]
    ledger_event: PseudoLedgerEventV1,
}

#[derive(Debug, Serialize)]
struct ProviderChatResponse {
    #[serde(rename = "jobId")]
    job_id: String,
    text: String,
    #[serde(rename = "streamEvents")]
    stream_events: Vec<ProviderStreamEventV1>,
    receipt: ProviderChatReceiptV1,
    #[serde(rename = "ledgerEvents")]
    ledger_events: Vec<PseudoLedgerEventV1>,
    #[serde(rename = "ledgerState")]
    ledger_state: PseudoPaymentStateV1,
}

#[derive(Debug, Serialize)]
struct ProviderLedgerResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    state: PseudoPaymentStateV1,
    events: Vec<PseudoLedgerEventV1>,
}

#[derive(Debug, Serialize)]
struct ProviderErrorBody {
    error: ProviderErrorDetail,
}

#[derive(Debug, Serialize)]
struct ProviderErrorDetail {
    code: &'static str,
    message: String,
}

#[derive(Debug)]
struct ProviderApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ProviderApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ProviderApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ProviderErrorBody {
                error: ProviderErrorDetail {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

pub async fn serve(config: ServeProviderConfig) -> Result<()> {
    let auth_modes = auth_modes_for_config(&config);
    provider_security_mode_allows_bind(&config.host, &config.security_mode, &auth_modes)
        .with_context(|| {
            format!(
                "provider mode {:?} refused bind host {}",
                config.security_mode, config.host
            )
        })?;
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .with_context(|| {
            format!(
                "invalid provider listen address {}:{}",
                config.host, config.port
            )
        })?;
    let state = provider_state_from_config(config)?;
    let app = router(state);
    let listener = TcpListener::bind(addr).await?;
    info!("serving Hivemind provider API on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: ProviderState) -> Router {
    Router::new()
        .route("/v1/provider/health", get(provider_health))
        .route("/v1/provider/capabilities", get(provider_capabilities))
        .route("/v1/provider/models", get(provider_models))
        .route(
            "/v1/provider/models/{model_id}/status",
            get(provider_model_status),
        )
        .route(
            "/v1/provider/models/{model_id}/start",
            post(provider_start_model),
        )
        .route(
            "/v1/provider/models/{model_id}/stop",
            post(provider_stop_model),
        )
        .route("/v1/provider/quote", post(provider_quote))
        .route("/v1/provider/sessions", post(provider_open_session))
        .route(
            "/v1/provider/sessions/{session_id}",
            get(provider_get_session),
        )
        .route(
            "/v1/provider/sessions/{session_id}/close",
            post(provider_close_session),
        )
        .route(
            "/v1/provider/sessions/{session_id}/summary",
            get(provider_get_session_summary),
        )
        .route("/v1/provider/chat", post(provider_chat))
        .route(
            "/v1/provider/jobs/{job_id}/cancel",
            post(provider_cancel_job),
        )
        .route("/v1/provider/ledger/{session_id}", get(provider_get_ledger))
        .route(
            "/v1/provider/receipts/{receipt_id}",
            get(provider_get_receipt),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

fn provider_state_from_config(config: ServeProviderConfig) -> Result<ProviderState> {
    let now = Utc::now();
    let auth_modes = auth_modes_for_config(&config);
    provider_security_mode_allows_bind(&config.host, &config.security_mode, &auth_modes)?;
    if config.provider_id.trim().is_empty() {
        bail!("provider id is required");
    }
    if config.model_id.trim().is_empty() {
        bail!("model id is required");
    }
    let backend = provider_backend_from_config(&config)?;
    if config.max_debt < 0.0
        || config.forgiveness_per_second < 0.0
        || config.price_per_input_token < 0.0
        || config.price_per_output_token < 0.0
        || config.price_per_model_second < 0.0
        || config.price_per_request < 0.0
    {
        bail!("provider pseudopayment amounts must be non-negative");
    }
    if config.max_concurrent_sessions == 0
        || config.max_concurrent_jobs == 0
        || config.max_context_tokens == 0
        || config.max_output_tokens == 0
        || config.max_prompt_bytes == 0
        || config.max_prompt_messages == 0
        || config.max_model_starts_per_hour == 0
        || config.max_cold_start_seconds == 0
    {
        bail!("provider resource limits must be greater than zero");
    }

    let readiness_label = readiness_for_security_mode(&config.security_mode);
    let policy = PseudoPaymentPolicyV1 {
        schema_version: hivemind_core::PSEUDO_PAYMENT_POLICY_SCHEMA_VERSION.to_string(),
        policy_id: format!("pseudo-policy-{}", config.provider_id),
        currency_unit: "pseudo-credit".to_string(),
        max_debt: config.max_debt,
        forgiveness_per_second: config.forgiveness_per_second,
        forgiveness_starts_at: now,
        price_per_input_token: config.price_per_input_token,
        price_per_output_token: config.price_per_output_token,
        price_per_model_second: config.price_per_model_second,
        price_per_request: Some(config.price_per_request),
        max_session_duration_seconds: 3600,
        max_jobs_per_minute: 30,
        max_concurrent_jobs: config.max_concurrent_jobs,
        stop_when_debt_above_max: true,
        allow_provider_policy_update: false,
        dispute_window_seconds: 60,
        created_at: now,
        expires_at: now + Duration::days(1),
    };
    let identity = ProviderIdentityV1 {
        schema_version: hivemind_core::PROVIDER_IDENTITY_SCHEMA_VERSION.to_string(),
        provider_id: config.provider_id.clone(),
        public_key: format!("local-dev-public-key:{}", config.provider_id),
        signing_scheme: "local-dev-deterministic".to_string(),
        display_name: config.display_name,
        operator_contact: None,
        readiness_label: readiness_label.clone(),
        created_at: now,
        signature: Some(format!(
            "dev-provider-identity-signature-v1:{}",
            config.provider_id
        )),
    };
    let offer = ProviderModelOfferV1 {
        schema_version: hivemind_core::PROVIDER_MODEL_OFFER_SCHEMA_VERSION.to_string(),
        offer_id: format!("offer-{}", config.model_id),
        provider_id: config.provider_id.clone(),
        model_id: config.model_id,
        display_name: config.model_display_name,
        backend_type: backend.backend_type(),
        backend_model_id: config.backend_model_id,
        supported_apis: vec![
            ApiSurface::OpenAiChatCompletions,
            ApiSurface::HivemindNative,
        ],
        supported_features: backend.supported_features(),
        max_context_tokens: config.max_context_tokens,
        max_output_tokens: config.max_output_tokens,
        max_concurrent_sessions: config.max_concurrent_sessions,
        max_concurrent_jobs: config.max_concurrent_jobs,
        cold_start_policy: ModelColdStartPolicyV1 {
            allow_consumer_triggered_start: true,
            require_session_before_start: true,
            require_payment_authorization_before_start: true,
            max_starts_per_hour: config.max_model_starts_per_hour,
            max_cold_start_seconds: config.max_cold_start_seconds,
            idle_unload_seconds: Some(300),
        },
        pricing_policy_ref: None,
        pseudopayment_policy: Some(policy.clone()),
        privacy_tier: PrivacyTier::Standard,
        verification_tier: IntegrityTier::ReceiptOnly,
        readiness_label,
        expires_at: now + Duration::days(1),
        signature: Some(format!(
            "dev-provider-offer-signature-v1:{}",
            config.provider_id
        )),
    };

    let loaded_provider_state =
        load_provider_state(&config.state_path, &config.provider_id, &offer.model_id)?;
    let model_lifecycle = loaded_provider_state.model_lifecycle.unwrap_or_else(|| {
        initial_model_lifecycle(&backend, config.initial_model_state.clone(), now)
    });

    Ok(ProviderState {
        started_at: Instant::now(),
        identity,
        offer,
        policy,
        backend,
        security_mode: config.security_mode,
        auth_modes,
        bearer_token: config.bearer_token.map(Arc::new),
        require_signed_requests: config.require_signed_requests,
        state_path: Arc::new(config.state_path),
        signed_request_nonces: Arc::new(Mutex::new(BTreeMap::new())),
        sessions: Arc::new(Mutex::new(loaded_provider_state.sessions)),
        receipts: Arc::new(Mutex::new(loaded_provider_state.receipts)),
        model_lifecycle: Arc::new(Mutex::new(model_lifecycle)),
        active_jobs: Arc::new(AtomicU32::new(0)),
        active_job_records: Arc::new(Mutex::new(BTreeMap::new())),
        max_prompt_bytes: config.max_prompt_bytes,
        max_prompt_messages: config.max_prompt_messages,
    })
}

fn provider_backend_from_config(config: &ServeProviderConfig) -> Result<ProviderBackend> {
    if config.backend_start_command.is_none() && !config.backend_start_args.is_empty() {
        bail!("--backend-start-arg requires --backend-start-command");
    }
    match config.backend_type {
        ModelBackendType::Mock => {
            if config.backend_start_command.is_some() || config.backend_health_url.is_some() {
                bail!("mock provider backend does not accept managed backend process config");
            }
            Ok(ProviderBackend::Mock)
        }
        ModelBackendType::OpenAiCompatibleHttp => {
            let Some(base_url) = config.backend_base_url.as_ref() else {
                bail!("openai-compatible-http backend requires --backend-base-url");
            };
            if base_url.trim().is_empty() {
                bail!("openai-compatible-http backend base URL is required");
            }
            let health_url = config
                .backend_health_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| Arc::new(value.to_string()));
            let managed_process = config
                .backend_start_command
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|program| {
                    ManagedBackendProcess::new(
                        program.to_string(),
                        config.backend_start_args.clone(),
                    )
                });
            if config
                .backend_start_command
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                bail!("openai-compatible-http backend start command cannot be empty");
            }
            let timeout = config.backend_timeout_seconds.clamp(1, 600);
            let client = reqwest::Client::builder()
                .timeout(StdDuration::from_secs(timeout))
                .build()
                .context("failed to build OpenAI-compatible backend client")?;
            Ok(ProviderBackend::OpenAiCompatibleHttp(
                OpenAiCompatibleHttpBackend {
                    base_url: Arc::new(base_url.trim_end_matches('/').to_string()),
                    api_key: config.backend_api_key.clone().map(Arc::new),
                    health_url,
                    managed_process,
                    client,
                },
            ))
        }
        _ => bail!(
            "provider backend {:?} is not implemented yet; use mock or openai-compatible-http",
            config.backend_type
        ),
    }
}

fn initial_model_lifecycle(
    backend: &ProviderBackend,
    initial_state: Option<ModelLifecycleStateKind>,
    now: DateTime<Utc>,
) -> StoredProviderModelLifecycle {
    let state = initial_state.unwrap_or_else(|| backend.initial_lifecycle_state());
    let warmed_at = matches!(state, ModelLifecycleStateKind::Ready).then_some(now);
    StoredProviderModelLifecycle {
        state,
        last_started_at: warmed_at,
        last_warmed_at: warmed_at,
        last_error: None,
        recent_start_attempts: Vec::new(),
    }
}

fn load_provider_state(
    state_path: &FsPath,
    provider_id: &str,
    model_id: &str,
) -> Result<LoadedProviderState> {
    if !state_path.exists() {
        return Ok(LoadedProviderState::default());
    }
    let bytes = std::fs::read(state_path)
        .with_context(|| format!("failed to read provider state {}", state_path.display()))?;
    let snapshot: ProviderStateSnapshot = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse provider state {}", state_path.display()))?;
    if snapshot.schema_version != PROVIDER_STATE_SCHEMA_VERSION {
        warn!(
            "ignoring provider state {} with unsupported schema {}",
            state_path.display(),
            snapshot.schema_version
        );
        return Ok(LoadedProviderState::default());
    }
    if snapshot.provider_id != provider_id || snapshot.model_id != model_id {
        warn!(
            "ignoring provider state {} for provider/model {}/{} while serving {}/{}",
            state_path.display(),
            snapshot.provider_id,
            snapshot.model_id,
            provider_id,
            model_id
        );
        return Ok(LoadedProviderState::default());
    }

    let mut sessions = BTreeMap::new();
    for (session_id, stored) in snapshot.sessions {
        if stored.provider_session.session_id != session_id
            || stored.payment_session.session_id != session_id
            || stored.provider_session.provider_id != provider_id
            || stored.payment_session.provider_id != provider_id
            || stored.provider_session.model_id != model_id
        {
            warn!(
                "skipping inconsistent persisted provider session {} from {}",
                session_id,
                state_path.display()
            );
            continue;
        }
        sessions.insert(session_id, stored);
    }
    let mut receipts = BTreeMap::new();
    for (receipt_id, receipt) in snapshot.receipts {
        if receipt.receipt_id != receipt_id
            || receipt.provider_id != provider_id
            || receipt.model_id != model_id
        {
            warn!(
                "skipping inconsistent persisted provider receipt {} from {}",
                receipt_id,
                state_path.display()
            );
            continue;
        }
        receipts.insert(receipt_id, receipt);
    }
    Ok(LoadedProviderState {
        sessions,
        receipts,
        model_lifecycle: snapshot.model_lifecycle,
    })
}

async fn persist_provider_state(state: &ProviderState) -> Result<(), ProviderApiError> {
    let snapshot = {
        let sessions = lock_sessions(state)?.clone();
        let receipts = lock_receipts(state)?.clone();
        let model_lifecycle = Some(lock_model_lifecycle(state)?.clone());
        ProviderStateSnapshot {
            schema_version: PROVIDER_STATE_SCHEMA_VERSION.to_string(),
            provider_id: state.identity.provider_id.clone(),
            model_id: state.offer.model_id.clone(),
            stored_at: Utc::now(),
            sessions,
            receipts,
            model_lifecycle,
        }
    };
    persist_provider_snapshot(state.state_path.as_ref(), &snapshot)
        .await
        .map_err(|error| {
            ProviderApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "provider_state_persist_failed",
                error.to_string(),
            )
        })
}

async fn persist_provider_snapshot(
    state_path: &FsPath,
    snapshot: &ProviderStateSnapshot,
) -> Result<()> {
    if let Some(parent) = state_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create provider state dir {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(snapshot)?;
    tokio::fs::write(state_path, bytes)
        .await
        .with_context(|| format!("failed to write provider state {}", state_path.display()))?;
    Ok(())
}

impl ProviderBackend {
    fn backend_type(&self) -> ModelBackendType {
        match self {
            Self::Mock => ModelBackendType::Mock,
            Self::OpenAiCompatibleHttp(_) => ModelBackendType::OpenAiCompatibleHttp,
        }
    }

    fn backend_health_label(&self) -> &'static str {
        match self {
            Self::Mock => "mock-ready",
            Self::OpenAiCompatibleHttp(backend) => {
                if backend.managed_process.is_some() {
                    "openai-compatible-managed-cold"
                } else {
                    "openai-compatible-configured"
                }
            }
        }
    }

    fn can_stop_model(&self) -> bool {
        match self {
            Self::Mock => false,
            Self::OpenAiCompatibleHttp(backend) => backend.managed_process.is_some(),
        }
    }

    fn initial_lifecycle_state(&self) -> ModelLifecycleStateKind {
        match self {
            Self::Mock => ModelLifecycleStateKind::Ready,
            Self::OpenAiCompatibleHttp(backend) => {
                if backend.managed_process.is_some() {
                    ModelLifecycleStateKind::AvailableCold
                } else {
                    ModelLifecycleStateKind::Configured
                }
            }
        }
    }

    fn supported_features(&self) -> Vec<ModelBackendFeature> {
        match self {
            Self::Mock => vec![
                ModelBackendFeature::Chat,
                ModelBackendFeature::StreamingChat,
                ModelBackendFeature::UsageMetrics,
                ModelBackendFeature::Cancellation,
            ],
            Self::OpenAiCompatibleHttp(backend) => {
                let mut features = vec![
                    ModelBackendFeature::Chat,
                    ModelBackendFeature::StreamingChat,
                    ModelBackendFeature::UsageMetrics,
                ];
                if backend.managed_process.is_some() || backend.health_url.is_some() {
                    features.push(ModelBackendFeature::Warmup);
                }
                if backend.managed_process.is_some() {
                    features.push(ModelBackendFeature::ModelUnload);
                }
                features
            }
        }
    }

    async fn chat(
        &self,
        request: &ProviderChatRequestV1,
        backend_model_id: &str,
    ) -> Result<BackendChatOutput, ProviderApiError> {
        match self {
            Self::Mock => Ok(mock_backend_chat(request)),
            Self::OpenAiCompatibleHttp(backend) => backend.chat(request, backend_model_id).await,
        }
    }

    async fn start_model(
        &self,
        _backend_model_id: &str,
        max_cold_start_seconds: u64,
    ) -> Result<(), ProviderApiError> {
        match self {
            Self::Mock => Ok(()),
            Self::OpenAiCompatibleHttp(backend) => {
                backend.start_model(max_cold_start_seconds).await
            }
        }
    }

    fn stop_model(&self) -> Result<bool, ProviderApiError> {
        match self {
            Self::Mock => Ok(false),
            Self::OpenAiCompatibleHttp(backend) => backend.stop_model(),
        }
    }

    fn managed_process_exit_reason(&self) -> Result<Option<String>, ProviderApiError> {
        match self {
            Self::Mock => Ok(None),
            Self::OpenAiCompatibleHttp(backend) => backend.managed_process_exit_reason(),
        }
    }
}

impl OpenAiCompatibleHttpBackend {
    async fn start_model(&self, max_cold_start_seconds: u64) -> Result<(), ProviderApiError> {
        if let Some(process) = &self.managed_process {
            process.ensure_started()?;
        }
        self.wait_for_health(max_cold_start_seconds).await
    }

    async fn wait_for_health(&self, max_cold_start_seconds: u64) -> Result<(), ProviderApiError> {
        let Some(health_url) = &self.health_url else {
            return Ok(());
        };
        let deadline = Instant::now()
            .checked_add(StdDuration::from_secs(max_cold_start_seconds.max(1)))
            .unwrap_or_else(Instant::now);
        let mut last_error: Option<String> = None;
        loop {
            if Instant::now() >= deadline {
                return Err(ProviderApiError::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "backend_health_timeout",
                    format!(
                        "backend health check did not pass within {} seconds: {}",
                        max_cold_start_seconds.max(1),
                        last_error.unwrap_or_else(|| "no successful health response".to_string())
                    ),
                ));
            }
            if let Some(reason) = self.managed_process_exit_reason()? {
                return Err(ProviderApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "backend_process_exited",
                    reason,
                ));
            }
            match self.client.get(health_url.as_str()).send().await {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => {
                    last_error = Some(format!(
                        "health endpoint returned HTTP {}",
                        response.status()
                    ));
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                }
            }
            sleep(StdDuration::from_millis(250)).await;
        }
    }

    fn managed_process_exit_reason(&self) -> Result<Option<String>, ProviderApiError> {
        let Some(process) = &self.managed_process else {
            return Ok(None);
        };
        process.exited()
    }

    fn stop_model(&self) -> Result<bool, ProviderApiError> {
        let Some(process) = &self.managed_process else {
            return Ok(false);
        };
        process.terminate()
    }

    async fn chat(
        &self,
        request: &ProviderChatRequestV1,
        backend_model_id: &str,
    ) -> Result<BackendChatOutput, ProviderApiError> {
        let url = format!("{}/chat/completions", self.base_url.as_str());
        let started = Instant::now();
        let mut builder = self
            .client
            .post(url)
            .json(&openai_chat_request_body(request, backend_model_id));
        if let Some(api_key) = &self.api_key {
            builder = builder.bearer_auth(api_key.as_str());
        }
        let response = builder.send().await.map_err(|error| {
            ProviderApiError::new(
                StatusCode::BAD_GATEWAY,
                "backend_unavailable",
                format!("OpenAI-compatible backend request failed: {error}"),
            )
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(ProviderApiError::new(
                StatusCode::BAD_GATEWAY,
                "backend_error",
                format!("OpenAI-compatible backend returned HTTP {status}"),
            ));
        }
        let value = response.json::<Value>().await.map_err(|error| {
            ProviderApiError::new(
                StatusCode::BAD_GATEWAY,
                "backend_invalid_response",
                format!("OpenAI-compatible backend response was not valid JSON: {error}"),
            )
        })?;
        openai_chat_output_from_value(request, value, started.elapsed().as_secs_f64())
    }
}

fn openai_chat_request_body(request: &ProviderChatRequestV1, backend_model_id: &str) -> Value {
    json!({
        "model": backend_model_id,
        "messages": request.messages.clone(),
        "stream": false,
        "max_tokens": request.max_output_tokens,
        "temperature": request.temperature,
    })
}

fn openai_chat_output_from_value(
    request: &ProviderChatRequestV1,
    value: Value,
    elapsed_seconds: f64,
) -> Result<BackendChatOutput, ProviderApiError> {
    let text = value
        .pointer("/choices/0/message/content")
        .and_then(openai_content_text)
        .or_else(|| {
            value
                .pointer("/choices/0/text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| {
            ProviderApiError::new(
                StatusCode::BAD_GATEWAY,
                "backend_invalid_response",
                "OpenAI-compatible backend response did not include choices[0].message.content",
            )
        })?;
    let usage = value
        .get("usage")
        .cloned()
        .and_then(|usage| serde_json::from_value::<OpenAiChatCompletionUsage>(usage).ok());
    let usage = normalized_openai_usage(request, &text, usage, elapsed_seconds);
    Ok(BackendChatOutput {
        text,
        usage,
        backend_type: ModelBackendType::OpenAiCompatibleHttp,
    })
}

fn openai_content_text(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    value.as_array().map(|parts| {
        parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn normalized_openai_usage(
    request: &ProviderChatRequestV1,
    text: &str,
    usage: Option<OpenAiChatCompletionUsage>,
    elapsed_seconds: f64,
) -> ProviderUsageV1 {
    if let Some(usage) = usage {
        let output_tokens = usage
            .completion_tokens
            .unwrap_or_else(|| estimate_tokens(text).min(request.max_output_tokens).max(1));
        let input_tokens = usage
            .prompt_tokens
            .unwrap_or_else(|| estimate_tokens(&last_user_text(&request.messages)).max(1));
        let total_tokens = usage
            .total_tokens
            .unwrap_or_else(|| input_tokens.saturating_add(output_tokens));
        return ProviderUsageV1 {
            input_tokens,
            output_tokens,
            total_tokens,
            model_seconds: elapsed_seconds.max(0.001),
            queue_seconds: 0.0,
            first_token_ms: None,
            tokens_per_second: Some(output_tokens as f64 / elapsed_seconds.max(0.001)),
            usage_confidence: UsageConfidence::BackendReported,
        };
    }
    let input_tokens = estimate_tokens(&last_user_text(&request.messages)).max(1);
    let output_tokens = estimate_tokens(text).min(request.max_output_tokens).max(1);
    ProviderUsageV1 {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        model_seconds: elapsed_seconds.max(0.001),
        queue_seconds: 0.0,
        first_token_ms: None,
        tokens_per_second: Some(output_tokens as f64 / elapsed_seconds.max(0.001)),
        usage_confidence: UsageConfidence::Estimated,
    }
}

async fn provider_health(
    State(state): State<ProviderState>,
    headers: HeaderMap,
) -> Result<Json<ProviderHealthV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    let model_status = model_status(&state)?;
    Ok(Json(ProviderHealthV1 {
        schema_version: hivemind_core::PROVIDER_HEALTH_SCHEMA_VERSION.to_string(),
        provider_id: state.identity.provider_id.clone(),
        status: ProviderStatus::Healthy,
        uptime_seconds: state.started_at.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        security_mode: state.security_mode.clone(),
        auth_modes: state.auth_modes.clone(),
        active_sessions: session_count(&state),
        active_jobs: active_job_count(&state),
        model_statuses: vec![model_status],
        generated_at: Utc::now(),
    }))
}

async fn provider_capabilities(
    State(state): State<ProviderState>,
    headers: HeaderMap,
) -> Result<Json<ProviderCapabilitiesResponse>, ProviderApiError> {
    require_auth(&state, &headers)?;
    Ok(Json(ProviderCapabilitiesResponse {
        identity: state.identity.clone(),
        offers: vec![state.offer.clone()],
        security_mode: state.security_mode.clone(),
        auth_modes: state.auth_modes.clone(),
        readiness_label: state.offer.readiness_label.clone(),
    }))
}

async fn provider_models(
    State(state): State<ProviderState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProviderModelOfferV1>>, ProviderApiError> {
    require_auth(&state, &headers)?;
    Ok(Json(vec![state.offer.clone()]))
}

async fn provider_model_status(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(model_id): Path<String>,
) -> Result<Json<ModelLifecycleStateV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    if model_id != state.offer.model_id {
        return Err(ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("provider model {model_id} is not configured"),
        ));
    }
    Ok(Json(model_status(&state)?))
}

async fn provider_start_model(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(model_id): Path<String>,
    Json(request): Json<ProviderModelStartRequestV1>,
) -> Result<Json<ModelLifecycleStateV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    require_signed_request(
        &state,
        &request,
        request.request_envelope.as_ref(),
        "POST",
        &format!("/v1/provider/models/{model_id}/start"),
        &request.consumer_id,
        request.session_id.as_deref(),
        None,
    )?;
    if model_id != state.offer.model_id || request.model_id != state.offer.model_id {
        return Err(ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "model_not_found",
            "provider model is not configured",
        ));
    }
    if request.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_mismatch",
            "model start request providerId does not match this provider",
        ));
    }
    authorize_model_start(&state, &request)?;
    if mark_model_starting(&state)? {
        persist_provider_state(&state).await?;
        let start_result = state
            .backend
            .start_model(
                &state.offer.backend_model_id,
                state.offer.cold_start_policy.max_cold_start_seconds,
            )
            .await;
        finish_model_start(&state, start_result).await?;
    }
    Ok(Json(model_status(&state)?))
}

async fn provider_stop_model(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(model_id): Path<String>,
    Json(request): Json<ProviderModelStopRequestV1>,
) -> Result<Json<ModelLifecycleStateV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    require_signed_request(
        &state,
        &request,
        request.request_envelope.as_ref(),
        "POST",
        &format!("/v1/provider/models/{model_id}/stop"),
        &request.consumer_id,
        request.session_id.as_deref(),
        None,
    )?;
    if model_id != state.offer.model_id || request.model_id != state.offer.model_id {
        return Err(ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "model_not_found",
            "provider model is not configured",
        ));
    }
    if request.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_mismatch",
            "model stop request providerId does not match this provider",
        ));
    }
    mark_model_stopping(&state)?;
    persist_provider_state(&state).await?;
    let stop_result = state.backend.stop_model();
    finish_model_stop(&state, stop_result).await?;
    Ok(Json(model_status(&state)?))
}

async fn provider_quote(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Json(request): Json<ProviderQuoteRequestV1>,
) -> Result<Json<ProviderQuoteV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    require_signed_request(
        &state,
        &request,
        request.request_envelope.as_ref(),
        "POST",
        "/v1/provider/quote",
        &request.consumer_id,
        None,
        None,
    )?;
    if request.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_mismatch",
            "quote request providerId does not match this provider",
        ));
    }
    if request.model_id != state.offer.model_id {
        return Err(ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("provider model {} is not configured", request.model_id),
        ));
    }
    if request.payment_mode != ProviderPaymentMode::PseudopaymentDebtForgiveness {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_payment_mode",
            "mock provider MVP currently requires pseudopayment debt forgiveness",
        ));
    }
    let quote = ProviderQuoteV1 {
        schema_version: hivemind_core::PROVIDER_QUOTE_SCHEMA_VERSION.to_string(),
        quote_id: format!("provider-quote-{}", Uuid::new_v4()),
        request_id: request.request_id,
        provider_id: state.identity.provider_id.clone(),
        consumer_id: request.consumer_id.clone(),
        model_id: state.offer.model_id.clone(),
        price_terms: ProviderPriceTermsV1 {
            currency_unit: state.policy.currency_unit.clone(),
            price_per_input_token: state.policy.price_per_input_token,
            price_per_output_token: state.policy.price_per_output_token,
            price_per_model_second: state.policy.price_per_model_second,
            price_per_request: state.policy.price_per_request,
        },
        pseudopayment_policy: state.policy.clone(),
        cold_start_policy: state.offer.cold_start_policy.clone(),
        limits: ProviderSessionLimitsV1 {
            max_session_duration_seconds: state.policy.max_session_duration_seconds,
            max_jobs_per_minute: state.policy.max_jobs_per_minute,
            max_concurrent_jobs: state.policy.max_concurrent_jobs,
            max_input_tokens: state.offer.max_context_tokens,
            max_output_tokens: state.offer.max_output_tokens,
        },
        expires_at: Utc::now() + Duration::minutes(5),
        signature: Some(format!(
            "dev-provider-quote-signature-v1:{}",
            state.identity.provider_id
        )),
    };
    Ok(Json(quote))
}

async fn provider_open_session(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Json(request): Json<ProviderSessionOpenRequestV1>,
) -> Result<Json<ProviderSessionOpenResponse>, ProviderApiError> {
    require_auth(&state, &headers)?;
    require_signed_request(
        &state,
        &request,
        request.request_envelope.as_ref(),
        "POST",
        "/v1/provider/sessions",
        &request.consumer_id,
        None,
        Some(&request.quote_id),
    )?;
    if request.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_mismatch",
            "session request providerId does not match this provider",
        ));
    }
    if request.spending_cap < 0.0 || request.spending_cap > state.policy.max_debt {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_spending_cap",
            "spendingCap must be between zero and provider policy maxDebt",
        ));
    }
    let now = Utc::now();
    if request.requested_expires_at <= now {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "expired_session_request",
            "requestedExpiresAt must be in the future",
        ));
    }
    {
        let mut sessions = lock_sessions(&state)?;
        refresh_all_session_states(&mut sessions, &state.policy, now)?;
        let active_sessions = active_session_count_from_sessions(&sessions);
        if active_sessions >= state.offer.max_concurrent_sessions {
            return Err(ProviderApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "provider_session_limit_reached",
                format!(
                    "provider already has {} active sessions, max is {}",
                    active_sessions, state.offer.max_concurrent_sessions
                ),
            ));
        }
    }
    let expires_at = request
        .requested_expires_at
        .min(now + Duration::seconds(state.policy.max_session_duration_seconds as i64));
    let session_id = format!("provider-session-{}", Uuid::new_v4());
    let payment_session = PseudoPaymentSessionV1 {
        schema_version: hivemind_core::PSEUDO_PAYMENT_SESSION_SCHEMA_VERSION.to_string(),
        session_id: session_id.clone(),
        provider_id: state.identity.provider_id.clone(),
        consumer_id: request.consumer_id.clone(),
        quote_id: request.quote_id.clone(),
        policy_hash: request.accepted_policy_hash.clone(),
        current_debt: 0.0,
        last_forgiveness_at: now,
        next_sequence: 1,
        status: ProviderSessionStatus::Active,
        opened_at: now,
        expires_at,
    };
    let ledger_state =
        pseudo_payment_state(&payment_session, &state.policy, now).map_err(payment_error)?;
    let provider_session = ProviderSessionV1 {
        schema_version: hivemind_core::PROVIDER_SESSION_SCHEMA_VERSION.to_string(),
        session_id: session_id.clone(),
        quote_id: request.quote_id,
        provider_id: state.identity.provider_id.clone(),
        consumer_id: request.consumer_id.clone(),
        model_id: state.offer.model_id.clone(),
        status: ProviderSessionStatus::Active,
        payment_mode: ProviderPaymentMode::PseudopaymentDebtForgiveness,
        policy_hash: request.accepted_policy_hash,
        opened_at: now,
        expires_at,
        current_ledger_state: ledger_state,
        signature: Some(format!(
            "dev-provider-session-signature-v1:{}:{}",
            state.identity.provider_id, session_id
        )),
    };
    let ledger_event = PseudoLedgerEventV1 {
        schema_version: hivemind_core::PSEUDO_LEDGER_EVENT_SCHEMA_VERSION.to_string(),
        event_id: format!("pseudo-ledger-{session_id}-0"),
        session_id: session_id.clone(),
        sequence: 0,
        event_type: PseudoLedgerEventType::SessionOpened,
        amount: 0.0,
        debt_before: 0.0,
        debt_after: 0.0,
        job_id: None,
        receipt_id: None,
        reason: "pseudopayment session opened".to_string(),
        created_at: now,
        signer: state.identity.provider_id.clone(),
        signature: format!(
            "dev-pseudo-ledger-signature-v1:{}:{}:0",
            state.identity.provider_id, session_id
        ),
    };
    {
        lock_sessions(&state)?.insert(
            session_id,
            StoredProviderSession {
                provider_session: provider_session.clone(),
                payment_session,
                ledger: vec![ledger_event.clone()],
            },
        );
    }
    persist_provider_state(&state).await?;
    Ok(Json(ProviderSessionOpenResponse {
        session: provider_session,
        ledger_event,
    }))
}

async fn provider_get_session(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<ProviderSessionV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    let now = Utc::now();
    let mut sessions = lock_sessions(&state)?;
    let stored = sessions.get_mut(&session_id).ok_or_else(|| {
        ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        )
    })?;
    refresh_session_state(stored, &state.policy, now)?;
    Ok(Json(stored.provider_session.clone()))
}

async fn provider_close_session(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(request): Json<ProviderSessionCloseRequestV1>,
) -> Result<Json<ProviderSessionCloseResponse>, ProviderApiError> {
    require_auth(&state, &headers)?;
    require_signed_request(
        &state,
        &request,
        request.request_envelope.as_ref(),
        "POST",
        &format!("/v1/provider/sessions/{session_id}/close"),
        &request.consumer_id,
        Some(&request.session_id),
        None,
    )?;
    if request.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_mismatch",
            "session close request providerId does not match this provider",
        ));
    }
    if request.session_id != session_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "session_mismatch",
            "session close request sessionId does not match the path",
        ));
    }
    if active_job_count(&state) > 0 {
        return Err(ProviderApiError::new(
            StatusCode::CONFLICT,
            "session_close_busy",
            "provider session cannot be closed while jobs are active",
        ));
    }

    let now = Utc::now();
    let (provider_session, ledger_event) = {
        let mut sessions = lock_sessions(&state)?;
        let stored = sessions.get_mut(&session_id).ok_or_else(|| {
            ProviderApiError::new(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            )
        })?;
        if stored.provider_session.consumer_id != request.consumer_id {
            return Err(ProviderApiError::new(
                StatusCode::FORBIDDEN,
                "consumer_mismatch",
                "session close consumerId does not match the session",
            ));
        }
        if stored.provider_session.provider_id != state.identity.provider_id {
            return Err(ProviderApiError::new(
                StatusCode::BAD_REQUEST,
                "session_provider_mismatch",
                "session does not belong to this provider",
            ));
        }
        if stored.provider_session.status == ProviderSessionStatus::Closed {
            let event = stored
                .ledger
                .iter()
                .rev()
                .find(|event| event.event_type == PseudoLedgerEventType::SessionClosed)
                .cloned()
                .ok_or_else(|| {
                    ProviderApiError::new(
                        StatusCode::CONFLICT,
                        "session_already_closed",
                        "session is already closed and has no close ledger event",
                    )
                })?;
            (stored.provider_session.clone(), event)
        } else {
            let ledger_event = apply_pseudo_payment_session_close(
                &mut stored.payment_session,
                &state.policy,
                request.reason.as_deref(),
                now,
                state.identity.provider_id.clone(),
            )
            .map_err(payment_error)?;
            stored.ledger.push(ledger_event.clone());
            let ledger_state = pseudo_payment_state(&stored.payment_session, &state.policy, now)
                .map_err(payment_error)?;
            stored.provider_session.status = ProviderSessionStatus::Closed;
            stored.provider_session.current_ledger_state = ledger_state;
            stored.provider_session.signature = Some(format!(
                "dev-provider-session-signature-v1:{}:{}",
                state.identity.provider_id, session_id
            ));
            (stored.provider_session.clone(), ledger_event)
        }
    };
    persist_provider_state(&state).await?;
    Ok(Json(ProviderSessionCloseResponse {
        session: provider_session,
        ledger_event,
    }))
}

async fn provider_get_session_summary(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<ProviderSessionSummaryV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    let now = Utc::now();
    let (provider_session, ledger) = {
        let mut sessions = lock_sessions(&state)?;
        let stored = sessions.get_mut(&session_id).ok_or_else(|| {
            ProviderApiError::new(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            )
        })?;
        refresh_session_state(stored, &state.policy, now)?;
        if stored.provider_session.status != ProviderSessionStatus::Closed {
            return Err(ProviderApiError::new(
                StatusCode::CONFLICT,
                "session_not_closed",
                "provider session summary is available after session close",
            ));
        }
        (stored.provider_session.clone(), stored.ledger.clone())
    };
    let closed_at = ledger
        .iter()
        .rev()
        .find(|event| event.event_type == PseudoLedgerEventType::SessionClosed)
        .map(|event| event.created_at)
        .ok_or_else(|| {
            ProviderApiError::new(
                StatusCode::CONFLICT,
                "session_close_event_missing",
                "closed provider session has no session_closed ledger event",
            )
        })?;

    let receipts = lock_receipts(&state)?;
    let session_receipts = receipts
        .values()
        .filter(|receipt| receipt.session_id == session_id);
    let mut total_jobs = 0;
    let mut total_input_tokens = 0;
    let mut total_output_tokens = 0;
    let mut total_cost = 0.0;
    let mut receipt_ids = Vec::new();
    for receipt in session_receipts {
        total_jobs += 1;
        total_input_tokens += receipt.usage.input_tokens;
        total_output_tokens += receipt.usage.output_tokens;
        total_cost += receipt.cost;
        receipt_ids.push(receipt.receipt_id.clone());
    }

    let total_forgiven = ledger
        .iter()
        .fold(0.0, |total, event| match event.event_type {
            PseudoLedgerEventType::ForgivenessApplied => total + event.amount.max(0.0),
            PseudoLedgerEventType::SessionClosed => {
                total + (event.debt_before - event.debt_after).max(0.0)
            }
            _ => total,
        });

    Ok(Json(ProviderSessionSummaryV1 {
        schema_version: hivemind_core::PROVIDER_SESSION_SUMMARY_SCHEMA_VERSION.to_string(),
        summary_id: format!("provider-session-summary-{session_id}"),
        session_id,
        provider_id: provider_session.provider_id.clone(),
        consumer_id: provider_session.consumer_id.clone(),
        model_id: provider_session.model_id.clone(),
        total_jobs,
        total_input_tokens,
        total_output_tokens,
        total_cost,
        total_forgiven,
        final_debt: provider_session.current_ledger_state.current_debt,
        receipt_ids,
        ledger_event_count: ledger.len() as u64,
        closed_at,
        signature: Some(format!(
            "dev-provider-session-summary-signature-v1:{}:{}",
            state.identity.provider_id, provider_session.session_id
        )),
    }))
}

async fn provider_chat(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Json(request): Json<ProviderChatRequestV1>,
) -> Result<Json<ProviderChatResponse>, ProviderApiError> {
    require_auth(&state, &headers)?;
    require_signed_request(
        &state,
        &request,
        request.request_envelope.as_ref(),
        "POST",
        "/v1/provider/chat",
        &request.consumer_id,
        Some(&request.session_id),
        None,
    )?;
    if request.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_mismatch",
            "chat request providerId does not match this provider",
        ));
    }
    if request.model_id != state.offer.model_id {
        return Err(ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("provider model {} is not configured", request.model_id),
        ));
    }
    validate_chat_feature_support(&state, &request)?;
    require_model_ready_for_chat(&state)?;
    if request.max_output_tokens == 0 || request.max_output_tokens > state.offer.max_output_tokens {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_output_limit",
            "maxOutputTokens must be within provider offer limits",
        ));
    }
    validate_chat_resource_limits(&state, &request)?;

    let mut ledger_events = Vec::new();
    let mut persist_after_forgiveness = false;
    {
        let now = Utc::now();
        let mut sessions = lock_sessions(&state)?;
        let stored = sessions.get_mut(&request.session_id).ok_or_else(|| {
            ProviderApiError::new(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            )
        })?;
        if stored.provider_session.consumer_id != request.consumer_id {
            return Err(ProviderApiError::new(
                StatusCode::FORBIDDEN,
                "consumer_mismatch",
                "chat request consumerId does not match the session",
            ));
        }
        refresh_session_state(stored, &state.policy, now)?;
        if !stored
            .provider_session
            .current_ledger_state
            .can_submit_next_job
        {
            return Err(ProviderApiError::new(
                StatusCode::PAYMENT_REQUIRED,
                "debt_ceiling_exceeded",
                stored
                    .provider_session
                    .current_ledger_state
                    .refusal_reason
                    .clone()
                    .unwrap_or_else(|| "session cannot submit another job".to_string()),
            ));
        }
        if let Some(event) = apply_pseudo_payment_forgiveness(
            &mut stored.payment_session,
            &state.policy,
            now,
            state.identity.provider_id.clone(),
        )
        .map_err(payment_error)?
        {
            stored.ledger.push(event.clone());
            ledger_events.push(event);
            persist_after_forgiveness = true;
        }
    }
    if persist_after_forgiveness {
        persist_provider_state(&state).await?;
    }

    let _job_permit = acquire_job_permit_for_request(&state, &request)?;
    let started_at = Utc::now();
    let BackendChatOutput {
        text: answer,
        usage,
        backend_type,
    } = state
        .backend
        .chat(&request, &state.offer.backend_model_id)
        .await?;
    let cost = provider_chat_usage_cost(&state.policy, &usage);
    let finished_at = Utc::now();
    let receipt_id = format!("provider-receipt-{}", Uuid::new_v4());
    let ledger_state = {
        let mut sessions = lock_sessions(&state)?;
        let stored = sessions.get_mut(&request.session_id).ok_or_else(|| {
            ProviderApiError::new(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            )
        })?;
        let debit_event = apply_pseudo_payment_debit(
            &mut stored.payment_session,
            &state.policy,
            cost,
            Some(request.job_id.clone()),
            Some(receipt_id.clone()),
            finished_at,
            state.identity.provider_id.clone(),
        )
        .map_err(payment_error)?;
        stored.ledger.push(debit_event.clone());
        ledger_events.push(debit_event);
        let ledger_state =
            pseudo_payment_state(&stored.payment_session, &state.policy, finished_at)
                .map_err(payment_error)?;
        stored.provider_session.current_ledger_state = ledger_state.clone();
        ledger_state
    };
    let receipt = ProviderChatReceiptV1 {
        schema_version: hivemind_core::PROVIDER_CHAT_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: receipt_id.clone(),
        job_id: request.job_id.clone(),
        session_id: request.session_id.clone(),
        provider_id: state.identity.provider_id.clone(),
        consumer_id: request.consumer_id.clone(),
        model_id: state.offer.model_id.clone(),
        backend_type,
        input_hash: hash_canonical_json(&json!({ "messages": request.messages.clone() })),
        output_hash: hash_canonical_json(&json!({ "text": answer.clone() })),
        usage,
        cost,
        started_at,
        finished_at,
        stream_summary: json!({
            "mode": if request.stream { "mock-stream" } else { "mock-non-stream" },
            "eventCount": 5
        }),
        ledger_event_ids: ledger_events
            .iter()
            .map(|event| event.event_id.clone())
            .collect(),
        signature: Some(format!(
            "dev-provider-chat-receipt-signature-v1:{}:{}",
            state.identity.provider_id, receipt_id
        )),
    };
    {
        let mut receipts = lock_receipts(&state)?;
        receipts.insert(receipt.receipt_id.clone(), receipt.clone());
    }
    persist_provider_state(&state).await?;

    let stream_events = mock_stream_events(&request, &answer, &receipt, &ledger_state, started_at);
    Ok(Json(ProviderChatResponse {
        job_id: request.job_id,
        text: answer,
        stream_events,
        receipt,
        ledger_events,
        ledger_state,
    }))
}

async fn provider_cancel_job(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Json(request): Json<ProviderJobCancelRequestV1>,
) -> Result<Json<ProviderJobCancelResponseV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    require_signed_request(
        &state,
        &request,
        request.request_envelope.as_ref(),
        "POST",
        &format!("/v1/provider/jobs/{job_id}/cancel"),
        &request.consumer_id,
        Some(&request.session_id),
        None,
    )?;
    if request.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "provider_mismatch",
            "job cancellation request providerId does not match this provider",
        ));
    }
    if request.job_id != job_id {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "job_mismatch",
            "job cancellation request jobId does not match the path",
        ));
    }
    if !state
        .offer
        .supported_features
        .contains(&ModelBackendFeature::Cancellation)
    {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_job_cancellation",
            format!(
                "provider model {} does not advertise cancellation",
                state.offer.model_id
            ),
        ));
    }

    let now = Utc::now();
    let ledger_state = {
        let mut sessions = lock_sessions(&state)?;
        let stored = sessions.get_mut(&request.session_id).ok_or_else(|| {
            ProviderApiError::new(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "session not found",
            )
        })?;
        if stored.provider_session.consumer_id != request.consumer_id {
            return Err(ProviderApiError::new(
                StatusCode::FORBIDDEN,
                "consumer_mismatch",
                "job cancellation consumerId does not match the session",
            ));
        }
        if stored.provider_session.provider_id != state.identity.provider_id {
            return Err(ProviderApiError::new(
                StatusCode::BAD_REQUEST,
                "session_provider_mismatch",
                "session does not belong to this provider",
            ));
        }
        refresh_session_state(stored, &state.policy, now)?;
        stored.provider_session.current_ledger_state.clone()
    };

    let (accepted, status, stream_event) = {
        let mut active_jobs = lock_active_job_records(&state)?;
        match active_jobs.get_mut(&request.job_id) {
            Some(active_job) => {
                if active_job.consumer_id != request.consumer_id
                    || active_job.session_id != request.session_id
                {
                    return Err(ProviderApiError::new(
                        StatusCode::FORBIDDEN,
                        "job_mismatch",
                        "active provider job does not belong to this consumer session",
                    ));
                }
                active_job.cancel_requested = true;
                (
                    true,
                    ProviderJobCancellationStatus::CancelRequested,
                    Some(ProviderStreamEventV1 {
                        schema_version: hivemind_core::PROVIDER_STREAM_EVENT_SCHEMA_VERSION
                            .to_string(),
                        event_id: format!("provider-stream-{}-cancel", request.job_id),
                        job_id: request.job_id.clone(),
                        session_id: request.session_id.clone(),
                        sequence: 0,
                        event_type: ProviderStreamEventType::StreamCancelled,
                        payload: json!({
                            "reason": request.reason.clone(),
                            "jobStartedAt": active_job.started_at,
                            "cancelRequestedAt": now
                        }),
                        created_at: now,
                    }),
                )
            }
            None => (false, ProviderJobCancellationStatus::JobNotActive, None),
        }
    };

    Ok(Json(ProviderJobCancelResponseV1 {
        schema_version: hivemind_core::PROVIDER_JOB_CANCEL_RESPONSE_SCHEMA_VERSION.to_string(),
        cancellation_id: format!("provider-job-cancel-{}", Uuid::new_v4()),
        provider_id: state.identity.provider_id.clone(),
        consumer_id: request.consumer_id,
        session_id: request.session_id,
        job_id: request.job_id,
        accepted,
        status,
        reason: request.reason,
        stream_event,
        ledger_state: Some(ledger_state),
        created_at: now,
        signature: Some(format!(
            "dev-provider-job-cancel-signature-v1:{}:{}",
            state.identity.provider_id, job_id
        )),
    }))
}

async fn provider_get_receipt(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(receipt_id): Path<String>,
) -> Result<Json<ProviderChatReceiptV1>, ProviderApiError> {
    require_auth(&state, &headers)?;
    let receipts = lock_receipts(&state)?;
    let receipt = receipts.get(&receipt_id).ok_or_else(|| {
        ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "receipt_not_found",
            "receipt not found",
        )
    })?;
    Ok(Json(receipt.clone()))
}

async fn provider_get_ledger(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<ProviderLedgerResponse>, ProviderApiError> {
    require_auth(&state, &headers)?;
    let now = Utc::now();
    let mut sessions = lock_sessions(&state)?;
    let stored = sessions.get_mut(&session_id).ok_or_else(|| {
        ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        )
    })?;
    refresh_session_state(stored, &state.policy, now)?;
    Ok(Json(ProviderLedgerResponse {
        session_id,
        state: stored.provider_session.current_ledger_state.clone(),
        events: stored.ledger.clone(),
    }))
}

fn refresh_session_state(
    stored: &mut StoredProviderSession,
    policy: &PseudoPaymentPolicyV1,
    now: DateTime<Utc>,
) -> Result<(), ProviderApiError> {
    let ledger_now = if stored.payment_session.status == ProviderSessionStatus::Closed {
        stored.payment_session.last_forgiveness_at
    } else {
        now
    };
    let state =
        pseudo_payment_state(&stored.payment_session, policy, ledger_now).map_err(payment_error)?;
    stored.provider_session.status = state.status.clone();
    stored.provider_session.current_ledger_state = state;
    Ok(())
}

fn refresh_all_session_states(
    sessions: &mut BTreeMap<String, StoredProviderSession>,
    policy: &PseudoPaymentPolicyV1,
    now: DateTime<Utc>,
) -> Result<(), ProviderApiError> {
    for stored in sessions.values_mut() {
        refresh_session_state(stored, policy, now)?;
    }
    Ok(())
}

fn active_session_count_from_sessions(sessions: &BTreeMap<String, StoredProviderSession>) -> u32 {
    sessions
        .values()
        .filter(|stored| {
            !matches!(
                stored.provider_session.status,
                ProviderSessionStatus::Closed | ProviderSessionStatus::Expired
            )
        })
        .count() as u32
}

fn authorize_model_start(
    state: &ProviderState,
    request: &ProviderModelStartRequestV1,
) -> Result<(), ProviderApiError> {
    if !state.offer.cold_start_policy.allow_consumer_triggered_start {
        return Err(ProviderApiError::new(
            StatusCode::FORBIDDEN,
            "model_start_refused_by_policy",
            "provider policy does not allow consumer-triggered model start",
        ));
    }
    if !state.offer.cold_start_policy.require_session_before_start {
        return Ok(());
    }
    let session_id = request.session_id.as_deref().ok_or_else(|| {
        ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "model_start_requires_session",
            "provider policy requires a session before model start",
        )
    })?;
    let now = Utc::now();
    let mut sessions = lock_sessions(state)?;
    let stored = sessions.get_mut(session_id).ok_or_else(|| {
        ProviderApiError::new(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session not found",
        )
    })?;
    if stored.provider_session.consumer_id != request.consumer_id {
        return Err(ProviderApiError::new(
            StatusCode::FORBIDDEN,
            "consumer_mismatch",
            "model start consumerId does not match the session",
        ));
    }
    if stored.provider_session.provider_id != state.identity.provider_id
        || stored.provider_session.model_id != state.offer.model_id
    {
        return Err(ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "session_model_mismatch",
            "model start session does not match this provider model",
        ));
    }
    refresh_session_state(stored, &state.policy, now)?;
    if state
        .offer
        .cold_start_policy
        .require_payment_authorization_before_start
        && !stored
            .provider_session
            .current_ledger_state
            .can_submit_next_job
    {
        return Err(ProviderApiError::new(
            StatusCode::PAYMENT_REQUIRED,
            "model_start_payment_required",
            stored
                .provider_session
                .current_ledger_state
                .refusal_reason
                .clone()
                .unwrap_or_else(|| "session cannot start model".to_string()),
        ));
    }
    Ok(())
}

fn mark_model_starting(state: &ProviderState) -> Result<bool, ProviderApiError> {
    let now = Utc::now();
    let cutoff = now - Duration::hours(1);
    let mut lifecycle = lock_model_lifecycle(state)?;
    lifecycle
        .recent_start_attempts
        .retain(|started_at| *started_at >= cutoff);
    match lifecycle.state {
        ModelLifecycleStateKind::Ready => return Ok(false),
        ModelLifecycleStateKind::Starting | ModelLifecycleStateKind::Warming => {
            return Ok(false);
        }
        ModelLifecycleStateKind::Disabled => {
            return Err(ProviderApiError::new(
                StatusCode::FORBIDDEN,
                "model_disabled",
                "provider model is disabled",
            ));
        }
        ModelLifecycleStateKind::Unavailable => {
            return Err(ProviderApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "model_unavailable",
                "provider model is unavailable",
            ));
        }
        ModelLifecycleStateKind::Busy
        | ModelLifecycleStateKind::Configured
        | ModelLifecycleStateKind::AvailableCold
        | ModelLifecycleStateKind::Failed
        | ModelLifecycleStateKind::Stopping => {}
    }
    if lifecycle.recent_start_attempts.len() as u32
        >= state.offer.cold_start_policy.max_starts_per_hour
    {
        return Err(ProviderApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "model_start_rate_limited",
            "provider model start rate limit reached",
        ));
    }
    lifecycle.state = ModelLifecycleStateKind::Starting;
    lifecycle.last_started_at = Some(now);
    lifecycle.last_error = None;
    lifecycle.recent_start_attempts.push(now);
    Ok(true)
}

async fn finish_model_start(
    state: &ProviderState,
    start_result: Result<(), ProviderApiError>,
) -> Result<(), ProviderApiError> {
    match start_result {
        Ok(()) => {
            let now = Utc::now();
            {
                let mut lifecycle = lock_model_lifecycle(state)?;
                lifecycle.state = ModelLifecycleStateKind::Ready;
                lifecycle.last_warmed_at = Some(now);
                lifecycle.last_error = None;
            }
            persist_provider_state(state).await
        }
        Err(error) => {
            {
                let mut lifecycle = lock_model_lifecycle(state)?;
                lifecycle.state = ModelLifecycleStateKind::Failed;
                lifecycle.last_error = Some(error.message.clone());
            }
            persist_provider_state(state).await?;
            Err(error)
        }
    }
}

fn mark_model_stopping(state: &ProviderState) -> Result<(), ProviderApiError> {
    if !state.backend.can_stop_model() {
        return Err(ProviderApiError::new(
            StatusCode::CONFLICT,
            "model_stop_not_managed",
            "provider model stop is only supported for managed backend processes",
        ));
    }
    if active_job_count(state) > 0 {
        return Err(ProviderApiError::new(
            StatusCode::CONFLICT,
            "model_stop_busy",
            "provider model cannot be stopped while jobs are active",
        ));
    }
    reconcile_model_lifecycle(state)?;
    let mut lifecycle = lock_model_lifecycle(state)?;
    match lifecycle.state {
        ModelLifecycleStateKind::Disabled => {
            return Err(ProviderApiError::new(
                StatusCode::FORBIDDEN,
                "model_disabled",
                "provider model is disabled",
            ));
        }
        ModelLifecycleStateKind::Unavailable => {
            return Err(ProviderApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "model_unavailable",
                "provider model is unavailable",
            ));
        }
        ModelLifecycleStateKind::Busy
        | ModelLifecycleStateKind::Configured
        | ModelLifecycleStateKind::AvailableCold
        | ModelLifecycleStateKind::Starting
        | ModelLifecycleStateKind::Warming
        | ModelLifecycleStateKind::Ready
        | ModelLifecycleStateKind::Stopping
        | ModelLifecycleStateKind::Failed => {}
    }
    lifecycle.state = ModelLifecycleStateKind::Stopping;
    lifecycle.last_error = None;
    Ok(())
}

async fn finish_model_stop(
    state: &ProviderState,
    stop_result: Result<bool, ProviderApiError>,
) -> Result<(), ProviderApiError> {
    match stop_result {
        Ok(_stopped_live_process) => {
            {
                let mut lifecycle = lock_model_lifecycle(state)?;
                lifecycle.state = ModelLifecycleStateKind::AvailableCold;
                lifecycle.last_error = None;
            }
            persist_provider_state(state).await
        }
        Err(error) => {
            {
                let mut lifecycle = lock_model_lifecycle(state)?;
                lifecycle.state = ModelLifecycleStateKind::Failed;
                lifecycle.last_error = Some(error.message.clone());
            }
            persist_provider_state(state).await?;
            Err(error)
        }
    }
}

fn require_model_ready_for_chat(state: &ProviderState) -> Result<(), ProviderApiError> {
    reconcile_model_lifecycle(state)?;
    let lifecycle = lock_model_lifecycle(state)?;
    match lifecycle.state {
        ModelLifecycleStateKind::Ready => Ok(()),
        ModelLifecycleStateKind::Configured | ModelLifecycleStateKind::AvailableCold => {
            Err(ProviderApiError::new(
                StatusCode::CONFLICT,
                "model_not_started",
                "provider model must be started before chat",
            ))
        }
        ModelLifecycleStateKind::Starting | ModelLifecycleStateKind::Warming => {
            Err(ProviderApiError::new(
                StatusCode::CONFLICT,
                "model_starting",
                "provider model is still starting",
            ))
        }
        ModelLifecycleStateKind::Unavailable | ModelLifecycleStateKind::Failed => {
            Err(ProviderApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "model_not_ready",
                lifecycle
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "provider model is not ready".to_string()),
            ))
        }
        ModelLifecycleStateKind::Disabled => Err(ProviderApiError::new(
            StatusCode::FORBIDDEN,
            "model_disabled",
            "provider model is disabled",
        )),
        ModelLifecycleStateKind::Busy | ModelLifecycleStateKind::Stopping => {
            Err(ProviderApiError::new(
                StatusCode::CONFLICT,
                "model_not_ready",
                "provider model is not accepting chat jobs",
            ))
        }
    }
}

fn validate_chat_feature_support(
    state: &ProviderState,
    request: &ProviderChatRequestV1,
) -> Result<(), ProviderApiError> {
    let Some(tool_policy) = request.tool_policy.as_ref() else {
        return Ok(());
    };
    if tool_policy.is_null() {
        return Ok(());
    }

    require_supported_chat_feature(state, ModelBackendFeature::FunctionCalling, "toolPolicy")?;
    if json_contains_any_key(tool_policy, &["toolChoice", "tool_choice"]) {
        require_supported_chat_feature(state, ModelBackendFeature::ToolChoice, "toolPolicy")?;
    }
    if json_contains_any_key(
        tool_policy,
        &["responseFormat", "response_format", "jsonMode", "json_mode"],
    ) {
        require_supported_chat_feature(state, ModelBackendFeature::JsonMode, "toolPolicy")?;
    }
    if json_contains_any_key(
        tool_policy,
        &[
            "structuredOutput",
            "structured_output",
            "jsonSchema",
            "json_schema",
            "schema",
        ],
    ) {
        require_supported_chat_feature(state, ModelBackendFeature::StructuredOutput, "toolPolicy")?;
    }

    Ok(())
}

fn require_supported_chat_feature(
    state: &ProviderState,
    feature: ModelBackendFeature,
    request_field: &'static str,
) -> Result<(), ProviderApiError> {
    if state.offer.supported_features.contains(&feature) {
        return Ok(());
    }
    Err(ProviderApiError::new(
        StatusCode::BAD_REQUEST,
        "unsupported_chat_feature",
        format!(
            "provider model {} does not advertise {} required by {request_field}",
            state.offer.model_id,
            model_backend_feature_label(&feature)
        ),
    ))
}

fn model_backend_feature_label(feature: &ModelBackendFeature) -> &'static str {
    match feature {
        ModelBackendFeature::Chat => "chat",
        ModelBackendFeature::StreamingChat => "streaming_chat",
        ModelBackendFeature::Completions => "completions",
        ModelBackendFeature::Embeddings => "embeddings",
        ModelBackendFeature::FunctionCalling => "function_calling",
        ModelBackendFeature::StructuredOutput => "structured_output",
        ModelBackendFeature::JsonMode => "json_mode",
        ModelBackendFeature::VisionInput => "vision_input",
        ModelBackendFeature::AudioInput => "audio_input",
        ModelBackendFeature::ToolChoice => "tool_choice",
        ModelBackendFeature::Logprobs => "logprobs",
        ModelBackendFeature::UsageMetrics => "usage_metrics",
        ModelBackendFeature::Cancellation => "cancellation",
        ModelBackendFeature::ModelPull => "model_pull",
        ModelBackendFeature::ModelUnload => "model_unload",
        ModelBackendFeature::Warmup => "warmup",
    }
}

fn json_contains_any_key(value: &Value, keys: &[&str]) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            keys.iter().any(|expected| key == expected) || json_contains_any_key(value, keys)
        }),
        Value::Array(items) => items.iter().any(|item| json_contains_any_key(item, keys)),
        _ => false,
    }
}

fn reconcile_model_lifecycle(state: &ProviderState) -> Result<(), ProviderApiError> {
    let Some(reason) = state.backend.managed_process_exit_reason()? else {
        return Ok(());
    };
    let mut lifecycle = lock_model_lifecycle(state)?;
    if matches!(
        lifecycle.state,
        ModelLifecycleStateKind::Ready
            | ModelLifecycleStateKind::Busy
            | ModelLifecycleStateKind::Starting
            | ModelLifecycleStateKind::Warming
    ) {
        lifecycle.state = ModelLifecycleStateKind::Failed;
        lifecycle.last_error = Some(reason);
    }
    Ok(())
}

fn model_status(state: &ProviderState) -> Result<ModelLifecycleStateV1, ProviderApiError> {
    reconcile_model_lifecycle(state)?;
    let lifecycle = lock_model_lifecycle(state)?.clone();
    let active_jobs = active_job_count(state);
    let public_state = if lifecycle.state == ModelLifecycleStateKind::Ready
        && active_jobs >= state.offer.max_concurrent_jobs
    {
        ModelLifecycleStateKind::Busy
    } else {
        lifecycle.state.clone()
    };
    let estimated_cold_start_seconds = match public_state {
        ModelLifecycleStateKind::Ready | ModelLifecycleStateKind::Busy => Some(0),
        ModelLifecycleStateKind::Failed
        | ModelLifecycleStateKind::Disabled
        | ModelLifecycleStateKind::Unavailable => None,
        _ => Some(state.offer.cold_start_policy.max_cold_start_seconds),
    };
    Ok(ModelLifecycleStateV1 {
        schema_version: hivemind_core::MODEL_LIFECYCLE_STATE_SCHEMA_VERSION.to_string(),
        provider_id: state.identity.provider_id.clone(),
        model_id: state.offer.model_id.clone(),
        state: public_state,
        backend_type: state.backend.backend_type(),
        backend_health: backend_health_for_lifecycle(&state.backend, &lifecycle),
        current_concurrency: active_jobs,
        max_concurrency: state.offer.max_concurrent_jobs,
        last_started_at: lifecycle.last_started_at,
        last_warmed_at: lifecycle.last_warmed_at,
        last_error: lifecycle.last_error,
        estimated_cold_start_seconds,
    })
}

fn backend_health_for_lifecycle(
    backend: &ProviderBackend,
    lifecycle: &StoredProviderModelLifecycle,
) -> String {
    match lifecycle.state {
        ModelLifecycleStateKind::Configured => backend.backend_health_label().to_string(),
        ModelLifecycleStateKind::AvailableCold => "available-cold".to_string(),
        ModelLifecycleStateKind::Starting => "starting".to_string(),
        ModelLifecycleStateKind::Warming => "warming".to_string(),
        ModelLifecycleStateKind::Ready | ModelLifecycleStateKind::Busy => match backend {
            ProviderBackend::Mock => "mock-ready".to_string(),
            ProviderBackend::OpenAiCompatibleHttp(_) => {
                "openai-compatible-ready-unverified".to_string()
            }
        },
        ModelLifecycleStateKind::Stopping => "stopping".to_string(),
        ModelLifecycleStateKind::Failed => lifecycle
            .last_error
            .clone()
            .unwrap_or_else(|| "failed".to_string()),
        ModelLifecycleStateKind::Unavailable => "unavailable".to_string(),
        ModelLifecycleStateKind::Disabled => "disabled".to_string(),
    }
}

fn session_count(state: &ProviderState) -> u32 {
    state
        .sessions
        .lock()
        .map(|sessions| active_session_count_from_sessions(&sessions))
        .unwrap_or(0)
}

fn active_job_count(state: &ProviderState) -> u32 {
    state.active_jobs.load(Ordering::SeqCst)
}

#[derive(Debug)]
struct ProviderJobPermit {
    active_jobs: Arc<AtomicU32>,
    active_job_records: Arc<Mutex<BTreeMap<String, ActiveProviderJob>>>,
    job_id: Option<String>,
}

impl Drop for ProviderJobPermit {
    fn drop(&mut self) {
        self.active_jobs.fetch_sub(1, Ordering::SeqCst);
        let Some(job_id) = self.job_id.as_ref() else {
            return;
        };
        match self.active_job_records.lock() {
            Ok(mut records) => {
                records.remove(job_id);
            }
            Err(_) => {
                warn!("provider active job record state could not be locked during permit drop");
            }
        }
    }
}

#[cfg(test)]
fn acquire_job_permit(state: &ProviderState) -> Result<ProviderJobPermit, ProviderApiError> {
    acquire_job_permit_with_record(state, None)
}

fn acquire_job_permit_for_request(
    state: &ProviderState,
    request: &ProviderChatRequestV1,
) -> Result<ProviderJobPermit, ProviderApiError> {
    acquire_job_permit_with_record(state, Some(request))
}

fn acquire_job_permit_with_record(
    state: &ProviderState,
    request: Option<&ProviderChatRequestV1>,
) -> Result<ProviderJobPermit, ProviderApiError> {
    loop {
        let observed = state.active_jobs.load(Ordering::SeqCst);
        if observed >= state.offer.max_concurrent_jobs {
            return Err(ProviderApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "provider_job_limit_reached",
                format!(
                    "provider already has {observed} active jobs, max is {}",
                    state.offer.max_concurrent_jobs
                ),
            ));
        }
        if state
            .active_jobs
            .compare_exchange(observed, observed + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let mut job_id = None;
            if let Some(request) = request {
                match state.active_job_records.lock() {
                    Ok(mut records) => {
                        if records.contains_key(&request.job_id) {
                            state.active_jobs.fetch_sub(1, Ordering::SeqCst);
                            return Err(ProviderApiError::new(
                                StatusCode::CONFLICT,
                                "provider_job_already_active",
                                format!("provider job {} is already active", request.job_id),
                            ));
                        }
                        let started_at = Utc::now();
                        records.insert(
                            request.job_id.clone(),
                            ActiveProviderJob {
                                session_id: request.session_id.clone(),
                                consumer_id: request.consumer_id.clone(),
                                started_at,
                                cancel_requested: false,
                            },
                        );
                        job_id = Some(request.job_id.clone());
                    }
                    Err(_) => {
                        state.active_jobs.fetch_sub(1, Ordering::SeqCst);
                        return Err(ProviderApiError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "provider_active_job_state_poisoned",
                            "provider active job state could not be locked",
                        ));
                    }
                }
            }
            return Ok(ProviderJobPermit {
                active_jobs: state.active_jobs.clone(),
                active_job_records: state.active_job_records.clone(),
                job_id,
            });
        }
    }
}

fn validate_chat_resource_limits(
    state: &ProviderState,
    request: &ProviderChatRequestV1,
) -> Result<(), ProviderApiError> {
    if request.messages.len() > state.max_prompt_messages {
        return Err(ProviderApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "prompt_message_limit_exceeded",
            format!(
                "chat request has {} messages, max is {}",
                request.messages.len(),
                state.max_prompt_messages
            ),
        ));
    }
    let prompt_bytes = serde_json::to_vec(&request.messages).map_err(|error| {
        ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "prompt_invalid",
            format!("chat messages could not be serialized for limit checks: {error}"),
        )
    })?;
    if prompt_bytes.len() > state.max_prompt_bytes {
        return Err(ProviderApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "prompt_byte_limit_exceeded",
            format!(
                "chat prompt is {} bytes, max is {}",
                prompt_bytes.len(),
                state.max_prompt_bytes
            ),
        ));
    }
    let estimated_input_tokens = estimate_tokens(&messages_text(&request.messages)).max(1);
    if estimated_input_tokens > state.offer.max_context_tokens {
        return Err(ProviderApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "prompt_context_limit_exceeded",
            format!(
                "estimated prompt tokens {estimated_input_tokens} exceed context limit {}",
                state.offer.max_context_tokens
            ),
        ));
    }
    if estimated_input_tokens.saturating_add(request.max_output_tokens)
        > state.offer.max_context_tokens
    {
        return Err(ProviderApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "prompt_context_limit_exceeded",
            format!(
                "estimated prompt plus requested output tokens exceed context limit {}",
                state.offer.max_context_tokens
            ),
        ));
    }
    Ok(())
}

fn messages_text(messages: &[Value]) -> String {
    messages
        .iter()
        .filter_map(|message| message.get("content"))
        .filter_map(message_text)
        .collect::<Vec<_>>()
        .join("\n")
}

fn require_auth(state: &ProviderState, headers: &HeaderMap) -> Result<(), ProviderApiError> {
    let Some(expected_token) = &state.bearer_token else {
        return Ok(());
    };
    let expected = format!("Bearer {}", expected_token.as_str());
    let observed = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if observed == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "provider_auth_required",
            "provider bearer token is missing or invalid",
        ))
    }
}

fn require_signed_request<T: Serialize>(
    state: &ProviderState,
    request: &T,
    envelope: Option<&SignedRequestEnvelopeV1>,
    method: &str,
    path: &str,
    consumer_id: &str,
    session_id: Option<&str>,
    quote_id: Option<&str>,
) -> Result<(), ProviderApiError> {
    let Some(envelope) = envelope else {
        if state.require_signed_requests {
            return Err(ProviderApiError::new(
                StatusCode::UNAUTHORIZED,
                "signed_request_required",
                "provider requires a signed request envelope",
            ));
        }
        return Ok(());
    };

    let now = Utc::now();
    let issues = validate_signed_request_envelope(envelope, method, path, now);
    if let Some(first) = issues.first() {
        return Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_request_invalid",
            format!("{}: {}", first.path, first.message),
        ));
    }
    if envelope.provider_id != state.identity.provider_id {
        return Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_request_provider_mismatch",
            "signed request providerId does not match this provider",
        ));
    }
    if envelope.consumer_id != consumer_id {
        return Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_request_consumer_mismatch",
            "signed request consumerId does not match request body",
        ));
    }
    if let Some(expected_session_id) = session_id {
        if envelope.session_id.as_deref() != Some(expected_session_id) {
            return Err(ProviderApiError::new(
                StatusCode::UNAUTHORIZED,
                "signed_request_session_mismatch",
                "signed request sessionId does not match request body",
            ));
        }
    }
    if let Some(expected_quote_id) = quote_id {
        if envelope.quote_id.as_deref() != Some(expected_quote_id) {
            return Err(ProviderApiError::new(
                StatusCode::UNAUTHORIZED,
                "signed_request_quote_mismatch",
                "signed request quoteId does not match request body",
            ));
        }
    }

    let body_hash = signed_request_body_hash(request)?;
    if envelope.body_hash != body_hash {
        return Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_request_body_hash_mismatch",
            "signed request bodyHash does not match request body",
        ));
    }
    if envelope.signature_scheme != "local-dev-deterministic" {
        return Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_request_signature_scheme_unsupported",
            "provider MVP only supports local-dev-deterministic signed envelopes",
        ));
    }
    let expected_signature =
        dev_signed_request_signature(&envelope.consumer_id, &envelope.nonce, &envelope.body_hash);
    if envelope.signature != expected_signature {
        return Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_request_signature_invalid",
            "signed request signature is invalid",
        ));
    }
    remember_signed_nonce(state, envelope, now)
}

fn signed_request_body_hash<T: Serialize>(request: &T) -> Result<String, ProviderApiError> {
    let mut value = serde_json::to_value(request).map_err(|error| {
        ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "signed_request_body_invalid",
            format!("request body could not be serialized for signing: {error}"),
        )
    })?;
    if let Value::Object(map) = &mut value {
        map.remove("requestEnvelope");
    }
    Ok(hash_canonical_json(&value))
}

fn dev_signed_request_signature(consumer_id: &str, nonce: &str, body_hash: &str) -> String {
    format!("dev-signed-request-envelope-v1:{consumer_id}:{nonce}:{body_hash}")
}

fn remember_signed_nonce(
    state: &ProviderState,
    envelope: &SignedRequestEnvelopeV1,
    now: DateTime<Utc>,
) -> Result<(), ProviderApiError> {
    let mut nonces = state.signed_request_nonces.lock().map_err(|_| {
        ProviderApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider_nonce_state_poisoned",
            "provider signed request nonce state could not be locked",
        )
    })?;
    nonces.retain(|_, expires_at| *expires_at > now);
    let key = format!("{}:{}", envelope.consumer_id, envelope.nonce);
    if nonces.contains_key(&key) {
        return Err(ProviderApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_request_replay",
            "signed request nonce has already been used",
        ));
    }
    nonces.insert(key, envelope.expires_at);
    Ok(())
}

fn lock_sessions(
    state: &ProviderState,
) -> Result<MutexGuard<'_, BTreeMap<String, StoredProviderSession>>, ProviderApiError> {
    state.sessions.lock().map_err(|_| {
        ProviderApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider_state_poisoned",
            "provider session state could not be locked",
        )
    })
}

fn lock_receipts(
    state: &ProviderState,
) -> Result<MutexGuard<'_, BTreeMap<String, ProviderChatReceiptV1>>, ProviderApiError> {
    state.receipts.lock().map_err(|_| {
        ProviderApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider_state_poisoned",
            "provider receipt state could not be locked",
        )
    })
}

fn lock_model_lifecycle(
    state: &ProviderState,
) -> Result<MutexGuard<'_, StoredProviderModelLifecycle>, ProviderApiError> {
    state.model_lifecycle.lock().map_err(|_| {
        ProviderApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider_state_poisoned",
            "provider model lifecycle state could not be locked",
        )
    })
}

fn lock_active_job_records(
    state: &ProviderState,
) -> Result<MutexGuard<'_, BTreeMap<String, ActiveProviderJob>>, ProviderApiError> {
    state.active_job_records.lock().map_err(|_| {
        ProviderApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider_active_job_state_poisoned",
            "provider active job state could not be locked",
        )
    })
}

fn auth_modes_for_config(config: &ServeProviderConfig) -> Vec<ProviderAuthMode> {
    let mut modes = Vec::new();
    if config.bearer_token.is_some() {
        modes.push(ProviderAuthMode::BearerToken);
    }
    if config.require_signed_requests {
        modes.push(ProviderAuthMode::SignedRequestEnvelope);
    }
    if modes.is_empty() {
        modes.push(ProviderAuthMode::None);
    }
    modes
}

pub fn parse_provider_security_mode(value: &str) -> Result<ProviderSecurityMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local-dev" | "local" | "dev" => Ok(ProviderSecurityMode::LocalDev),
        "lan-test" | "lan" => Ok(ProviderSecurityMode::LanTest),
        "testnet" | "test-net" => Ok(ProviderSecurityMode::Testnet),
        "production" | "production-reserved" => Ok(ProviderSecurityMode::ProductionReserved),
        other => bail!(
            "unknown provider security mode {other}; expected local-dev, lan-test, testnet, or production-reserved"
        ),
    }
}

pub fn parse_provider_backend_type(value: &str) -> Result<ModelBackendType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "mock" | "local-mock" => Ok(ModelBackendType::Mock),
        "openai-compatible-http" | "openai-compatible" | "openai-http" | "openai" => {
            Ok(ModelBackendType::OpenAiCompatibleHttp)
        }
        other => {
            bail!("unknown provider backend type {other}; expected mock or openai-compatible-http")
        }
    }
}

pub fn parse_model_lifecycle_state(value: &str) -> Result<ModelLifecycleStateKind> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "configured" => Ok(ModelLifecycleStateKind::Configured),
        "unavailable" => Ok(ModelLifecycleStateKind::Unavailable),
        "available_cold" | "cold" => Ok(ModelLifecycleStateKind::AvailableCold),
        "starting" => Ok(ModelLifecycleStateKind::Starting),
        "warming" => Ok(ModelLifecycleStateKind::Warming),
        "ready" | "warm" => Ok(ModelLifecycleStateKind::Ready),
        "busy" => Ok(ModelLifecycleStateKind::Busy),
        "stopping" => Ok(ModelLifecycleStateKind::Stopping),
        "failed" => Ok(ModelLifecycleStateKind::Failed),
        "disabled" => Ok(ModelLifecycleStateKind::Disabled),
        other => bail!(
            "unknown model lifecycle state {other}; expected configured, unavailable, available_cold, starting, warming, ready, busy, stopping, failed, or disabled"
        ),
    }
}

fn readiness_for_security_mode(mode: &ProviderSecurityMode) -> ProviderReadinessLabel {
    match mode {
        ProviderSecurityMode::LocalDev => ProviderReadinessLabel::Local,
        ProviderSecurityMode::LanTest => ProviderReadinessLabel::LanTest,
        ProviderSecurityMode::Testnet => ProviderReadinessLabel::Testnet,
        ProviderSecurityMode::ProductionReserved => ProviderReadinessLabel::ProductionReserved,
    }
}

fn last_user_text(messages: &[Value]) -> String {
    messages
        .iter()
        .rev()
        .find_map(|message| {
            let role = message.get("role")?.as_str()?;
            (role == "user").then(|| message_text(message.get("content").unwrap_or(&Value::Null)))
        })
        .flatten()
        .unwrap_or_else(|| "hello".to_string())
}

fn message_text(content: &Value) -> Option<String> {
    if let Some(text) = content.as_str() {
        return Some(text.to_string());
    }
    content.as_array().map(|parts| {
        parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn mock_backend_chat(request: &ProviderChatRequestV1) -> BackendChatOutput {
    let input_text = last_user_text(&request.messages);
    let text = format!(
        "Mock provider {} received: {}",
        request.model_id, input_text
    );
    let usage = mock_usage(request, &input_text, &text);
    BackendChatOutput {
        text,
        usage,
        backend_type: ModelBackendType::Mock,
    }
}

fn mock_usage(request: &ProviderChatRequestV1, input_text: &str, answer: &str) -> ProviderUsageV1 {
    let input_tokens = estimate_tokens(input_text).max(1);
    let output_tokens = estimate_tokens(answer)
        .min(request.max_output_tokens)
        .max(1);
    ProviderUsageV1 {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        model_seconds: 0.05,
        queue_seconds: 0.0,
        first_token_ms: Some(10),
        tokens_per_second: Some(output_tokens as f64 / 0.05),
        usage_confidence: UsageConfidence::Estimated,
    }
}

fn estimate_tokens(text: &str) -> u64 {
    let words = text.split_whitespace().count() as u64;
    words.max((text.len() as u64).saturating_add(3) / 4)
}

fn mock_stream_events(
    request: &ProviderChatRequestV1,
    answer: &str,
    receipt: &ProviderChatReceiptV1,
    ledger_state: &PseudoPaymentStateV1,
    started_at: DateTime<Utc>,
) -> Vec<ProviderStreamEventV1> {
    vec![
        stream_event(
            request,
            1,
            ProviderStreamEventType::StreamStarted,
            json!({ "stream": request.stream }),
            started_at,
        ),
        stream_event(
            request,
            2,
            ProviderStreamEventType::ModelReady,
            json!({ "backendType": "mock" }),
            started_at + Duration::milliseconds(5),
        ),
        stream_event(
            request,
            3,
            ProviderStreamEventType::TokenDelta,
            json!({ "text": answer }),
            started_at + Duration::milliseconds(10),
        ),
        stream_event(
            request,
            4,
            ProviderStreamEventType::ReceiptCreated,
            json!({ "receipt": receipt }),
            receipt.finished_at,
        ),
        stream_event(
            request,
            5,
            ProviderStreamEventType::LedgerUpdated,
            json!({ "state": ledger_state }),
            receipt.finished_at,
        ),
        stream_event(
            request,
            6,
            ProviderStreamEventType::StreamFinished,
            json!({ "receiptId": receipt.receipt_id }),
            receipt.finished_at,
        ),
    ]
}

fn stream_event(
    request: &ProviderChatRequestV1,
    sequence: u64,
    event_type: ProviderStreamEventType,
    payload: Value,
    created_at: DateTime<Utc>,
) -> ProviderStreamEventV1 {
    ProviderStreamEventV1 {
        schema_version: hivemind_core::PROVIDER_STREAM_EVENT_SCHEMA_VERSION.to_string(),
        event_id: format!("provider-stream-{}-{sequence}", request.job_id),
        job_id: request.job_id.clone(),
        session_id: request.session_id.clone(),
        sequence,
        event_type,
        payload,
        created_at,
    }
}

fn payment_error(error: hivemind_core::PseudoPaymentError) -> ProviderApiError {
    match error {
        hivemind_core::PseudoPaymentError::DebtCeilingExceeded => ProviderApiError::new(
            StatusCode::PAYMENT_REQUIRED,
            "debt_ceiling_exceeded",
            error.to_string(),
        ),
        hivemind_core::PseudoPaymentError::SessionExpired => {
            ProviderApiError::new(StatusCode::FORBIDDEN, "session_expired", error.to_string())
        }
        hivemind_core::PseudoPaymentError::SessionNotActive => ProviderApiError::new(
            StatusCode::FORBIDDEN,
            "session_not_active",
            error.to_string(),
        ),
        _ => ProviderApiError::new(
            StatusCode::BAD_REQUEST,
            "pseudopayment_error",
            error.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ServeProviderConfig {
        ServeProviderConfig {
            host: "127.0.0.1".to_string(),
            port: 8788,
            security_mode: ProviderSecurityMode::LocalDev,
            bearer_token: None,
            provider_id: "provider-local".to_string(),
            display_name: "Local Provider".to_string(),
            model_id: "mock-chat".to_string(),
            model_display_name: "Mock Chat".to_string(),
            backend_type: ModelBackendType::Mock,
            backend_model_id: "mock-chat".to_string(),
            backend_base_url: None,
            backend_api_key: None,
            backend_timeout_seconds: 60,
            backend_start_command: None,
            backend_start_args: Vec::new(),
            backend_health_url: None,
            max_debt: 100.0,
            forgiveness_per_second: 10.0,
            price_per_input_token: 0.1,
            price_per_output_token: 0.2,
            price_per_model_second: 1.0,
            price_per_request: 1.0,
            state_path: std::env::temp_dir()
                .join(format!("hivemind-provider-test-{}.json", Uuid::new_v4())),
            require_signed_requests: false,
            max_concurrent_sessions: 32,
            max_concurrent_jobs: 1,
            max_context_tokens: 8192,
            max_output_tokens: 1024,
            max_prompt_bytes: 262_144,
            max_prompt_messages: 64,
            max_model_starts_per_hour: 60,
            max_cold_start_seconds: 1,
            initial_model_state: None,
        }
    }

    fn quote_request(state: &ProviderState) -> ProviderQuoteRequestV1 {
        ProviderQuoteRequestV1 {
            schema_version: hivemind_core::PROVIDER_QUOTE_REQUEST_SCHEMA_VERSION.to_string(),
            request_id: "quote-request-1".to_string(),
            consumer_id: "consumer-1".to_string(),
            provider_id: state.identity.provider_id.clone(),
            model_id: state.offer.model_id.clone(),
            task: "chat".to_string(),
            expected_max_input_tokens: 100,
            expected_max_output_tokens: 50,
            streaming: true,
            requested_privacy_tier: PrivacyTier::Standard,
            requested_verification_tier: IntegrityTier::ReceiptOnly,
            payment_mode: ProviderPaymentMode::PseudopaymentDebtForgiveness,
            request_envelope: None,
            created_at: Utc::now(),
            signature: None,
        }
    }

    fn chat_request(state: &ProviderState) -> ProviderChatRequestV1 {
        ProviderChatRequestV1 {
            schema_version: hivemind_core::PROVIDER_CHAT_REQUEST_SCHEMA_VERSION.to_string(),
            job_id: "job-1".to_string(),
            session_id: "session-1".to_string(),
            provider_id: state.identity.provider_id.clone(),
            consumer_id: "consumer-1".to_string(),
            model_id: state.offer.model_id.clone(),
            messages: vec![json!({ "role": "user", "content": "hello there" })],
            stream: true,
            max_output_tokens: 100,
            temperature: None,
            tool_policy: None,
            request_envelope: None,
            created_at: Utc::now(),
        }
    }

    fn session_open_request(state: &ProviderState) -> ProviderSessionOpenRequestV1 {
        ProviderSessionOpenRequestV1 {
            schema_version: hivemind_core::PROVIDER_SESSION_OPEN_REQUEST_SCHEMA_VERSION.to_string(),
            request_id: "open-1".to_string(),
            quote_id: "quote-1".to_string(),
            consumer_id: "consumer-1".to_string(),
            provider_id: state.identity.provider_id.clone(),
            accepted_policy_hash: "policy-hash-1".to_string(),
            spending_cap: 10.0,
            requested_expires_at: Utc::now() + Duration::minutes(5),
            auth_proof: None,
            request_envelope: None,
            signature: None,
        }
    }

    fn session_close_request(
        state: &ProviderState,
        session_id: impl Into<String>,
    ) -> ProviderSessionCloseRequestV1 {
        ProviderSessionCloseRequestV1 {
            schema_version: hivemind_core::PROVIDER_SESSION_CLOSE_REQUEST_SCHEMA_VERSION
                .to_string(),
            request_id: format!("close-{}", Uuid::new_v4()),
            provider_id: state.identity.provider_id.clone(),
            consumer_id: "consumer-1".to_string(),
            session_id: session_id.into(),
            reason: Some("test close".to_string()),
            request_envelope: None,
            created_at: Utc::now(),
            signature: None,
        }
    }

    fn job_cancel_request(
        state: &ProviderState,
        session_id: impl Into<String>,
        job_id: impl Into<String>,
    ) -> ProviderJobCancelRequestV1 {
        ProviderJobCancelRequestV1 {
            schema_version: hivemind_core::PROVIDER_JOB_CANCEL_REQUEST_SCHEMA_VERSION.to_string(),
            request_id: format!("cancel-{}", Uuid::new_v4()),
            provider_id: state.identity.provider_id.clone(),
            consumer_id: "consumer-1".to_string(),
            session_id: session_id.into(),
            job_id: job_id.into(),
            reason: Some("test cancellation".to_string()),
            request_envelope: None,
            created_at: Utc::now(),
            signature: None,
        }
    }

    fn model_start_request(
        state: &ProviderState,
        session_id: Option<String>,
    ) -> ProviderModelStartRequestV1 {
        ProviderModelStartRequestV1 {
            schema_version: hivemind_core::PROVIDER_MODEL_START_REQUEST_SCHEMA_VERSION.to_string(),
            request_id: format!("start-{}", Uuid::new_v4()),
            provider_id: state.identity.provider_id.clone(),
            consumer_id: "consumer-1".to_string(),
            model_id: state.offer.model_id.clone(),
            session_id,
            request_envelope: None,
            created_at: Utc::now(),
            signature: None,
        }
    }

    fn model_stop_request(
        state: &ProviderState,
        session_id: Option<String>,
    ) -> ProviderModelStopRequestV1 {
        ProviderModelStopRequestV1 {
            schema_version: hivemind_core::PROVIDER_MODEL_STOP_REQUEST_SCHEMA_VERSION.to_string(),
            request_id: format!("stop-{}", Uuid::new_v4()),
            provider_id: state.identity.provider_id.clone(),
            consumer_id: "consumer-1".to_string(),
            model_id: state.offer.model_id.clone(),
            session_id,
            request_envelope: None,
            created_at: Utc::now(),
            signature: None,
        }
    }

    fn attach_signed_envelope(
        request: &mut ProviderQuoteRequestV1,
        state: &ProviderState,
        nonce: &str,
    ) {
        let body_hash = signed_request_body_hash(request).unwrap();
        request.request_envelope = Some(SignedRequestEnvelopeV1 {
            schema_version: hivemind_core::SIGNED_REQUEST_ENVELOPE_SCHEMA_VERSION.to_string(),
            envelope_id: format!("envelope-{nonce}"),
            provider_id: state.identity.provider_id.clone(),
            consumer_id: request.consumer_id.clone(),
            method: "POST".to_string(),
            path: "/v1/provider/quote".to_string(),
            body_hash: body_hash.clone(),
            nonce: nonce.to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            session_id: None,
            quote_id: None,
            signature_scheme: "local-dev-deterministic".to_string(),
            signature: dev_signed_request_signature(&request.consumer_id, nonce, &body_hash),
        });
    }

    #[test]
    fn provider_state_refuses_lan_bind_without_auth() {
        let mut config = config();
        config.host = "0.0.0.0".to_string();
        config.security_mode = ProviderSecurityMode::LanTest;

        assert!(provider_state_from_config(config).is_err());
    }

    #[test]
    fn provider_state_accepts_lan_bind_with_bearer_auth() {
        let mut config = config();
        config.host = "0.0.0.0".to_string();
        config.security_mode = ProviderSecurityMode::LanTest;
        config.bearer_token = Some("secret".to_string());

        let state = provider_state_from_config(config).unwrap();
        assert_eq!(state.auth_modes, vec![ProviderAuthMode::BearerToken]);
        assert_eq!(state.offer.readiness_label, ProviderReadinessLabel::LanTest);
    }

    #[test]
    fn provider_state_accepts_lan_bind_with_signed_requests() {
        let mut config = config();
        config.host = "0.0.0.0".to_string();
        config.security_mode = ProviderSecurityMode::LanTest;
        config.require_signed_requests = true;

        let state = provider_state_from_config(config).unwrap();
        assert_eq!(
            state.auth_modes,
            vec![ProviderAuthMode::SignedRequestEnvelope]
        );
        assert!(state.require_signed_requests);
    }

    #[test]
    fn provider_state_advertises_configured_resource_limits() {
        let mut config = config();
        config.max_concurrent_sessions = 3;
        config.max_concurrent_jobs = 2;
        config.max_context_tokens = 2048;
        config.max_output_tokens = 256;
        config.max_model_starts_per_hour = 7;
        config.max_cold_start_seconds = 12;
        let state = provider_state_from_config(config).unwrap();

        assert_eq!(state.offer.max_concurrent_sessions, 3);
        assert_eq!(state.offer.max_concurrent_jobs, 2);
        assert_eq!(state.offer.max_context_tokens, 2048);
        assert_eq!(state.offer.max_output_tokens, 256);
        assert_eq!(state.policy.max_concurrent_jobs, 2);
        assert_eq!(state.offer.cold_start_policy.max_starts_per_hour, 7);
        assert_eq!(state.offer.cold_start_policy.max_cold_start_seconds, 12);
    }

    #[test]
    fn provider_state_uses_configured_initial_model_state() {
        let mut config = config();
        config.initial_model_state = Some(ModelLifecycleStateKind::AvailableCold);
        let state = provider_state_from_config(config).unwrap();
        let status = model_status(&state).unwrap();

        assert_eq!(status.state, ModelLifecycleStateKind::AvailableCold);
        assert_eq!(status.estimated_cold_start_seconds, Some(1));
    }

    #[test]
    fn openai_compatible_backend_requires_base_url() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;

        assert!(provider_state_from_config(config).is_err());
    }

    #[test]
    fn openai_compatible_backend_advertises_configured_backend() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;
        config.backend_base_url = Some("http://127.0.0.1:8000/v1/".to_string());
        config.backend_model_id = "local-model".to_string();

        let state = provider_state_from_config(config).unwrap();
        assert_eq!(
            state.offer.backend_type,
            ModelBackendType::OpenAiCompatibleHttp
        );
        assert_eq!(state.offer.backend_model_id, "local-model");
        assert_eq!(
            state.backend.backend_health_label(),
            "openai-compatible-configured"
        );
    }

    #[test]
    fn managed_openai_backend_starts_cold_and_advertises_warmup() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;
        config.backend_base_url = Some("http://127.0.0.1:8000/v1/".to_string());
        config.backend_start_command = Some("hivemind-test-managed-backend".to_string());

        let state = provider_state_from_config(config).unwrap();
        let status = model_status(&state).unwrap();

        assert_eq!(status.state, ModelLifecycleStateKind::AvailableCold);
        assert_eq!(status.backend_health, "available-cold");
        assert!(
            state
                .offer
                .supported_features
                .contains(&ModelBackendFeature::Warmup)
        );
    }

    #[test]
    fn managed_backend_args_require_start_command() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;
        config.backend_base_url = Some("http://127.0.0.1:8000/v1/".to_string());
        config.backend_start_args = vec!["serve".to_string()];

        let error = provider_state_from_config(config).unwrap_err();
        assert!(error.to_string().contains("--backend-start-arg"));
    }

    #[test]
    fn bearer_auth_rejects_missing_or_wrong_token() {
        let mut config = config();
        config.bearer_token = Some("secret".to_string());
        let state = provider_state_from_config(config).unwrap();
        let headers = HeaderMap::new();

        assert!(require_auth(&state, &headers).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(require_auth(&state, &headers).is_ok());
    }

    #[test]
    fn signed_request_envelope_accepts_valid_request_and_rejects_replay() {
        let mut config = config();
        config.require_signed_requests = true;
        let state = provider_state_from_config(config).unwrap();
        let mut request = quote_request(&state);
        attach_signed_envelope(&mut request, &state, "nonce-1");

        assert!(
            require_signed_request(
                &state,
                &request,
                request.request_envelope.as_ref(),
                "POST",
                "/v1/provider/quote",
                &request.consumer_id,
                None,
                None,
            )
            .is_ok()
        );
        let replay = require_signed_request(
            &state,
            &request,
            request.request_envelope.as_ref(),
            "POST",
            "/v1/provider/quote",
            &request.consumer_id,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(replay.code, "signed_request_replay");
    }

    #[test]
    fn signed_request_required_rejects_missing_envelope() {
        let mut config = config();
        config.require_signed_requests = true;
        let state = provider_state_from_config(config).unwrap();
        let request = quote_request(&state);

        let error = require_signed_request(
            &state,
            &request,
            None,
            "POST",
            "/v1/provider/quote",
            &request.consumer_id,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, "signed_request_required");
    }

    #[test]
    fn signed_request_envelope_rejects_expired_envelope() {
        let mut config = config();
        config.require_signed_requests = true;
        let state = provider_state_from_config(config).unwrap();
        let mut request = quote_request(&state);
        attach_signed_envelope(&mut request, &state, "nonce-expired");
        let envelope = request.request_envelope.as_mut().unwrap();
        envelope.issued_at = Utc::now() - Duration::minutes(10);
        envelope.expires_at = Utc::now() - Duration::minutes(1);

        let error = require_signed_request(
            &state,
            &request,
            request.request_envelope.as_ref(),
            "POST",
            "/v1/provider/quote",
            &request.consumer_id,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, "signed_request_invalid");
    }

    #[test]
    fn signed_request_envelope_rejects_body_hash_mismatch() {
        let mut config = config();
        config.require_signed_requests = true;
        let state = provider_state_from_config(config).unwrap();
        let mut request = quote_request(&state);
        attach_signed_envelope(&mut request, &state, "nonce-2");
        request.expected_max_output_tokens += 1;

        let error = require_signed_request(
            &state,
            &request,
            request.request_envelope.as_ref(),
            "POST",
            "/v1/provider/quote",
            &request.consumer_id,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, "signed_request_body_hash_mismatch");
    }

    #[test]
    fn mock_usage_cost_feeds_pseudopayment_policy() {
        let state = provider_state_from_config(config()).unwrap();
        let request = chat_request(&state);

        let input = last_user_text(&request.messages);
        let usage = mock_usage(&request, &input, "mock answer");
        let cost = provider_chat_usage_cost(&state.policy, &usage);

        assert!(cost > state.policy.price_per_request.unwrap());
    }

    #[test]
    fn chat_resource_limits_reject_oversized_prompts() {
        let mut byte_limit_config = config();
        byte_limit_config.max_prompt_bytes = 20;
        let state = provider_state_from_config(byte_limit_config).unwrap();
        let request = chat_request(&state);
        let error = validate_chat_resource_limits(&state, &request).unwrap_err();
        assert_eq!(error.code, "prompt_byte_limit_exceeded");

        let mut message_limit_config = config();
        message_limit_config.max_prompt_messages = 1;
        let state = provider_state_from_config(message_limit_config).unwrap();
        let mut request = chat_request(&state);
        request
            .messages
            .push(json!({ "role": "user", "content": "second" }));
        let error = validate_chat_resource_limits(&state, &request).unwrap_err();
        assert_eq!(error.code, "prompt_message_limit_exceeded");

        let mut context_limit_config = config();
        context_limit_config.max_context_tokens = 3;
        let state = provider_state_from_config(context_limit_config).unwrap();
        let request = chat_request(&state);
        let error = validate_chat_resource_limits(&state, &request).unwrap_err();
        assert_eq!(error.code, "prompt_context_limit_exceeded");
    }

    #[tokio::test]
    async fn provider_chat_rejects_unsupported_tool_policy_before_debit() {
        let state = provider_state_from_config(config()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let mut request = chat_request(&state);
        request.session_id = open.session.session_id.clone();
        request.tool_policy = Some(json!({
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "parameters": { "type": "object" }
                    }
                }
            ],
            "toolChoice": "auto"
        }));

        let error = provider_chat(State(state.clone()), HeaderMap::new(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(error.code, "unsupported_chat_feature");
        assert!(error.message.contains("function_calling"));
        let sessions = lock_sessions(&state).unwrap();
        assert_eq!(sessions[&open.session.session_id].ledger.len(), 1);
        drop(sessions);
        assert!(lock_receipts(&state).unwrap().is_empty());
    }

    #[test]
    fn job_limit_rejects_second_active_job() {
        let state = provider_state_from_config(config()).unwrap();
        let permit = acquire_job_permit(&state).unwrap();
        assert_eq!(active_job_count(&state), 1);
        let error = acquire_job_permit(&state).unwrap_err();
        assert_eq!(error.code, "provider_job_limit_reached");

        drop(permit);
        assert_eq!(active_job_count(&state), 0);
        assert!(acquire_job_permit(&state).is_ok());
    }

    #[tokio::test]
    async fn provider_cancel_job_reports_not_active_without_ledger_debit() {
        let state = provider_state_from_config(config()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let request = job_cancel_request(&state, open.session.session_id.clone(), "job-missing");

        let response = provider_cancel_job(
            State(state.clone()),
            HeaderMap::new(),
            Path("job-missing".to_string()),
            Json(request),
        )
        .await
        .unwrap()
        .0;

        assert!(!response.accepted);
        assert_eq!(response.status, ProviderJobCancellationStatus::JobNotActive);
        assert!(response.stream_event.is_none());
        assert!(response.ledger_state.is_some());
        let sessions = lock_sessions(&state).unwrap();
        assert_eq!(sessions[&open.session.session_id].ledger.len(), 1);
        drop(sessions);
        assert!(lock_receipts(&state).unwrap().is_empty());
    }

    #[tokio::test]
    async fn provider_cancel_job_marks_active_job_requested() {
        let state = provider_state_from_config(config()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let mut chat = chat_request(&state);
        chat.session_id = open.session.session_id.clone();
        let permit = acquire_job_permit_for_request(&state, &chat).unwrap();
        let request =
            job_cancel_request(&state, open.session.session_id.clone(), chat.job_id.clone());

        let response = provider_cancel_job(
            State(state.clone()),
            HeaderMap::new(),
            Path(chat.job_id.clone()),
            Json(request),
        )
        .await
        .unwrap()
        .0;

        assert!(response.accepted);
        assert_eq!(
            response.status,
            ProviderJobCancellationStatus::CancelRequested
        );
        let stream_event = response.stream_event.unwrap();
        assert_eq!(
            stream_event.event_type,
            ProviderStreamEventType::StreamCancelled
        );
        assert_eq!(active_job_count(&state), 1);
        {
            let records = lock_active_job_records(&state).unwrap();
            assert!(records[&chat.job_id].cancel_requested);
        }
        drop(permit);
        assert_eq!(active_job_count(&state), 0);
        assert!(lock_active_job_records(&state).unwrap().is_empty());
    }

    #[tokio::test]
    async fn provider_cancel_job_rejects_unsupported_backend() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;
        config.backend_base_url = Some("http://127.0.0.1:8000/v1/".to_string());
        let state = provider_state_from_config(config).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let request = job_cancel_request(&state, open.session.session_id, "job-1");

        let error = provider_cancel_job(
            State(state),
            HeaderMap::new(),
            Path("job-1".to_string()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "unsupported_job_cancellation");
    }

    #[tokio::test]
    async fn provider_open_session_enforces_session_limit() {
        let mut config = config();
        config.max_concurrent_sessions = 1;
        let state = provider_state_from_config(config).unwrap();
        let first = session_open_request(&state);
        let _ = provider_open_session(State(state.clone()), HeaderMap::new(), Json(first))
            .await
            .unwrap();

        let mut second = session_open_request(&state);
        second.request_id = "open-2".to_string();
        let error = provider_open_session(State(state), HeaderMap::new(), Json(second))
            .await
            .unwrap_err();
        assert_eq!(error.code, "provider_session_limit_reached");
    }

    #[tokio::test]
    async fn provider_close_session_records_ledger_and_blocks_chat() {
        let state = provider_state_from_config(config()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let close_request = session_close_request(&state, open.session.session_id.clone());

        let closed = provider_close_session(
            State(state.clone()),
            HeaderMap::new(),
            Path(open.session.session_id.clone()),
            Json(close_request),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(closed.session.status, ProviderSessionStatus::Closed);
        assert_eq!(
            closed.ledger_event.event_type,
            PseudoLedgerEventType::SessionClosed
        );
        assert_eq!(closed.ledger_event.sequence, 1);
        assert!(!closed.session.current_ledger_state.can_submit_next_job);

        let mut request = chat_request(&state);
        request.session_id = open.session.session_id;
        let error = provider_chat(State(state), HeaderMap::new(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(error.code, "debt_ceiling_exceeded");
        assert!(error.message.contains("session is not active"));
    }

    #[tokio::test]
    async fn provider_close_session_frees_session_capacity() {
        let mut config = config();
        config.max_concurrent_sessions = 1;
        let state = provider_state_from_config(config).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let close_request = session_close_request(&state, open.session.session_id.clone());
        let _ = provider_close_session(
            State(state.clone()),
            HeaderMap::new(),
            Path(open.session.session_id),
            Json(close_request),
        )
        .await
        .unwrap();

        let mut second = session_open_request(&state);
        second.request_id = "open-2".to_string();
        let second = provider_open_session(State(state), HeaderMap::new(), Json(second))
            .await
            .unwrap()
            .0;

        assert_eq!(second.session.status, ProviderSessionStatus::Active);
    }

    #[tokio::test]
    async fn provider_session_summary_requires_closed_session() {
        let state = provider_state_from_config(config()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;

        let error = provider_get_session_summary(
            State(state),
            HeaderMap::new(),
            Path(open.session.session_id),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "session_not_closed");
    }

    #[tokio::test]
    async fn provider_session_summary_rolls_up_closed_session_receipts_and_ledger() {
        let state = provider_state_from_config(config()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let mut request = chat_request(&state);
        request.session_id = open.session.session_id.clone();
        let chat = provider_chat(State(state.clone()), HeaderMap::new(), Json(request))
            .await
            .unwrap()
            .0;
        let close_request = session_close_request(&state, open.session.session_id.clone());
        let closed = provider_close_session(
            State(state.clone()),
            HeaderMap::new(),
            Path(open.session.session_id.clone()),
            Json(close_request),
        )
        .await
        .unwrap()
        .0;

        let summary = provider_get_session_summary(
            State(state),
            HeaderMap::new(),
            Path(open.session.session_id.clone()),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(summary.session_id, open.session.session_id);
        assert_eq!(summary.provider_id, closed.session.provider_id);
        assert_eq!(summary.consumer_id, closed.session.consumer_id);
        assert_eq!(summary.model_id, closed.session.model_id);
        assert_eq!(summary.total_jobs, 1);
        assert_eq!(summary.total_input_tokens, chat.receipt.usage.input_tokens);
        assert_eq!(
            summary.total_output_tokens,
            chat.receipt.usage.output_tokens
        );
        assert_eq!(summary.total_cost, chat.receipt.cost);
        assert_eq!(
            summary.final_debt,
            closed.session.current_ledger_state.current_debt
        );
        assert_eq!(summary.receipt_ids, vec![chat.receipt.receipt_id]);
        assert!(summary.ledger_event_count >= 3);
        assert_eq!(summary.closed_at, closed.ledger_event.created_at);
        assert!(summary.total_forgiven >= 0.0);
        assert!(summary.signature.is_some());
    }

    #[tokio::test]
    async fn provider_model_start_requires_session_when_policy_requires_it() {
        let mut config = config();
        config.initial_model_state = Some(ModelLifecycleStateKind::AvailableCold);
        let state = provider_state_from_config(config).unwrap();
        let request = model_start_request(&state, None);

        let error = provider_start_model(
            State(state.clone()),
            HeaderMap::new(),
            Path(state.offer.model_id.clone()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "model_start_requires_session");
    }

    #[tokio::test]
    async fn provider_model_start_transitions_cold_model_to_ready_and_persists() {
        let mut config = config();
        config.initial_model_state = Some(ModelLifecycleStateKind::AvailableCold);
        let state = provider_state_from_config(config.clone()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let request = model_start_request(&state, Some(open.session.session_id));

        let status = provider_start_model(
            State(state),
            HeaderMap::new(),
            Path(config.model_id.clone()),
            Json(request),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(status.state, ModelLifecycleStateKind::Ready);
        assert!(status.last_started_at.is_some());
        assert!(status.last_warmed_at.is_some());

        let reloaded = provider_state_from_config(config).unwrap();
        let status = model_status(&reloaded).unwrap();
        assert_eq!(status.state, ModelLifecycleStateKind::Ready);
        assert_eq!(status.estimated_cold_start_seconds, Some(0));
    }

    #[tokio::test]
    async fn provider_model_start_records_failed_managed_backend_start() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;
        config.backend_base_url = Some("http://127.0.0.1:8000/v1/".to_string());
        config.backend_start_command =
            Some("hivemind-missing-managed-backend-command-for-test".to_string());
        let state = provider_state_from_config(config.clone()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let request = model_start_request(&state, Some(open.session.session_id));

        let error = provider_start_model(
            State(state.clone()),
            HeaderMap::new(),
            Path(config.model_id),
            Json(request),
        )
        .await
        .unwrap_err();
        let status = model_status(&state).unwrap();

        assert_eq!(error.code, "backend_start_failed");
        assert_eq!(status.state, ModelLifecycleStateKind::Failed);
        assert!(status.last_error.unwrap().contains("failed to start"));
    }

    #[tokio::test]
    async fn provider_model_stop_rejects_unmanaged_backend() {
        let state = provider_state_from_config(config()).unwrap();
        let request = model_stop_request(&state, None);

        let error = provider_stop_model(
            State(state.clone()),
            HeaderMap::new(),
            Path(state.offer.model_id.clone()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "model_stop_not_managed");
    }

    #[tokio::test]
    async fn provider_model_stop_refuses_active_jobs() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;
        config.backend_base_url = Some("http://127.0.0.1:8000/v1/".to_string());
        config.backend_start_command = Some("hivemind-test-managed-backend".to_string());
        config.initial_model_state = Some(ModelLifecycleStateKind::Ready);
        let state = provider_state_from_config(config).unwrap();
        let _permit = acquire_job_permit(&state).unwrap();
        let request = model_stop_request(&state, None);

        let error = provider_stop_model(
            State(state.clone()),
            HeaderMap::new(),
            Path(state.offer.model_id.clone()),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "model_stop_busy");
        assert_eq!(
            model_status(&state).unwrap().state,
            ModelLifecycleStateKind::Busy
        );
    }

    #[tokio::test]
    async fn provider_model_stop_marks_managed_model_cold_and_persists() {
        let mut config = config();
        config.backend_type = ModelBackendType::OpenAiCompatibleHttp;
        config.backend_base_url = Some("http://127.0.0.1:8000/v1/".to_string());
        config.backend_start_command = Some("hivemind-test-managed-backend".to_string());
        config.initial_model_state = Some(ModelLifecycleStateKind::Ready);
        let state = provider_state_from_config(config.clone()).unwrap();
        assert!(
            state
                .offer
                .supported_features
                .contains(&ModelBackendFeature::ModelUnload)
        );
        let request = model_stop_request(&state, None);

        let status = provider_stop_model(
            State(state),
            HeaderMap::new(),
            Path(config.model_id.clone()),
            Json(request),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(status.state, ModelLifecycleStateKind::AvailableCold);
        assert_eq!(status.estimated_cold_start_seconds, Some(1));

        let reloaded = provider_state_from_config(config).unwrap();
        let status = model_status(&reloaded).unwrap();
        assert_eq!(status.state, ModelLifecycleStateKind::AvailableCold);
    }

    #[tokio::test]
    async fn provider_chat_rejects_cold_model_before_start() {
        let mut config = config();
        config.initial_model_state = Some(ModelLifecycleStateKind::AvailableCold);
        let state = provider_state_from_config(config).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let mut request = chat_request(&state);
        request.session_id = open.session.session_id;

        let error = provider_chat(State(state), HeaderMap::new(), Json(request))
            .await
            .unwrap_err();

        assert_eq!(error.code, "model_not_started");
    }

    #[tokio::test]
    async fn provider_model_start_enforces_hourly_start_cap() {
        let mut config = config();
        config.initial_model_state = Some(ModelLifecycleStateKind::AvailableCold);
        config.max_model_starts_per_hour = 1;
        let state = provider_state_from_config(config.clone()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let request = model_start_request(&state, Some(open.session.session_id.clone()));
        let _ = provider_start_model(
            State(state.clone()),
            HeaderMap::new(),
            Path(config.model_id.clone()),
            Json(request),
        )
        .await
        .unwrap();

        {
            let mut lifecycle = lock_model_lifecycle(&state).unwrap();
            lifecycle.state = ModelLifecycleStateKind::AvailableCold;
        }
        let request = model_start_request(&state, Some(open.session.session_id));
        let error = provider_start_model(
            State(state),
            HeaderMap::new(),
            Path(config.model_id),
            Json(request),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "model_start_rate_limited");
    }

    #[test]
    fn openai_request_body_disables_backend_streaming_for_provider_receipts() {
        let request = ProviderChatRequestV1 {
            schema_version: hivemind_core::PROVIDER_CHAT_REQUEST_SCHEMA_VERSION.to_string(),
            job_id: "job-1".to_string(),
            session_id: "session-1".to_string(),
            provider_id: "provider-local".to_string(),
            consumer_id: "consumer-1".to_string(),
            model_id: "mock-chat".to_string(),
            messages: vec![json!({ "role": "user", "content": "hello there" })],
            stream: true,
            max_output_tokens: 100,
            temperature: Some(0.2),
            tool_policy: None,
            request_envelope: None,
            created_at: Utc::now(),
        };

        let body = openai_chat_request_body(&request, "backend-model");
        assert_eq!(body["model"], "backend-model");
        assert_eq!(body["stream"], false);
        assert_eq!(body["max_tokens"], 100);
        assert_eq!(body["temperature"], 0.2);
    }

    #[test]
    fn openai_response_usage_maps_to_provider_usage() {
        let request = ProviderChatRequestV1 {
            schema_version: hivemind_core::PROVIDER_CHAT_REQUEST_SCHEMA_VERSION.to_string(),
            job_id: "job-1".to_string(),
            session_id: "session-1".to_string(),
            provider_id: "provider-local".to_string(),
            consumer_id: "consumer-1".to_string(),
            model_id: "mock-chat".to_string(),
            messages: vec![json!({ "role": "user", "content": "hello there" })],
            stream: false,
            max_output_tokens: 100,
            temperature: None,
            tool_policy: None,
            request_envelope: None,
            created_at: Utc::now(),
        };
        let response = json!({
            "choices": [
                { "message": { "role": "assistant", "content": "hello consumer" } }
            ],
            "usage": {
                "prompt_tokens": 7,
                "completion_tokens": 11,
                "total_tokens": 18
            }
        });

        let output = openai_chat_output_from_value(&request, response, 0.5).unwrap();
        assert_eq!(output.text, "hello consumer");
        assert_eq!(output.backend_type, ModelBackendType::OpenAiCompatibleHttp);
        assert_eq!(output.usage.input_tokens, 7);
        assert_eq!(output.usage.output_tokens, 11);
        assert_eq!(
            output.usage.usage_confidence,
            UsageConfidence::BackendReported
        );
    }

    #[tokio::test]
    async fn provider_sessions_persist_and_reload() {
        let config = config();
        let state_path = config.state_path.clone();
        let state = provider_state_from_config(config.clone()).unwrap();
        let request = session_open_request(&state);

        let response = provider_open_session(State(state), HeaderMap::new(), Json(request))
            .await
            .unwrap()
            .0;

        let reloaded = provider_state_from_config(config).unwrap();
        assert!(state_path.exists());
        let sessions = lock_sessions(&reloaded).unwrap();
        assert!(sessions.contains_key(&response.session.session_id));
        assert_eq!(
            sessions[&response.session.session_id].ledger[0].event_type,
            PseudoLedgerEventType::SessionOpened
        );
    }

    #[tokio::test]
    async fn provider_chat_stores_receipt_for_lookup() {
        let state = provider_state_from_config(config()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let mut request = chat_request(&state);
        request.session_id = open.session.session_id;

        let chat = provider_chat(State(state.clone()), HeaderMap::new(), Json(request))
            .await
            .unwrap()
            .0;
        let receipt = provider_get_receipt(
            State(state),
            HeaderMap::new(),
            Path(chat.receipt.receipt_id.clone()),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(receipt.receipt_id, chat.receipt.receipt_id);
        assert_eq!(receipt.job_id, chat.job_id);
        assert_eq!(receipt.ledger_event_ids, chat.receipt.ledger_event_ids);
    }

    #[tokio::test]
    async fn provider_receipts_persist_and_reload() {
        let config = config();
        let state = provider_state_from_config(config.clone()).unwrap();
        let open = provider_open_session(
            State(state.clone()),
            HeaderMap::new(),
            Json(session_open_request(&state)),
        )
        .await
        .unwrap()
        .0;
        let mut request = chat_request(&state);
        request.session_id = open.session.session_id;

        let chat = provider_chat(State(state), HeaderMap::new(), Json(request))
            .await
            .unwrap()
            .0;

        let reloaded = provider_state_from_config(config).unwrap();
        let receipts = lock_receipts(&reloaded).unwrap();
        let receipt = receipts.get(&chat.receipt.receipt_id).unwrap();
        assert_eq!(receipt.receipt_id, chat.receipt.receipt_id);
        assert_eq!(receipt.session_id, chat.receipt.session_id);
        assert_eq!(receipt.consumer_id, "consumer-1");
    }
}
