use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use hivemind_core::{
    IntegrityTier, ModelLifecycleStateKind, ModelLifecycleStateV1, PrivacyTier, ProviderAuthMode,
    ProviderChatReceiptV1, ProviderChatRequestV1, ProviderHealthV1, ProviderIdentityV1,
    ProviderJobCancelRequestV1, ProviderJobCancelResponseV1, ProviderModelOfferV1,
    ProviderModelStartRequestV1, ProviderPaymentMode, ProviderQuoteRequestV1, ProviderQuoteV1,
    ProviderSecurityMode, ProviderSessionCloseRequestV1, ProviderSessionOpenRequestV1,
    ProviderSessionSummaryV1, ProviderSessionV1, ProviderStreamEventType, ProviderStreamEventV1,
    PseudoLedgerEventV1, PseudoPaymentPolicyV1, PseudoPaymentStateV1, SignedRequestEnvelopeV1,
    hash_canonical_json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const CONSUMER_SESSION_STATE_SCHEMA_VERSION: &str = "hivemind.provider_consumer.local_session.v1";
const LEDGER_DEBT_EPSILON: f64 = 0.000_001;

#[derive(Debug, Clone)]
pub struct ProviderChatConfig {
    pub provider_url: String,
    pub bearer_token: Option<String>,
    pub consumer_id: String,
    pub model_id: Option<String>,
    pub message: Option<String>,
    pub expected_max_input_tokens: u64,
    pub expected_max_output_tokens: u64,
    pub max_output_tokens: u64,
    pub spending_cap: Option<f64>,
    pub receipts_dir: PathBuf,
    pub session_state_dir: PathBuf,
    pub session_summaries_dir: PathBuf,
    pub resume_session_id: Option<String>,
    pub cancel_job_id: Option<String>,
    pub sign_requests: bool,
    pub show_events: bool,
    pub close_session: bool,
}

#[derive(Debug, Clone)]
pub struct ProviderCheckConfig {
    pub provider_url: String,
    pub bearer_token: Option<String>,
    pub model_id: Option<String>,
    pub json: bool,
}

#[derive(Debug, Deserialize)]
struct ProviderCapabilitiesResponse {
    identity: ProviderIdentityV1,
    offers: Vec<ProviderModelOfferV1>,
    #[serde(rename = "securityMode")]
    security_mode: hivemind_core::ProviderSecurityMode,
    #[serde(rename = "authModes")]
    auth_modes: Vec<ProviderAuthMode>,
}

#[derive(Debug, Deserialize)]
struct ProviderSessionOpenResponse {
    session: ProviderSessionV1,
    #[serde(rename = "ledgerEvent")]
    ledger_event: PseudoLedgerEventV1,
}

#[derive(Debug, Deserialize)]
struct ProviderSessionCloseResponse {
    session: ProviderSessionV1,
    #[serde(rename = "ledgerEvent")]
    ledger_event: PseudoLedgerEventV1,
}

#[derive(Debug, Deserialize)]
struct ProviderLedgerResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    state: PseudoPaymentStateV1,
    events: Vec<PseudoLedgerEventV1>,
}

#[derive(Debug, Deserialize)]
struct ProviderChatResponse {
    text: String,
    #[serde(rename = "streamEvents")]
    stream_events: Vec<ProviderStreamEventV1>,
    receipt: ProviderChatReceiptV1,
    #[serde(rename = "ledgerEvents")]
    ledger_events: Vec<PseudoLedgerEventV1>,
    #[serde(rename = "ledgerState")]
    ledger_state: PseudoPaymentStateV1,
}

#[derive(Debug, Clone, PartialEq)]
struct RenderedProviderAnswer {
    text: String,
    token_deltas: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderCheckReport {
    provider_url: String,
    health: ProviderHealthV1,
    identity: ProviderIdentityV1,
    #[serde(rename = "selectedOffer")]
    selected_offer: ProviderModelOfferV1,
    #[serde(rename = "modelStatus")]
    model_status: ModelLifecycleStateV1,
    warnings: Vec<String>,
}

struct ProviderChatSession {
    provider_url: String,
    client: reqwest::Client,
    bearer_token: Option<String>,
    health: ProviderHealthV1,
    capabilities: ProviderCapabilitiesResponse,
    offer: ProviderModelOfferV1,
    model_status: ModelLifecycleStateV1,
    quote: Option<ProviderQuoteV1>,
    session: ProviderSessionV1,
    local_state: ConsumerProviderSessionState,
    conversation: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsumerProviderSessionState {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "providerUrl")]
    provider_url: String,
    #[serde(rename = "providerId")]
    provider_id: String,
    #[serde(rename = "consumerId")]
    consumer_id: String,
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "quoteId")]
    quote_id: String,
    #[serde(rename = "modelId")]
    model_id: String,
    #[serde(rename = "paymentPolicyHash")]
    payment_policy_hash: String,
    #[serde(rename = "currentDebt")]
    current_debt: f64,
    #[serde(rename = "lastLedgerSequence")]
    last_ledger_sequence: u64,
    #[serde(rename = "receiptIds", default)]
    receipt_ids: Vec<String>,
    #[serde(
        rename = "sessionSummaryId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    session_summary_id: Option<String>,
    #[serde(
        rename = "sessionSummaryPath",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    session_summary_path: Option<String>,
    #[serde(rename = "closedAt", default, skip_serializing_if = "Option::is_none")]
    closed_at: Option<DateTime<Utc>>,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: DateTime<Utc>,
}

pub async fn check(config: ProviderCheckConfig) -> Result<()> {
    let provider_url = normalize_provider_url(&config.provider_url)?;
    let client = reqwest::Client::new();
    let health: ProviderHealthV1 = get_json(
        &client,
        config.bearer_token.as_deref(),
        &format!("{provider_url}/v1/provider/health"),
    )
    .await
    .context("failed to fetch provider health")?;
    let capabilities: ProviderCapabilitiesResponse = get_json(
        &client,
        config.bearer_token.as_deref(),
        &format!("{provider_url}/v1/provider/capabilities"),
    )
    .await
    .context("failed to fetch provider capabilities")?;
    let offer = select_offer(&capabilities.offers, config.model_id.as_deref())?;
    let model_status = fetch_provider_model_status(
        &client,
        config.bearer_token.as_deref(),
        &provider_url,
        &offer,
    )
    .await?;
    let report = provider_check_report(provider_url, health, &capabilities, offer, model_status);
    if config.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_provider_check_report(&report);
    }
    Ok(())
}

pub async fn chat(config: ProviderChatConfig) -> Result<()> {
    validate_provider_chat_config(&config)?;
    let mut session = open_provider_chat_session(&config).await?;
    print_session_summary(&session);

    if let Some(job_id) = config.cancel_job_id.as_deref() {
        cancel_provider_job(&mut session, &config, job_id).await?;
        return Ok(());
    }

    if let Some(message) = config.message.as_deref() {
        send_chat_turn(&mut session, &config, message).await?;
        if config.close_session {
            close_provider_chat_session(&mut session, &config).await?;
        }
        return Ok(());
    }

    println!("Type a message and press Enter. Empty input exits.");
    loop {
        print!("consumer> ");
        io::stdout().flush().context("failed to flush stdout")?;
        let mut line = String::new();
        let read = io::stdin()
            .read_line(&mut line)
            .context("failed to read stdin")?;
        if read == 0 {
            break;
        }
        let message = line.trim();
        if message.is_empty() {
            break;
        }
        send_chat_turn(&mut session, &config, message).await?;
    }

    if config.close_session {
        close_provider_chat_session(&mut session, &config).await?;
    }
    Ok(())
}

fn validate_provider_chat_config(config: &ProviderChatConfig) -> Result<()> {
    if config.cancel_job_id.is_some() {
        if config.resume_session_id.is_none() {
            bail!(
                "--cancel-job-id requires --resume-session-id so the consumer can bind the request to an existing provider session"
            );
        }
        if config.message.is_some() {
            bail!("--cancel-job-id cannot be combined with --message");
        }
        if config.close_session {
            bail!("--cancel-job-id cannot be combined with --close-session");
        }
    }
    Ok(())
}

fn provider_check_report(
    provider_url: String,
    health: ProviderHealthV1,
    capabilities: &ProviderCapabilitiesResponse,
    selected_offer: ProviderModelOfferV1,
    model_status: ModelLifecycleStateV1,
) -> ProviderCheckReport {
    let warnings = consumer_warning_lines_for(
        &provider_url,
        &capabilities.security_mode,
        &capabilities.auth_modes,
        &selected_offer.privacy_tier,
        &model_status.state,
    );
    ProviderCheckReport {
        provider_url,
        health,
        identity: capabilities.identity.clone(),
        selected_offer,
        model_status,
        warnings,
    }
}

fn print_provider_check_report(report: &ProviderCheckReport) {
    println!("{}", provider_check_text(report));
}

fn provider_check_text(report: &ProviderCheckReport) -> String {
    let offer = &report.selected_offer;
    let model_status = &report.model_status;
    let mut lines = Vec::new();
    lines.push(format!(
        "Provider: {} ({})",
        report.identity.display_name, report.identity.provider_id
    ));
    lines.push(format!("URL: {}", report.provider_url));
    lines.push(format!(
        "Status: {:?}, uptime {}s, version {}",
        report.health.status, report.health.uptime_seconds, report.health.version
    ));
    lines.push(format!(
        "Security: {:?}, auth {:?}",
        report.health.security_mode, report.health.auth_modes
    ));
    lines.push(format!(
        "Sessions/jobs: active sessions {}, active jobs {}",
        report.health.active_sessions, report.health.active_jobs
    ));
    lines.push(format!(
        "Model: {} ({})",
        offer.model_id, offer.display_name
    ));
    lines.push(format!(
        "Backend: {:?} model {}",
        offer.backend_type, offer.backend_model_id
    ));
    lines.push(format!(
        "Model state: {:?}, backend health {}, concurrency {}/{}",
        model_status.state,
        model_status.backend_health,
        model_status.current_concurrency,
        model_status.max_concurrency
    ));
    if let Some(last_error) = &model_status.last_error {
        lines.push(format!("Last model error: {last_error}"));
    }
    lines.push(format!(
        "Limits: context {} tokens, output {} tokens, sessions {}, jobs {}",
        offer.max_context_tokens,
        offer.max_output_tokens,
        offer.max_concurrent_sessions,
        offer.max_concurrent_jobs
    ));
    lines.push(format!(
        "Readiness: {:?}, privacy {:?}, integrity {:?}",
        offer.readiness_label, offer.privacy_tier, offer.verification_tier
    ));
    if let Some(policy) = &offer.pseudopayment_policy {
        lines.push(format!(
            "Pseudopay: max debt {:.6}, forgiveness {:.6}/sec",
            policy.max_debt, policy.forgiveness_per_second
        ));
        lines.push(pseudo_payment_price_line(policy));
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines.join("\n")
}

async fn open_provider_chat_session(config: &ProviderChatConfig) -> Result<ProviderChatSession> {
    if config.consumer_id.trim().is_empty() {
        bail!("consumer id is required");
    }
    let provider_url = normalize_provider_url(&config.provider_url)?;
    let client = reqwest::Client::new();
    let health: ProviderHealthV1 = get_json(
        &client,
        config.bearer_token.as_deref(),
        &format!("{provider_url}/v1/provider/health"),
    )
    .await
    .context("failed to fetch provider health")?;
    let capabilities: ProviderCapabilitiesResponse = get_json(
        &client,
        config.bearer_token.as_deref(),
        &format!("{provider_url}/v1/provider/capabilities"),
    )
    .await
    .context("failed to fetch provider capabilities")?;

    if let Some(session_id) = config.resume_session_id.as_deref() {
        return resume_provider_chat_session(
            config,
            provider_url,
            client,
            health,
            capabilities,
            session_id,
            config.cancel_job_id.is_none(),
        )
        .await;
    }

    let offer = select_offer(&capabilities.offers, config.model_id.as_deref())?;
    let quote = request_quote(
        &client,
        config.bearer_token.as_deref(),
        &provider_url,
        &health.provider_id,
        &config.consumer_id,
        &offer,
        config,
    )
    .await?;
    let session = open_session(
        &client,
        config.bearer_token.as_deref(),
        &provider_url,
        &health.provider_id,
        &config.consumer_id,
        &quote,
        config
            .spending_cap
            .unwrap_or(quote.pseudopayment_policy.max_debt),
        config.sign_requests,
    )
    .await?;
    let model_status = ensure_provider_model_started(
        &client,
        config.bearer_token.as_deref(),
        &provider_url,
        &health.provider_id,
        &config.consumer_id,
        &offer,
        &session.session_id,
        config.sign_requests,
    )
    .await?;
    let local_state = local_state_from_session(
        &provider_url,
        &health.provider_id,
        &config.consumer_id,
        &session,
        Vec::new(),
    );
    let state_path = write_consumer_session_state(&config.session_state_dir, &local_state).await?;
    println!("session state: {}", state_path.display());

    Ok(ProviderChatSession {
        provider_url,
        client,
        bearer_token: config.bearer_token.clone(),
        health,
        capabilities,
        offer,
        model_status,
        quote: Some(quote),
        session,
        local_state,
        conversation: Vec::new(),
    })
}

async fn resume_provider_chat_session(
    config: &ProviderChatConfig,
    provider_url: String,
    client: reqwest::Client,
    health: ProviderHealthV1,
    capabilities: ProviderCapabilitiesResponse,
    session_id: &str,
    ensure_model_ready: bool,
) -> Result<ProviderChatSession> {
    let session_id = session_id.trim();
    if session_id.is_empty() {
        bail!("resume session id is required");
    }
    let mut session: ProviderSessionV1 = get_json(
        &client,
        config.bearer_token.as_deref(),
        &format!("{provider_url}/v1/provider/sessions/{session_id}"),
    )
    .await
    .with_context(|| format!("failed to resume provider session {session_id}"))?;
    if session.provider_id != health.provider_id {
        bail!(
            "provider returned session for provider {}, but health reported {}",
            session.provider_id,
            health.provider_id
        );
    }
    if session.consumer_id != config.consumer_id {
        bail!(
            "session {} belongs to consumer {}, not {}",
            session.session_id,
            session.consumer_id,
            config.consumer_id
        );
    }
    if let Some(model_id) = config.model_id.as_deref()
        && model_id != session.model_id
    {
        bail!(
            "resume session model {} does not match requested model {}",
            session.model_id,
            model_id
        );
    }
    let ledger = fetch_provider_ledger(
        &client,
        config.bearer_token.as_deref(),
        &provider_url,
        &session.session_id,
    )
    .await?;
    validate_provider_ledger_response(&ledger, &session)?;
    session.current_ledger_state = ledger.state.clone();
    let offer = select_offer(&capabilities.offers, Some(&session.model_id))?;
    let loaded_local_state =
        read_consumer_session_state(&config.session_state_dir, &session.session_id).await?;
    let had_local_state = loaded_local_state.is_some();
    let local_state = loaded_local_state.unwrap_or_else(|| {
        local_state_from_session(
            &provider_url,
            &health.provider_id,
            &config.consumer_id,
            &session,
            Vec::new(),
        )
    });
    validate_resume_local_state(&local_state, &provider_url, &health.provider_id, &session)?;
    if had_local_state {
        for warning in reconcile_resume_ledger_state(&local_state, &ledger)? {
            println!("warning: {warning}");
        }
    }
    let mut local_state = local_state;
    local_state.current_debt = session.current_ledger_state.current_debt;
    local_state.last_ledger_sequence = session.current_ledger_state.last_event_sequence;
    local_state.updated_at = Utc::now();
    let state_path = write_consumer_session_state(&config.session_state_dir, &local_state).await?;
    println!("resumed session state: {}", state_path.display());
    let model_status = if ensure_model_ready {
        ensure_provider_model_started(
            &client,
            config.bearer_token.as_deref(),
            &provider_url,
            &health.provider_id,
            &config.consumer_id,
            &offer,
            &session.session_id,
            config.sign_requests,
        )
        .await?
    } else {
        fetch_provider_model_status(
            &client,
            config.bearer_token.as_deref(),
            &provider_url,
            &offer,
        )
        .await?
    };

    Ok(ProviderChatSession {
        provider_url,
        client,
        bearer_token: config.bearer_token.clone(),
        health,
        capabilities,
        offer,
        model_status,
        quote: None,
        session,
        local_state,
        conversation: Vec::new(),
    })
}

async fn fetch_provider_model_status(
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    provider_url: &str,
    offer: &ProviderModelOfferV1,
) -> Result<ModelLifecycleStateV1> {
    let status_url = format!(
        "{provider_url}/v1/provider/models/{}/status",
        offer.model_id
    );
    get_json(client, bearer_token, &status_url)
        .await
        .context("failed to fetch provider model status")
}

async fn ensure_provider_model_started(
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    provider_url: &str,
    provider_id: &str,
    consumer_id: &str,
    offer: &ProviderModelOfferV1,
    session_id: &str,
    sign_request: bool,
) -> Result<ModelLifecycleStateV1> {
    let status = fetch_provider_model_status(client, bearer_token, provider_url, offer).await?;
    if model_accepts_chat(&status.state) {
        return Ok(status);
    }
    if matches!(
        status.state,
        ModelLifecycleStateKind::Disabled | ModelLifecycleStateKind::Unavailable
    ) {
        bail!(
            "provider model {} is {:?}: {}",
            offer.model_id,
            status.state,
            status.backend_health
        );
    }
    if !offer.cold_start_policy.allow_consumer_triggered_start {
        bail!(
            "provider model {} is {:?} and does not allow consumer-triggered start",
            offer.model_id,
            status.state
        );
    }

    let mut request = ProviderModelStartRequestV1 {
        schema_version: hivemind_core::PROVIDER_MODEL_START_REQUEST_SCHEMA_VERSION.to_string(),
        request_id: format!("provider-model-start-{}", Uuid::new_v4()),
        provider_id: provider_id.to_string(),
        consumer_id: consumer_id.to_string(),
        model_id: offer.model_id.clone(),
        session_id: Some(session_id.to_string()),
        request_envelope: None,
        created_at: Utc::now(),
        signature: None,
    };
    let start_path = format!("/v1/provider/models/{}/start", offer.model_id);
    if sign_request {
        request.request_envelope = Some(signed_request_envelope(
            &request,
            "POST",
            &start_path,
            provider_id,
            consumer_id,
            Some(session_id),
            None,
        )?);
    }
    let started: ModelLifecycleStateV1 = post_json(
        client,
        bearer_token,
        &format!("{provider_url}{start_path}"),
        &request,
    )
    .await
    .context("failed to start provider model")?;
    println!("model start: {:?}", started.state);
    if !model_accepts_chat(&started.state) {
        bail!(
            "provider model {} is {:?} after start attempt",
            offer.model_id,
            started.state
        );
    }
    Ok(started)
}

fn model_accepts_chat(state: &ModelLifecycleStateKind) -> bool {
    matches!(state, ModelLifecycleStateKind::Ready)
}

async fn request_quote(
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    provider_url: &str,
    provider_id: &str,
    consumer_id: &str,
    offer: &ProviderModelOfferV1,
    config: &ProviderChatConfig,
) -> Result<ProviderQuoteV1> {
    let mut request = ProviderQuoteRequestV1 {
        schema_version: hivemind_core::PROVIDER_QUOTE_REQUEST_SCHEMA_VERSION.to_string(),
        request_id: format!("provider-quote-request-{}", Uuid::new_v4()),
        consumer_id: consumer_id.to_string(),
        provider_id: provider_id.to_string(),
        model_id: offer.model_id.clone(),
        task: "chat".to_string(),
        expected_max_input_tokens: config.expected_max_input_tokens,
        expected_max_output_tokens: config.expected_max_output_tokens,
        streaming: true,
        requested_privacy_tier: PrivacyTier::Standard,
        requested_verification_tier: IntegrityTier::ReceiptOnly,
        payment_mode: ProviderPaymentMode::PseudopaymentDebtForgiveness,
        request_envelope: None,
        created_at: Utc::now(),
        signature: None,
    };
    if config.sign_requests {
        request.request_envelope = Some(signed_request_envelope(
            &request,
            "POST",
            "/v1/provider/quote",
            provider_id,
            consumer_id,
            None,
            None,
        )?);
    }
    post_json(
        client,
        bearer_token,
        &format!("{provider_url}/v1/provider/quote"),
        &request,
    )
    .await
    .context("failed to request provider quote")
}

async fn open_session(
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    provider_url: &str,
    provider_id: &str,
    consumer_id: &str,
    quote: &ProviderQuoteV1,
    spending_cap: f64,
    sign_request: bool,
) -> Result<ProviderSessionV1> {
    let policy_value = serde_json::to_value(&quote.pseudopayment_policy)
        .context("failed to serialize pseudopayment policy")?;
    let mut request = ProviderSessionOpenRequestV1 {
        schema_version: hivemind_core::PROVIDER_SESSION_OPEN_REQUEST_SCHEMA_VERSION.to_string(),
        request_id: format!("provider-session-open-{}", Uuid::new_v4()),
        quote_id: quote.quote_id.clone(),
        consumer_id: consumer_id.to_string(),
        provider_id: provider_id.to_string(),
        accepted_policy_hash: hash_canonical_json(&policy_value),
        spending_cap,
        requested_expires_at: Utc::now() + Duration::minutes(30),
        auth_proof: None,
        request_envelope: None,
        signature: None,
    };
    if sign_request {
        request.request_envelope = Some(signed_request_envelope(
            &request,
            "POST",
            "/v1/provider/sessions",
            provider_id,
            consumer_id,
            None,
            Some(&quote.quote_id),
        )?);
    }
    let response: ProviderSessionOpenResponse = post_json(
        client,
        bearer_token,
        &format!("{provider_url}/v1/provider/sessions"),
        &request,
    )
    .await
    .context("failed to open provider session")?;
    println!("ledger opened: {}", response.ledger_event.event_id);
    Ok(response.session)
}

async fn send_chat_turn(
    session: &mut ProviderChatSession,
    config: &ProviderChatConfig,
    message: &str,
) -> Result<()> {
    session
        .conversation
        .push(json!({ "role": "user", "content": message }));
    let mut request = ProviderChatRequestV1 {
        schema_version: hivemind_core::PROVIDER_CHAT_REQUEST_SCHEMA_VERSION.to_string(),
        job_id: format!("provider-chat-job-{}", Uuid::new_v4()),
        session_id: session.session.session_id.clone(),
        provider_id: session.health.provider_id.clone(),
        consumer_id: config.consumer_id.clone(),
        model_id: session.offer.model_id.clone(),
        messages: session.conversation.clone(),
        stream: true,
        max_output_tokens: config.max_output_tokens,
        temperature: None,
        tool_policy: None,
        request_envelope: None,
        created_at: Utc::now(),
    };
    if config.sign_requests {
        request.request_envelope = Some(signed_request_envelope(
            &request,
            "POST",
            "/v1/provider/chat",
            &session.health.provider_id,
            &config.consumer_id,
            Some(&session.session.session_id),
            None,
        )?);
    }
    let response: ProviderChatResponse = post_json(
        &session.client,
        session.bearer_token.as_deref(),
        &format!("{}/v1/provider/chat", session.provider_url),
        &request,
    )
    .await
    .context("failed to send provider chat turn")?;

    let rendered_answer = render_provider_answer(&response)?;
    print_provider_answer(&rendered_answer)?;
    if config.show_events {
        for event in &response.stream_events {
            println!("event {}: {:?}", event.sequence, event.event_type);
        }
    }
    println!(
        "{}",
        payment_state_line(&response.ledger_state, Some(response.ledger_events.len()))
    );
    write_receipt(&config.receipts_dir, &response.receipt).await?;
    session.session.current_ledger_state = response.ledger_state.clone();
    session.local_state.current_debt = response.ledger_state.current_debt;
    session.local_state.last_ledger_sequence = response.ledger_state.last_event_sequence;
    session
        .local_state
        .receipt_ids
        .push(response.receipt.receipt_id.clone());
    session.local_state.updated_at = Utc::now();
    let state_path =
        write_consumer_session_state(&config.session_state_dir, &session.local_state).await?;
    println!("session state: {}", state_path.display());
    session
        .conversation
        .push(json!({ "role": "assistant", "content": rendered_answer.text }));
    Ok(())
}

fn print_provider_answer(answer: &RenderedProviderAnswer) -> Result<()> {
    print!("provider> ");
    if answer.token_deltas.is_empty() {
        println!("{}", answer.text);
        return Ok(());
    }
    for delta in &answer.token_deltas {
        print!("{delta}");
        io::stdout().flush().context("failed to flush stdout")?;
    }
    println!();
    Ok(())
}

fn render_provider_answer(response: &ProviderChatResponse) -> Result<RenderedProviderAnswer> {
    if response.stream_events.is_empty() {
        return Ok(RenderedProviderAnswer {
            text: response.text.clone(),
            token_deltas: Vec::new(),
        });
    }

    let mut events = response.stream_events.iter().collect::<Vec<_>>();
    events.sort_by_key(|event| event.sequence);
    let mut previous_sequence = None;
    let mut token_deltas = Vec::new();
    let mut saw_finished = false;
    for event in events {
        if previous_sequence == Some(event.sequence) {
            bail!("provider stream repeated sequence {}", event.sequence);
        }
        previous_sequence = Some(event.sequence);
        match &event.event_type {
            ProviderStreamEventType::TokenDelta => {
                let text = event
                    .payload
                    .get("text")
                    .and_then(Value::as_str)
                    .with_context(|| {
                        format!(
                            "provider token_delta event {} is missing text",
                            event.event_id
                        )
                    })?;
                token_deltas.push(text.to_string());
            }
            ProviderStreamEventType::StreamFinished => {
                if let Some(receipt_id) = event.payload.get("receiptId").and_then(Value::as_str)
                    && receipt_id != response.receipt.receipt_id
                {
                    bail!(
                        "provider stream finished with receiptId {receipt_id}, expected {}",
                        response.receipt.receipt_id
                    );
                }
                saw_finished = true;
            }
            ProviderStreamEventType::StreamCancelled => {
                bail!("provider stream was cancelled before a final receipt");
            }
            ProviderStreamEventType::StreamError => {
                bail!("provider stream failed: {}", event.payload);
            }
            _ => {}
        }
    }

    if !saw_finished {
        bail!("provider stream did not include stream_finished");
    }
    let text = if token_deltas.is_empty() {
        response.text.clone()
    } else {
        token_deltas.concat()
    };
    if !response.text.is_empty() && text != response.text {
        bail!("provider token deltas do not match final response text");
    }
    Ok(RenderedProviderAnswer { text, token_deltas })
}

async fn cancel_provider_job(
    session: &mut ProviderChatSession,
    config: &ProviderChatConfig,
    job_id: &str,
) -> Result<()> {
    let request = provider_job_cancel_request(
        &session.health.provider_id,
        &config.consumer_id,
        &session.session.session_id,
        job_id,
        config.sign_requests,
    )?;
    let job_id = request.job_id.clone();
    let response: ProviderJobCancelResponseV1 = post_json(
        &session.client,
        session.bearer_token.as_deref(),
        &format!("{}/v1/provider/jobs/{job_id}/cancel", session.provider_url),
        &request,
    )
    .await
    .with_context(|| format!("failed to cancel provider job {job_id}"))?;

    println!(
        "job cancellation: {} status {:?} accepted {}",
        response.job_id, response.status, response.accepted
    );
    if config.show_events
        && let Some(event) = &response.stream_event
    {
        println!("event {}: {:?}", event.sequence, event.event_type);
    }
    if let Some(ledger_state) = response.ledger_state {
        println!("{}", payment_state_line(&ledger_state, None));
        session.session.current_ledger_state = ledger_state.clone();
        session.local_state.current_debt = ledger_state.current_debt;
        session.local_state.last_ledger_sequence = ledger_state.last_event_sequence;
        session.local_state.updated_at = Utc::now();
        let state_path =
            write_consumer_session_state(&config.session_state_dir, &session.local_state).await?;
        println!("session state: {}", state_path.display());
    }
    Ok(())
}

fn provider_job_cancel_request(
    provider_id: &str,
    consumer_id: &str,
    session_id: &str,
    job_id: &str,
    sign_request: bool,
) -> Result<ProviderJobCancelRequestV1> {
    let job_id = job_id.trim();
    if job_id.is_empty() {
        bail!("cancel job id is required");
    }
    let mut request = ProviderJobCancelRequestV1 {
        schema_version: hivemind_core::PROVIDER_JOB_CANCEL_REQUEST_SCHEMA_VERSION.to_string(),
        request_id: format!("provider-job-cancel-{}", Uuid::new_v4()),
        provider_id: provider_id.to_string(),
        consumer_id: consumer_id.to_string(),
        session_id: session_id.to_string(),
        job_id: job_id.to_string(),
        reason: Some("consumer requested job cancellation".to_string()),
        request_envelope: None,
        created_at: Utc::now(),
        signature: None,
    };
    if sign_request {
        let path = format!("/v1/provider/jobs/{job_id}/cancel");
        request.request_envelope = Some(signed_request_envelope(
            &request,
            "POST",
            &path,
            provider_id,
            consumer_id,
            Some(session_id),
            None,
        )?);
    }
    Ok(request)
}

async fn close_provider_chat_session(
    session: &mut ProviderChatSession,
    config: &ProviderChatConfig,
) -> Result<()> {
    let mut request = ProviderSessionCloseRequestV1 {
        schema_version: hivemind_core::PROVIDER_SESSION_CLOSE_REQUEST_SCHEMA_VERSION.to_string(),
        request_id: format!("provider-session-close-{}", Uuid::new_v4()),
        provider_id: session.health.provider_id.clone(),
        consumer_id: config.consumer_id.clone(),
        session_id: session.session.session_id.clone(),
        reason: Some("consumer requested session close".to_string()),
        request_envelope: None,
        created_at: Utc::now(),
        signature: None,
    };
    if config.sign_requests {
        request.request_envelope = Some(signed_request_envelope(
            &request,
            "POST",
            &format!("/v1/provider/sessions/{}/close", session.session.session_id),
            &session.health.provider_id,
            &config.consumer_id,
            Some(&session.session.session_id),
            None,
        )?);
    }
    let response: ProviderSessionCloseResponse = post_json(
        &session.client,
        session.bearer_token.as_deref(),
        &format!(
            "{}/v1/provider/sessions/{}/close",
            session.provider_url, session.session.session_id
        ),
        &request,
    )
    .await
    .context("failed to close provider session")?;

    session.session = response.session;
    session.local_state.current_debt = session.session.current_ledger_state.current_debt;
    session.local_state.last_ledger_sequence =
        session.session.current_ledger_state.last_event_sequence;
    session.local_state.updated_at = Utc::now();
    write_consumer_session_state(&config.session_state_dir, &session.local_state).await?;
    let summary = fetch_provider_session_summary(session).await?;
    validate_provider_session_summary(&summary, session)?;
    let summary_path = write_session_summary(&config.session_summaries_dir, &summary).await?;
    session.local_state.session_summary_id = Some(summary.summary_id.clone());
    session.local_state.session_summary_path = Some(summary_path.display().to_string());
    session.local_state.closed_at = Some(summary.closed_at);
    session.local_state.updated_at = Utc::now();
    let state_path =
        write_consumer_session_state(&config.session_state_dir, &session.local_state).await?;
    println!(
        "session closed: {} (ledger {}, debt {:.6})",
        session.session.session_id,
        response.ledger_event.event_id,
        session.session.current_ledger_state.current_debt
    );
    println!("session summary: {}", summary_path.display());
    println!("session state: {}", state_path.display());
    Ok(())
}

async fn fetch_provider_session_summary(
    session: &ProviderChatSession,
) -> Result<ProviderSessionSummaryV1> {
    get_json(
        &session.client,
        session.bearer_token.as_deref(),
        &format!(
            "{}/v1/provider/sessions/{}/summary",
            session.provider_url, session.session.session_id
        ),
    )
    .await
    .context("failed to fetch provider session summary")
}

async fn fetch_provider_ledger(
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    provider_url: &str,
    session_id: &str,
) -> Result<ProviderLedgerResponse> {
    get_json(
        client,
        bearer_token,
        &format!("{provider_url}/v1/provider/ledger/{session_id}"),
    )
    .await
    .context("failed to fetch provider session ledger")
}

fn validate_provider_session_summary(
    summary: &ProviderSessionSummaryV1,
    session: &ProviderChatSession,
) -> Result<()> {
    if summary.provider_id != session.health.provider_id
        || summary.consumer_id != session.local_state.consumer_id
        || summary.session_id != session.session.session_id
        || summary.model_id != session.session.model_id
    {
        bail!("provider session summary identity does not match the closed session");
    }

    let summary_receipts = summary.receipt_ids.iter().collect::<BTreeSet<_>>();
    let local_receipts = session
        .local_state
        .receipt_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if !local_receipts.is_subset(&summary_receipts) {
        bail!("provider session summary is missing locally stored receipt IDs");
    }

    Ok(())
}

fn validate_provider_ledger_response(
    ledger: &ProviderLedgerResponse,
    session: &ProviderSessionV1,
) -> Result<()> {
    if ledger.session_id != session.session_id || ledger.state.session_id != session.session_id {
        bail!("provider ledger session ID does not match the resumed session");
    }
    Ok(())
}

fn print_session_summary(session: &ProviderChatSession) {
    println!("Provider: {}", session.capabilities.identity.display_name);
    println!("Provider ID: {}", session.health.provider_id);
    println!("Security mode: {:?}", session.capabilities.security_mode);
    println!("Auth modes: {:?}", session.capabilities.auth_modes);
    println!("Model: {}", session.offer.model_id);
    println!("Backend: {:?}", session.offer.backend_type);
    println!("Model state: {:?}", session.model_status.state);
    if let Some(quote) = &session.quote {
        println!("Quote: {}", quote.quote_id);
        println!(
            "Pseudopay: max debt {:.6}, forgiveness {:.6}/sec",
            quote.pseudopayment_policy.max_debt, quote.pseudopayment_policy.forgiveness_per_second
        );
        println!("{}", pseudo_payment_price_line(&quote.pseudopayment_policy));
    } else {
        println!("Quote: {} (resumed)", session.session.quote_id);
        println!(
            "Pseudopay: debt {:.6} / {:.6}, forgiveness {:.6}/sec",
            session.session.current_ledger_state.current_debt,
            session.session.current_ledger_state.max_debt,
            session.session.current_ledger_state.forgiveness_per_second
        );
        if let Some(policy) = &session.offer.pseudopayment_policy {
            println!("{}", pseudo_payment_price_line(policy));
        }
    }
    println!("Session: {}", session.session.session_id);
    for warning in consumer_session_warning_lines(session) {
        println!("warning: {warning}");
    }
}

fn payment_state_line(state: &PseudoPaymentStateV1, ledger_events_delta: Option<usize>) -> String {
    let mut line = format!(
        "ledger: debt {:.6} / {:.6}, remaining {:.6}, forgiveness {:.6}/sec, zero in {:.3}s",
        state.current_debt,
        state.max_debt,
        state.remaining_capacity,
        state.forgiveness_per_second,
        state.estimated_seconds_to_zero
    );
    if let Some(events_delta) = ledger_events_delta {
        line.push_str(&format!(", events +{events_delta}"));
    }
    line
}

fn pseudo_payment_price_line(policy: &PseudoPaymentPolicyV1) -> String {
    let unit = &policy.currency_unit;
    let mut line = format!(
        "Price: {:.6} {unit}/input-token, {:.6} {unit}/output-token, {:.6} {unit}/model-second",
        policy.price_per_input_token, policy.price_per_output_token, policy.price_per_model_second
    );
    if let Some(price_per_request) = policy.price_per_request {
        line.push_str(&format!(", {:.6} {unit}/request", price_per_request));
    }
    line
}

fn consumer_session_warning_lines(session: &ProviderChatSession) -> Vec<String> {
    consumer_warning_lines_for(
        &session.provider_url,
        &session.capabilities.security_mode,
        &session.capabilities.auth_modes,
        &session.offer.privacy_tier,
        &session.model_status.state,
    )
}

fn consumer_warning_lines_for(
    provider_url: &str,
    security_mode: &ProviderSecurityMode,
    auth_modes: &[ProviderAuthMode],
    privacy_tier: &PrivacyTier,
    model_state: &ModelLifecycleStateKind,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if provider_url_uses_plain_http(provider_url) && !provider_url_is_loopback(provider_url) {
        warnings.push(
            "provider connection is plain HTTP; use this only on a trusted LAN/test network"
                .to_string(),
        );
    }
    if matches!(security_mode, ProviderSecurityMode::LocalDev) {
        warnings.push("provider is advertising local-dev security mode".to_string());
    }
    if auth_modes.is_empty() || auth_modes.contains(&ProviderAuthMode::None) {
        warnings.push("provider accepts unauthenticated requests for this mode".to_string());
    }
    if matches!(
        privacy_tier,
        PrivacyTier::Public | PrivacyTier::Standard | PrivacyTier::StandardRemote
    ) {
        warnings.push("provider can see prompts and outputs for this privacy tier".to_string());
    }
    if !model_accepts_chat(model_state) {
        warnings.push(format!(
            "model is {:?}; first answer may need a cold start or operator action",
            model_state
        ));
    }
    warnings.push(
        "pseudopayment is local test accounting with debt forgiveness, not real settlement"
            .to_string(),
    );

    warnings
}

fn provider_url_uses_plain_http(provider_url: &str) -> bool {
    reqwest::Url::parse(provider_url)
        .map(|url| url.scheme() == "http")
        .unwrap_or(false)
}

fn provider_url_is_loopback(provider_url: &str) -> bool {
    reqwest::Url::parse(provider_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .map(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host == "::1"
                || host.starts_with("127.")
                || host == "0:0:0:0:0:0:0:1"
        })
        .unwrap_or(false)
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    url: &str,
) -> Result<T> {
    let request = with_optional_bearer(client.get(url), bearer_token);
    let response = request.send().await?;
    parse_response_json(response).await
}

async fn post_json<T: serde::de::DeserializeOwned, B: serde::Serialize + ?Sized>(
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    url: &str,
    body: &B,
) -> Result<T> {
    let request = with_optional_bearer(client.post(url).json(body), bearer_token);
    let response = request.send().await?;
    parse_response_json(response).await
}

async fn parse_response_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("provider returned HTTP {status}: {body}");
    }
    serde_json::from_str(&body)
        .with_context(|| format!("failed to parse provider response: {body}"))
}

fn with_optional_bearer(
    request: reqwest::RequestBuilder,
    bearer_token: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(token) = bearer_token {
        request.bearer_auth(token)
    } else {
        request
    }
}

fn select_offer(
    offers: &[ProviderModelOfferV1],
    model_id: Option<&str>,
) -> Result<ProviderModelOfferV1> {
    if let Some(model_id) = model_id {
        return offers
            .iter()
            .find(|offer| offer.model_id == model_id)
            .cloned()
            .with_context(|| format!("provider does not advertise model {model_id}"));
    }
    offers
        .first()
        .cloned()
        .context("provider did not advertise any model offers")
}

fn normalize_provider_url(provider_url: &str) -> Result<String> {
    let trimmed = provider_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("provider URL is required");
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        bail!("provider URL must start with http:// or https://");
    }
    Ok(trimmed.to_string())
}

fn signed_request_envelope<T: serde::Serialize>(
    request: &T,
    method: &str,
    path: &str,
    provider_id: &str,
    consumer_id: &str,
    session_id: Option<&str>,
    quote_id: Option<&str>,
) -> Result<SignedRequestEnvelopeV1> {
    let body_hash = signed_request_body_hash(request)?;
    let nonce = Uuid::new_v4().to_string();
    let now = Utc::now();
    Ok(SignedRequestEnvelopeV1 {
        schema_version: hivemind_core::SIGNED_REQUEST_ENVELOPE_SCHEMA_VERSION.to_string(),
        envelope_id: format!("signed-provider-request-{nonce}"),
        provider_id: provider_id.to_string(),
        consumer_id: consumer_id.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        body_hash: body_hash.clone(),
        nonce: nonce.clone(),
        issued_at: now,
        expires_at: now + Duration::minutes(5),
        session_id: session_id.map(str::to_string),
        quote_id: quote_id.map(str::to_string),
        signature_scheme: "local-dev-deterministic".to_string(),
        signature: dev_signed_request_signature(consumer_id, &nonce, &body_hash),
    })
}

fn signed_request_body_hash<T: serde::Serialize>(request: &T) -> Result<String> {
    let mut value = serde_json::to_value(request).context("failed to serialize request body")?;
    if let Value::Object(map) = &mut value {
        map.remove("requestEnvelope");
    }
    Ok(hash_canonical_json(&value))
}

fn dev_signed_request_signature(consumer_id: &str, nonce: &str, body_hash: &str) -> String {
    format!("dev-signed-request-envelope-v1:{consumer_id}:{nonce}:{body_hash}")
}

fn local_state_from_session(
    provider_url: &str,
    provider_id: &str,
    consumer_id: &str,
    session: &ProviderSessionV1,
    receipt_ids: Vec<String>,
) -> ConsumerProviderSessionState {
    let now = Utc::now();
    ConsumerProviderSessionState {
        schema_version: CONSUMER_SESSION_STATE_SCHEMA_VERSION.to_string(),
        provider_url: provider_url.to_string(),
        provider_id: provider_id.to_string(),
        consumer_id: consumer_id.to_string(),
        session_id: session.session_id.clone(),
        quote_id: session.quote_id.clone(),
        model_id: session.model_id.clone(),
        payment_policy_hash: session.policy_hash.clone(),
        current_debt: session.current_ledger_state.current_debt,
        last_ledger_sequence: session.current_ledger_state.last_event_sequence,
        receipt_ids,
        session_summary_id: None,
        session_summary_path: None,
        closed_at: None,
        created_at: session.opened_at,
        updated_at: now,
    }
}

fn validate_resume_local_state(
    local_state: &ConsumerProviderSessionState,
    provider_url: &str,
    provider_id: &str,
    session: &ProviderSessionV1,
) -> Result<()> {
    if local_state.schema_version != CONSUMER_SESSION_STATE_SCHEMA_VERSION {
        bail!(
            "local session state uses unsupported schema {}",
            local_state.schema_version
        );
    }
    if local_state.provider_url != provider_url {
        bail!(
            "local session state provider URL {} does not match {}",
            local_state.provider_url,
            provider_url
        );
    }
    if local_state.provider_id != provider_id || local_state.provider_id != session.provider_id {
        bail!("local session state provider identity does not match provider response");
    }
    if local_state.consumer_id != session.consumer_id {
        bail!("local session state consumer identity does not match provider response");
    }
    if local_state.session_id != session.session_id {
        bail!("local session state session ID does not match provider response");
    }
    if local_state.model_id != session.model_id {
        bail!("local session state model ID does not match provider response");
    }
    Ok(())
}

fn reconcile_resume_ledger_state(
    local_state: &ConsumerProviderSessionState,
    ledger: &ProviderLedgerResponse,
) -> Result<Vec<String>> {
    let provider_sequence = ledger.state.last_event_sequence;
    let local_sequence = local_state.last_ledger_sequence;
    if local_sequence > provider_sequence {
        bail!(
            "local session state mismatch: local ledger sequence {local_sequence} is ahead of provider sequence {provider_sequence}; refusing resume. Start a new session without --resume-session-id if the provider state is authoritative"
        );
    }

    let provider_receipts = ledger
        .events
        .iter()
        .filter_map(|event| event.receipt_id.as_deref())
        .collect::<BTreeSet<_>>();
    let missing_receipts = local_state
        .receipt_ids
        .iter()
        .filter(|receipt_id| !provider_receipts.contains(receipt_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_receipts.is_empty() {
        bail!(
            "local session state mismatch: provider ledger is missing local receipt IDs {}; refusing resume. Start a new session instead of trusting divergent local state",
            missing_receipts.join(", ")
        );
    }

    let provider_debt = ledger.state.current_debt;
    let local_debt = local_state.current_debt;
    if local_sequence == provider_sequence && provider_debt > local_debt + LEDGER_DEBT_EPSILON {
        bail!(
            "local session state mismatch: provider reports higher debt {provider_debt:.6} than local debt {local_debt:.6} at ledger sequence {provider_sequence}; refusing resume"
        );
    }

    let mut warnings = Vec::new();
    if local_sequence < provider_sequence {
        warnings.push(format!(
            "provider ledger is ahead of local state (local sequence {local_sequence}, provider sequence {provider_sequence}); adopting provider state"
        ));
    }
    if (provider_debt - local_debt).abs() > LEDGER_DEBT_EPSILON {
        warnings.push(format!(
            "provider ledger debt changed from local {local_debt:.6} to {provider_debt:.6}; adopting provider state"
        ));
    }

    Ok(warnings)
}

async fn read_consumer_session_state(
    session_state_dir: &Path,
    session_id: &str,
) -> Result<Option<ConsumerProviderSessionState>> {
    let path = consumer_session_state_path(session_state_dir, session_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read session state {}", path.display()))?;
    let state = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse session state {}", path.display()))?;
    Ok(Some(state))
}

async fn write_consumer_session_state(
    session_state_dir: &Path,
    state: &ConsumerProviderSessionState,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(session_state_dir)
        .await
        .with_context(|| format!("failed to create {}", session_state_dir.display()))?;
    let path = consumer_session_state_path(session_state_dir, &state.session_id);
    tokio::fs::write(&path, serde_json::to_vec_pretty(state)?)
        .await
        .with_context(|| format!("failed to write session state {}", path.display()))?;
    Ok(path)
}

fn consumer_session_state_path(session_state_dir: &Path, session_id: &str) -> PathBuf {
    session_state_dir.join(format!("{}.json", safe_file_component(session_id)))
}

async fn write_receipt(receipts_dir: &Path, receipt: &ProviderChatReceiptV1) -> Result<PathBuf> {
    tokio::fs::create_dir_all(receipts_dir)
        .await
        .with_context(|| format!("failed to create {}", receipts_dir.display()))?;
    let path = receipts_dir.join(format!("{}.json", safe_file_component(&receipt.receipt_id)));
    tokio::fs::write(&path, serde_json::to_vec_pretty(receipt)?)
        .await
        .with_context(|| format!("failed to write receipt {}", path.display()))?;
    println!("receipt: {}", path.display());
    Ok(path)
}

async fn write_session_summary(
    summaries_dir: &Path,
    summary: &ProviderSessionSummaryV1,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(summaries_dir)
        .await
        .with_context(|| format!("failed to create {}", summaries_dir.display()))?;
    let path = summaries_dir.join(format!("{}.json", safe_file_component(&summary.session_id)));
    tokio::fs::write(&path, serde_json::to_vec_pretty(summary)?)
        .await
        .with_context(|| format!("failed to write session summary {}", path.display()))?;
    Ok(path)
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
        ModelBackendType, ProviderPaymentMode, ProviderReadinessLabel, ProviderSessionStatus,
        ProviderStatus, PseudoLedgerEventType,
    };

    fn identity() -> ProviderIdentityV1 {
        ProviderIdentityV1 {
            schema_version: hivemind_core::PROVIDER_IDENTITY_SCHEMA_VERSION.to_string(),
            provider_id: "provider-1".to_string(),
            public_key: "local-dev-public-key:provider-1".to_string(),
            signing_scheme: "local-dev".to_string(),
            display_name: "Provider One".to_string(),
            operator_contact: None,
            readiness_label: ProviderReadinessLabel::LanTest,
            created_at: Utc::now(),
            signature: None,
        }
    }

    fn offer(model_id: &str) -> ProviderModelOfferV1 {
        let now = Utc::now();
        ProviderModelOfferV1 {
            schema_version: hivemind_core::PROVIDER_MODEL_OFFER_SCHEMA_VERSION.to_string(),
            offer_id: format!("offer-{model_id}"),
            provider_id: "provider-1".to_string(),
            model_id: model_id.to_string(),
            display_name: model_id.to_string(),
            backend_type: ModelBackendType::Mock,
            backend_model_id: model_id.to_string(),
            supported_apis: Vec::new(),
            supported_features: Vec::new(),
            max_context_tokens: 4096,
            max_output_tokens: 512,
            max_concurrent_sessions: 1,
            max_concurrent_jobs: 1,
            cold_start_policy: hivemind_core::ModelColdStartPolicyV1 {
                allow_consumer_triggered_start: true,
                require_session_before_start: true,
                require_payment_authorization_before_start: true,
                max_starts_per_hour: 1,
                max_cold_start_seconds: 1,
                idle_unload_seconds: None,
            },
            pricing_policy_ref: None,
            pseudopayment_policy: None,
            privacy_tier: PrivacyTier::Standard,
            verification_tier: IntegrityTier::ReceiptOnly,
            readiness_label: ProviderReadinessLabel::Local,
            expires_at: now + Duration::minutes(10),
            signature: None,
        }
    }

    fn lifecycle_state(model_id: &str, state: ModelLifecycleStateKind) -> ModelLifecycleStateV1 {
        ModelLifecycleStateV1 {
            schema_version: hivemind_core::MODEL_LIFECYCLE_STATE_SCHEMA_VERSION.to_string(),
            provider_id: "provider-1".to_string(),
            model_id: model_id.to_string(),
            state,
            backend_type: ModelBackendType::Mock,
            backend_health: "mock-ready".to_string(),
            current_concurrency: 0,
            max_concurrency: 1,
            last_started_at: None,
            last_warmed_at: None,
            last_error: None,
            estimated_cold_start_seconds: Some(1),
        }
    }

    fn health(model_status: ModelLifecycleStateV1) -> ProviderHealthV1 {
        ProviderHealthV1 {
            schema_version: hivemind_core::PROVIDER_HEALTH_SCHEMA_VERSION.to_string(),
            provider_id: "provider-1".to_string(),
            status: ProviderStatus::Healthy,
            uptime_seconds: 12,
            version: "0.1.0".to_string(),
            security_mode: ProviderSecurityMode::LanTest,
            auth_modes: vec![ProviderAuthMode::BearerToken],
            active_sessions: 2,
            active_jobs: 0,
            model_statuses: vec![model_status],
            generated_at: Utc::now(),
        }
    }

    fn session(session_id: &str) -> ProviderSessionV1 {
        let now = Utc::now();
        ProviderSessionV1 {
            schema_version: hivemind_core::PROVIDER_SESSION_SCHEMA_VERSION.to_string(),
            session_id: session_id.to_string(),
            quote_id: "quote-1".to_string(),
            provider_id: "provider-1".to_string(),
            consumer_id: "consumer-1".to_string(),
            model_id: "mock-chat".to_string(),
            status: ProviderSessionStatus::Active,
            payment_mode: ProviderPaymentMode::PseudopaymentDebtForgiveness,
            policy_hash: "policy-hash-1".to_string(),
            opened_at: now,
            expires_at: now + Duration::minutes(10),
            current_ledger_state: PseudoPaymentStateV1 {
                schema_version: hivemind_core::PSEUDO_PAYMENT_STATE_SCHEMA_VERSION.to_string(),
                session_id: session_id.to_string(),
                current_debt: 1.0,
                max_debt: 10.0,
                remaining_capacity: 9.0,
                forgiveness_per_second: 0.5,
                estimated_seconds_to_zero: 2.0,
                status: ProviderSessionStatus::Active,
                last_event_sequence: 1,
                can_submit_next_job: true,
                refusal_reason: None,
            },
            signature: None,
        }
    }

    fn payment_policy() -> PseudoPaymentPolicyV1 {
        let now = Utc::now();
        PseudoPaymentPolicyV1 {
            schema_version: hivemind_core::PSEUDO_PAYMENT_POLICY_SCHEMA_VERSION.to_string(),
            policy_id: "policy-1".to_string(),
            currency_unit: "unit".to_string(),
            max_debt: 10.0,
            forgiveness_per_second: 0.5,
            forgiveness_starts_at: now,
            price_per_input_token: 0.1,
            price_per_output_token: 0.2,
            price_per_model_second: 0.3,
            price_per_request: Some(0.4),
            max_session_duration_seconds: 3600,
            max_jobs_per_minute: 30,
            max_concurrent_jobs: 1,
            stop_when_debt_above_max: true,
            allow_provider_policy_update: false,
            dispute_window_seconds: 60,
            created_at: now,
            expires_at: now + Duration::minutes(10),
        }
    }

    fn session_summary(session_id: &str, receipt_ids: Vec<String>) -> ProviderSessionSummaryV1 {
        ProviderSessionSummaryV1 {
            schema_version: hivemind_core::PROVIDER_SESSION_SUMMARY_SCHEMA_VERSION.to_string(),
            summary_id: format!("provider-session-summary-{session_id}"),
            session_id: session_id.to_string(),
            provider_id: "provider-1".to_string(),
            consumer_id: "consumer-1".to_string(),
            model_id: "mock-chat".to_string(),
            total_jobs: receipt_ids.len() as u64,
            total_input_tokens: 10,
            total_output_tokens: 20,
            total_cost: 0.25,
            total_forgiven: 0.05,
            final_debt: 0.20,
            receipt_ids,
            ledger_event_count: 3,
            closed_at: Utc::now(),
            signature: Some("dev-summary-signature".to_string()),
        }
    }

    fn chat_receipt(receipt_id: &str) -> ProviderChatReceiptV1 {
        let now = Utc::now();
        ProviderChatReceiptV1 {
            schema_version: hivemind_core::PROVIDER_CHAT_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: receipt_id.to_string(),
            job_id: "job-1".to_string(),
            session_id: "session-1".to_string(),
            provider_id: "provider-1".to_string(),
            consumer_id: "consumer-1".to_string(),
            model_id: "mock-chat".to_string(),
            backend_type: ModelBackendType::Mock,
            input_hash: "input-hash".to_string(),
            output_hash: "output-hash".to_string(),
            usage: hivemind_core::ProviderUsageV1 {
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
                model_seconds: 0.1,
                queue_seconds: 0.0,
                first_token_ms: Some(1),
                tokens_per_second: Some(10.0),
                usage_confidence: hivemind_core::UsageConfidence::Estimated,
            },
            cost: 0.1,
            started_at: now,
            finished_at: now,
            stream_summary: json!({}),
            ledger_event_ids: Vec::new(),
            signature: None,
        }
    }

    fn stream_event(
        sequence: u64,
        event_type: ProviderStreamEventType,
        payload: Value,
    ) -> ProviderStreamEventV1 {
        ProviderStreamEventV1 {
            schema_version: hivemind_core::PROVIDER_STREAM_EVENT_SCHEMA_VERSION.to_string(),
            event_id: format!("event-{sequence}"),
            job_id: "job-1".to_string(),
            session_id: "session-1".to_string(),
            sequence,
            event_type,
            payload,
            created_at: Utc::now(),
        }
    }

    fn chat_response(
        text: &str,
        stream_events: Vec<ProviderStreamEventV1>,
    ) -> ProviderChatResponse {
        ProviderChatResponse {
            text: text.to_string(),
            stream_events,
            receipt: chat_receipt("receipt-1"),
            ledger_events: Vec::new(),
            ledger_state: session("session-1").current_ledger_state,
        }
    }

    fn ledger_event(sequence: u64, receipt_id: Option<&str>) -> PseudoLedgerEventV1 {
        PseudoLedgerEventV1 {
            schema_version: hivemind_core::PSEUDO_LEDGER_EVENT_SCHEMA_VERSION.to_string(),
            event_id: format!("ledger-event-{sequence}"),
            session_id: "session-1".to_string(),
            sequence,
            event_type: if receipt_id.is_some() {
                PseudoLedgerEventType::DebitApplied
            } else {
                PseudoLedgerEventType::SessionOpened
            },
            amount: 1.0,
            debt_before: 0.0,
            debt_after: 1.0,
            job_id: Some("job-1".to_string()),
            receipt_id: receipt_id.map(str::to_string),
            reason: "test ledger event".to_string(),
            created_at: Utc::now(),
            signer: "provider-1".to_string(),
            signature: format!("test-ledger-signature-{sequence}"),
        }
    }

    fn ledger_response(session: &ProviderSessionV1) -> ProviderLedgerResponse {
        ProviderLedgerResponse {
            session_id: session.session_id.clone(),
            state: session.current_ledger_state.clone(),
            events: vec![ledger_event(0, None)],
        }
    }

    #[test]
    fn provider_url_must_be_http() {
        assert!(normalize_provider_url("http://127.0.0.1:8788/").is_ok());
        assert!(normalize_provider_url("127.0.0.1:8788").is_err());
    }

    #[test]
    fn payment_state_line_includes_forgiveness_context() {
        let state = session("session-1").current_ledger_state;

        let line = payment_state_line(&state, Some(2));

        assert!(line.contains("forgiveness 0.500000/sec"));
        assert!(line.contains("zero in 2.000s"));
        assert!(line.contains("events +2"));
    }

    #[test]
    fn pseudo_payment_price_line_includes_all_price_terms() {
        let line = pseudo_payment_price_line(&payment_policy());

        assert!(line.contains("0.100000 unit/input-token"));
        assert!(line.contains("0.200000 unit/output-token"));
        assert!(line.contains("0.300000 unit/model-second"));
        assert!(line.contains("0.400000 unit/request"));
    }

    #[test]
    fn provider_check_text_includes_operational_status_and_warnings() {
        let mut checked_offer = offer("mock-chat");
        checked_offer.pseudopayment_policy = Some(payment_policy());
        let status = lifecycle_state("mock-chat", ModelLifecycleStateKind::Ready);
        let capabilities = ProviderCapabilitiesResponse {
            identity: identity(),
            offers: vec![checked_offer.clone()],
            security_mode: ProviderSecurityMode::LanTest,
            auth_modes: vec![ProviderAuthMode::BearerToken],
        };
        let report = provider_check_report(
            "http://provider-lan:8788".to_string(),
            health(status.clone()),
            &capabilities,
            checked_offer,
            status,
        );

        let text = provider_check_text(&report);

        assert!(text.contains("Provider: Provider One (provider-1)"));
        assert!(text.contains("Status: Healthy"));
        assert!(text.contains("Security: LanTest, auth [BearerToken]"));
        assert!(text.contains("Model state: Ready"));
        assert!(text.contains("Pseudopay: max debt 10.000000"));
        assert!(text.contains("Price: 0.100000 unit/input-token"));
        assert!(text.contains("warning: provider connection is plain HTTP"));
        assert!(text.contains("warning: provider can see prompts and outputs"));
    }

    #[test]
    fn consumer_warnings_call_out_lan_http_and_test_accounting() {
        let warnings = consumer_warning_lines_for(
            "http://192.168.1.50:8788",
            &ProviderSecurityMode::LanTest,
            &[ProviderAuthMode::None],
            &PrivacyTier::Standard,
            &ModelLifecycleStateKind::AvailableCold,
        );

        assert!(warnings.iter().any(|line| line.contains("plain HTTP")));
        assert!(warnings.iter().any(|line| line.contains("unauthenticated")));
        assert!(
            warnings
                .iter()
                .any(|line| line.contains("provider can see prompts"))
        );
        assert!(warnings.iter().any(|line| line.contains("cold start")));
        assert!(
            warnings
                .iter()
                .any(|line| line.contains("not real settlement"))
        );
    }

    #[test]
    fn consumer_warnings_allow_loopback_http_without_transport_warning() {
        let warnings = consumer_warning_lines_for(
            "http://127.0.0.1:8788",
            &ProviderSecurityMode::LocalDev,
            &[ProviderAuthMode::BearerToken],
            &PrivacyTier::NoLog,
            &ModelLifecycleStateKind::Ready,
        );

        assert!(!warnings.iter().any(|line| line.contains("plain HTTP")));
        assert!(warnings.iter().any(|line| line.contains("local-dev")));
        assert!(!warnings.iter().any(|line| line.contains("cold start")));
    }

    #[test]
    fn resume_reconciliation_warns_when_provider_ledger_is_ahead() {
        let provider_session = session("session-1");
        let mut ledger = ledger_response(&provider_session);
        ledger.state.last_event_sequence = 2;
        ledger.state.current_debt = 2.5;
        ledger.events.push(ledger_event(2, Some("receipt-2")));
        let local_state = local_state_from_session(
            "http://127.0.0.1:8788",
            "provider-1",
            "consumer-1",
            &provider_session,
            Vec::new(),
        );

        let warnings = reconcile_resume_ledger_state(&local_state, &ledger).unwrap();

        assert!(warnings.iter().any(|line| line.contains("ledger is ahead")));
        assert!(warnings.iter().any(|line| line.contains("debt changed")));
    }

    #[test]
    fn resume_reconciliation_rejects_local_ledger_ahead() {
        let provider_session = session("session-1");
        let mut ledger = ledger_response(&provider_session);
        ledger.state.last_event_sequence = 1;
        let mut local_state = local_state_from_session(
            "http://127.0.0.1:8788",
            "provider-1",
            "consumer-1",
            &provider_session,
            Vec::new(),
        );
        local_state.last_ledger_sequence = 2;

        let error = reconcile_resume_ledger_state(&local_state, &ledger).unwrap_err();

        assert!(error.to_string().contains("local ledger sequence"));
        assert!(error.to_string().contains("refusing resume"));
    }

    #[test]
    fn resume_reconciliation_rejects_missing_provider_receipt() {
        let provider_session = session("session-1");
        let ledger = ledger_response(&provider_session);
        let local_state = local_state_from_session(
            "http://127.0.0.1:8788",
            "provider-1",
            "consumer-1",
            &provider_session,
            vec!["receipt-1".to_string()],
        );

        let error = reconcile_resume_ledger_state(&local_state, &ledger).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing local receipt IDs receipt-1")
        );
    }

    #[test]
    fn resume_reconciliation_rejects_same_sequence_higher_provider_debt() {
        let provider_session = session("session-1");
        let mut ledger = ledger_response(&provider_session);
        ledger.state.current_debt = 2.0;
        let local_state = local_state_from_session(
            "http://127.0.0.1:8788",
            "provider-1",
            "consumer-1",
            &provider_session,
            Vec::new(),
        );

        let error = reconcile_resume_ledger_state(&local_state, &ledger).unwrap_err();

        assert!(error.to_string().contains("higher debt"));
    }

    #[test]
    fn render_provider_answer_uses_token_deltas_in_sequence_order() {
        let response = chat_response(
            "hello world",
            vec![
                stream_event(
                    3,
                    ProviderStreamEventType::TokenDelta,
                    json!({ "text": "world" }),
                ),
                stream_event(
                    1,
                    ProviderStreamEventType::StreamStarted,
                    json!({ "stream": true }),
                ),
                stream_event(
                    4,
                    ProviderStreamEventType::StreamFinished,
                    json!({ "receiptId": "receipt-1" }),
                ),
                stream_event(
                    2,
                    ProviderStreamEventType::TokenDelta,
                    json!({ "text": "hello " }),
                ),
            ],
        );

        let rendered = render_provider_answer(&response).unwrap();

        assert_eq!(rendered.text, "hello world");
        assert_eq!(rendered.token_deltas, vec!["hello ", "world"]);
    }

    #[test]
    fn render_provider_answer_falls_back_without_stream_events() {
        let response = chat_response("plain answer", Vec::new());

        let rendered = render_provider_answer(&response).unwrap();

        assert_eq!(rendered.text, "plain answer");
        assert!(rendered.token_deltas.is_empty());
    }

    #[test]
    fn render_provider_answer_requires_terminal_stream_event() {
        let response = chat_response(
            "hello",
            vec![stream_event(
                1,
                ProviderStreamEventType::TokenDelta,
                json!({ "text": "hello" }),
            )],
        );

        let error = render_provider_answer(&response).unwrap_err();

        assert!(error.to_string().contains("stream_finished"));
    }

    #[test]
    fn render_provider_answer_rejects_mismatched_receipt_id() {
        let response = chat_response(
            "hello",
            vec![
                stream_event(
                    1,
                    ProviderStreamEventType::TokenDelta,
                    json!({ "text": "hello" }),
                ),
                stream_event(
                    2,
                    ProviderStreamEventType::StreamFinished,
                    json!({ "receiptId": "receipt-2" }),
                ),
            ],
        );

        let error = render_provider_answer(&response).unwrap_err();

        assert!(error.to_string().contains("receiptId"));
    }

    #[test]
    fn cancel_mode_requires_resume_session_and_no_chat_turn() {
        let mut config = ProviderChatConfig {
            provider_url: "http://127.0.0.1:8788".to_string(),
            bearer_token: None,
            consumer_id: "consumer-1".to_string(),
            model_id: None,
            message: None,
            expected_max_input_tokens: 4096,
            expected_max_output_tokens: 1024,
            max_output_tokens: 512,
            spending_cap: None,
            receipts_dir: PathBuf::from("receipts"),
            session_state_dir: PathBuf::from("sessions"),
            session_summaries_dir: PathBuf::from("summaries"),
            resume_session_id: None,
            cancel_job_id: Some("job-1".to_string()),
            sign_requests: false,
            show_events: false,
            close_session: false,
        };

        assert!(validate_provider_chat_config(&config).is_err());

        config.resume_session_id = Some("session-1".to_string());
        assert!(validate_provider_chat_config(&config).is_ok());

        config.message = Some("hello".to_string());
        assert!(validate_provider_chat_config(&config).is_err());

        config.message = None;
        config.close_session = true;
        assert!(validate_provider_chat_config(&config).is_err());
    }

    #[test]
    fn job_cancel_request_signs_session_and_path() {
        let request =
            provider_job_cancel_request("provider-1", "consumer-1", "session-1", "job-1", true)
                .unwrap();
        let envelope = request.request_envelope.as_ref().unwrap();

        assert_eq!(
            request.schema_version,
            hivemind_core::PROVIDER_JOB_CANCEL_REQUEST_SCHEMA_VERSION
        );
        assert_eq!(request.job_id, "job-1");
        assert_eq!(envelope.method, "POST");
        assert_eq!(envelope.path, "/v1/provider/jobs/job-1/cancel");
        assert_eq!(envelope.session_id.as_deref(), Some("session-1"));
        assert_eq!(
            envelope.body_hash,
            signed_request_body_hash(&request).unwrap()
        );
    }

    #[test]
    fn job_cancel_request_rejects_empty_job_id() {
        let error =
            provider_job_cancel_request("provider-1", "consumer-1", "session-1", "   ", false)
                .unwrap_err();

        assert!(error.to_string().contains("cancel job id"));
    }

    #[test]
    fn selects_requested_offer_or_first_default() {
        let offers = vec![offer("small"), offer("large")];
        assert_eq!(select_offer(&offers, None).unwrap().model_id, "small");
        assert_eq!(
            select_offer(&offers, Some("large")).unwrap().model_id,
            "large"
        );
        assert!(select_offer(&offers, Some("missing")).is_err());
    }

    #[test]
    fn safe_receipt_file_component_removes_path_chars() {
        assert_eq!(safe_file_component("../receipt:1"), "---receipt-1");
    }

    #[test]
    fn local_session_state_path_is_safe() {
        let path = consumer_session_state_path(Path::new("sessions"), "../session:1");
        assert_eq!(path.file_name().unwrap(), "---session-1.json");
    }

    #[tokio::test]
    async fn session_summary_round_trips() {
        let summary = session_summary("../session:1", vec!["receipt-1".to_string()]);
        let dir =
            std::env::temp_dir().join(format!("hivemind-consumer-summary-test-{}", Uuid::new_v4()));

        let path = write_session_summary(&dir, &summary).await.unwrap();
        let loaded: ProviderSessionSummaryV1 =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();

        assert_eq!(path.file_name().unwrap(), "---session-1.json");
        assert_eq!(loaded.summary_id, summary.summary_id);
        assert_eq!(loaded.receipt_ids, vec!["receipt-1"]);
    }

    #[test]
    fn resume_local_state_rejects_identity_mismatch() {
        let session = session("session-1");
        let mut state = local_state_from_session(
            "http://127.0.0.1:8788",
            "provider-1",
            "consumer-1",
            &session,
            Vec::new(),
        );
        state.provider_id = "provider-2".to_string();

        assert!(
            validate_resume_local_state(&state, "http://127.0.0.1:8788", "provider-1", &session)
                .is_err()
        );
    }

    #[tokio::test]
    async fn local_session_state_round_trips() {
        let session = session("session-1");
        let state = local_state_from_session(
            "http://127.0.0.1:8788",
            "provider-1",
            "consumer-1",
            &session,
            vec!["receipt-1".to_string()],
        );
        let dir =
            std::env::temp_dir().join(format!("hivemind-consumer-session-test-{}", Uuid::new_v4()));

        write_consumer_session_state(&dir, &state).await.unwrap();
        let loaded = read_consumer_session_state(&dir, "session-1")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.session_id, "session-1");
        assert_eq!(loaded.receipt_ids, vec!["receipt-1"]);
        assert!(loaded.session_summary_id.is_none());
    }

    #[tokio::test]
    async fn local_session_state_round_trips_summary_metadata() {
        let session = session("session-1");
        let mut state = local_state_from_session(
            "http://127.0.0.1:8788",
            "provider-1",
            "consumer-1",
            &session,
            vec!["receipt-1".to_string()],
        );
        state.session_summary_id = Some("summary-1".to_string());
        state.session_summary_path = Some("summaries/session-1.json".to_string());
        state.closed_at = Some(Utc::now());
        let dir =
            std::env::temp_dir().join(format!("hivemind-consumer-session-test-{}", Uuid::new_v4()));

        write_consumer_session_state(&dir, &state).await.unwrap();
        let loaded = read_consumer_session_state(&dir, "session-1")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.session_summary_id.as_deref(), Some("summary-1"));
        assert_eq!(
            loaded.session_summary_path.as_deref(),
            Some("summaries/session-1.json")
        );
        assert!(loaded.closed_at.is_some());
    }
}
