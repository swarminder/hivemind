use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use hivemind_core::{
    IntegrityTier, ModelLifecycleStateKind, ModelLifecycleStateV1, PrivacyTier, ProviderAuthMode,
    ProviderChatReceiptV1, ProviderChatRequestV1, ProviderHealthV1, ProviderModelOfferV1,
    ProviderModelStartRequestV1, ProviderPaymentMode, ProviderQuoteRequestV1, ProviderQuoteV1,
    ProviderSessionCloseRequestV1, ProviderSessionOpenRequestV1, ProviderSessionSummaryV1,
    ProviderSessionV1, ProviderStreamEventV1, PseudoLedgerEventV1, PseudoPaymentStateV1,
    SignedRequestEnvelopeV1, hash_canonical_json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const CONSUMER_SESSION_STATE_SCHEMA_VERSION: &str = "hivemind.provider_consumer.local_session.v1";

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
    pub sign_requests: bool,
    pub show_events: bool,
    pub close_session: bool,
}

#[derive(Debug, Deserialize)]
struct ProviderCapabilitiesResponse {
    identity: hivemind_core::ProviderIdentityV1,
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

pub async fn chat(config: ProviderChatConfig) -> Result<()> {
    let mut session = open_provider_chat_session(&config).await?;
    print_session_summary(&session);

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
) -> Result<ProviderChatSession> {
    let session_id = session_id.trim();
    if session_id.is_empty() {
        bail!("resume session id is required");
    }
    let session: ProviderSessionV1 = get_json(
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
    let offer = select_offer(&capabilities.offers, Some(&session.model_id))?;
    let local_state = read_consumer_session_state(&config.session_state_dir, &session.session_id)
        .await?
        .unwrap_or_else(|| {
            local_state_from_session(
                &provider_url,
                &health.provider_id,
                &config.consumer_id,
                &session,
                Vec::new(),
            )
        });
    validate_resume_local_state(&local_state, &provider_url, &health.provider_id, &session)?;
    let mut local_state = local_state;
    local_state.current_debt = session.current_ledger_state.current_debt;
    local_state.last_ledger_sequence = session.current_ledger_state.last_event_sequence;
    local_state.updated_at = Utc::now();
    let state_path = write_consumer_session_state(&config.session_state_dir, &local_state).await?;
    println!("resumed session state: {}", state_path.display());
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
    let status_url = format!(
        "{provider_url}/v1/provider/models/{}/status",
        offer.model_id
    );
    let status: ModelLifecycleStateV1 = get_json(client, bearer_token, &status_url)
        .await
        .context("failed to fetch provider model status")?;
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

    println!("provider> {}", response.text);
    if config.show_events {
        for event in &response.stream_events {
            println!("event {}: {:?}", event.sequence, event.event_type);
        }
    }
    println!(
        "ledger: debt {:.6} / {:.6}, remaining {:.6}, events +{}",
        response.ledger_state.current_debt,
        response.ledger_state.max_debt,
        response.ledger_state.remaining_capacity,
        response.ledger_events.len()
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
        .push(json!({ "role": "assistant", "content": response.text }));
    Ok(())
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
    } else {
        println!("Quote: {} (resumed)", session.session.quote_id);
        println!(
            "Pseudopay: debt {:.6} / {:.6}, forgiveness {:.6}/sec",
            session.session.current_ledger_state.current_debt,
            session.session.current_ledger_state.max_debt,
            session.session.current_ledger_state.forgiveness_per_second
        );
    }
    println!("Session: {}", session.session.session_id);
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
    };

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

    #[test]
    fn provider_url_must_be_http() {
        assert!(normalize_provider_url("http://127.0.0.1:8788/").is_ok());
        assert!(normalize_provider_url("127.0.0.1:8788").is_err());
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
