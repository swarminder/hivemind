use hivemind_core::{
    AiInputPartType, AiInputPartV1, AiPackageSelectorV1, AiRequestConstraintsV1,
    AiRequestPrivacyV1, AiRequestV1, AiRequestValidationV1, AiSamplingOptionsV1, ApiSurface,
    ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1, Modality,
    PrivacyTier, canonicalize_json, hash_canonical_json,
};
use hivemind_realtime::{
    RealtimeConnectionPlanV1, RealtimeSessionInitOptionsV1, RealtimeSessionV1, RealtimeTransport,
    create_realtime_session, realtime_connection_plan_for_surface, verify_realtime_session,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnthropicMessageRequestV1 {
    pub model: String,
    #[serde(default)]
    pub messages: Vec<AnthropicMessageV1>,
    #[serde(default)]
    pub system: Option<Value>,
    #[serde(default)]
    pub stream: bool,
    #[serde(rename = "max_tokens", default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnthropicMessageV1 {
    pub role: String,
    #[serde(default)]
    pub content: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnthropicMessageResponseV1 {
    pub id: String,
    #[serde(rename = "type")]
    pub response_type: String,
    pub role: String,
    pub model: String,
    pub content: Vec<AnthropicContentBlockV1>,
    #[serde(rename = "stop_reason", default)]
    pub stop_reason: Option<String>,
    #[serde(rename = "stop_sequence", default)]
    pub stop_sequence: Option<String>,
    pub usage: AnthropicUsageV1,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnthropicContentBlockV1 {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnthropicUsageV1 {
    #[serde(rename = "input_tokens")]
    pub input_tokens: u64,
    #[serde(rename = "output_tokens")]
    pub output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnthropicErrorResponseV1 {
    #[serde(rename = "type")]
    pub response_type: String,
    pub error: AnthropicErrorDetailV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnthropicErrorDetailV1 {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiGenerateContentRequestV1 {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub contents: Vec<GeminiContentV1>,
    #[serde(rename = "systemInstruction", default)]
    pub system_instruction: Option<GeminiContentV1>,
    #[serde(rename = "generationConfig", default)]
    pub generation_config: Option<GeminiGenerationConfigV1>,
    #[serde(rename = "safetySettings", default)]
    pub safety_settings: Vec<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiContentV1 {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub parts: Vec<GeminiPartV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiPartV1 {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(rename = "inlineData", default)]
    pub inline_data: Option<Value>,
    #[serde(rename = "fileData", default)]
    pub file_data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiGenerationConfigV1 {
    #[serde(rename = "maxOutputTokens", default)]
    pub max_output_tokens: Option<u64>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(rename = "topP", default)]
    pub top_p: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiGenerateContentResponseV1 {
    pub candidates: Vec<GeminiCandidateV1>,
    #[serde(rename = "usageMetadata")]
    pub usage_metadata: GeminiUsageMetadataV1,
    #[serde(rename = "modelVersion", default)]
    pub model_version: Option<String>,
    #[serde(rename = "hivemindMetadata", default)]
    pub hivemind_metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiCandidateV1 {
    pub content: GeminiContentV1,
    #[serde(rename = "finishReason")]
    pub finish_reason: String,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiUsageMetadataV1 {
    #[serde(rename = "promptTokenCount")]
    pub prompt_token_count: u64,
    #[serde(rename = "candidatesTokenCount")]
    pub candidates_token_count: u64,
    #[serde(rename = "totalTokenCount")]
    pub total_token_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiErrorResponseV1 {
    pub error: GeminiErrorDetailV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiErrorDetailV1 {
    pub code: u16,
    pub message: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiLiveSessionCreateRequestV1 {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(rename = "systemInstruction", default)]
    pub system_instruction: Option<GeminiContentV1>,
    #[serde(rename = "generationConfig", default)]
    pub generation_config: Option<GeminiGenerationConfigV1>,
    #[serde(rename = "inputModalities", default)]
    pub input_modalities: Vec<String>,
    #[serde(rename = "responseModalities", default)]
    pub response_modalities: Vec<String>,
    #[serde(rename = "speechConfig", default)]
    pub speech_config: Option<Value>,
    #[serde(rename = "realtimeInputConfig", default)]
    pub realtime_input_config: Option<Value>,
    #[serde(rename = "sessionResumption", default)]
    pub session_resumption: Option<Value>,
    #[serde(rename = "contextWindowCompression", default)]
    pub context_window_compression: Option<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "packageId", default)]
    pub package_id: Option<String>,
    #[serde(rename = "packageVersion", default)]
    pub package_version: Option<String>,
    #[serde(rename = "serviceRef", default)]
    pub service_ref: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(rename = "latencyTargetMs", default)]
    pub latency_target_ms: Option<u32>,
    #[serde(rename = "interruptionsAllowed", default)]
    pub interruptions_allowed: Option<bool>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<String>,
    #[serde(rename = "settlementMethod", default)]
    pub settlement_method: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiLiveSessionV1 {
    pub name: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub model: String,
    pub state: String,
    #[serde(rename = "connectionUri")]
    pub connection_uri: String,
    pub transport: String,
    #[serde(rename = "inputModalities")]
    pub input_modalities: Vec<String>,
    #[serde(rename = "responseModalities")]
    pub response_modalities: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "hivemindMetadata", default)]
    pub hivemind_metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GeminiLiveSessionRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub request: GeminiLiveSessionCreateRequestV1,
    pub session: RealtimeSessionV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HuggingFaceInferenceRequestV1 {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub inputs: Value,
    #[serde(default)]
    pub parameters: Value,
    #[serde(default)]
    pub options: Value,
    #[serde(default)]
    pub task: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HuggingFaceInferenceResponseV1 {
    pub model: String,
    pub task: String,
    pub results: Value,
    #[serde(rename = "hivemindMetadata", default)]
    pub hivemind_metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HuggingFaceErrorResponseV1 {
    pub error: String,
    #[serde(rename = "error_type")]
    pub error_type: String,
}

pub fn anthropic_messages_to_execution(
    request: &AnthropicMessageRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id: impl Into<String>,
) -> ExecutionRequestV1 {
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: request_id.into(),
        package_ref: package_ref.into(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: "chat".to_string(),
        input: json!({
            "messages": request.messages,
            "system": request.system,
            "text": latest_anthropic_user_text(&request.messages),
            "model": request.model,
            "maxOutputTokens": request.max_tokens,
            "temperature": request.temperature,
            "metadata": request.metadata,
            "apiSurface": ApiSurface::AnthropicMessages,
            "compatTask": "anthropic_messages",
        }),
        options: ExecutionOptions {
            stream: request.stream,
            ..ExecutionOptions::default()
        },
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    }
}

pub fn anthropic_messages_to_ai_request(
    request: &AnthropicMessageRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    let text = latest_anthropic_user_text(&request.messages);
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: provider_requester(&request.metadata, default_requester),
        api_surface: ApiSurface::AnthropicMessages,
        package_selector: ai_package_selector_from_model(&request.model),
        inputs: ai_text_parts_from_text(text),
        messages: Some(
            request
                .messages
                .iter()
                .map(|message| json!(message))
                .collect(),
        ),
        tools: None,
        response_format: None,
        stream: request.stream,
        sampling: ai_sampling_options(request.temperature, None, request.max_tokens),
        task: Some("chat".to_string()),
        constraints: AiRequestConstraintsV1::default(),
        privacy: AiRequestPrivacyV1::default(),
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: provider_metadata_with_payload(
            request.metadata.clone(),
            "anthropic",
            json!({
                "compatTask": "anthropic_messages",
                "model": request.model,
                "system": request.system,
            }),
        ),
    }
}

pub fn anthropic_message_from_execution(
    request: &AnthropicMessageRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
) -> AnthropicMessageResponseV1 {
    let text = response_message_content(response);
    let output_tokens = response
        .metrics
        .output_tokens
        .unwrap_or_else(|| count_tokens(&text));
    let input_tokens = response
        .metrics
        .input_tokens
        .unwrap_or_else(|| count_tokens(&anthropic_prompt_text(request)));
    AnthropicMessageResponseV1 {
        id: id.into(),
        response_type: "message".to_string(),
        role: "assistant".to_string(),
        model: request.model.clone(),
        content: vec![AnthropicContentBlockV1 {
            block_type: "text".to_string(),
            text,
        }],
        stop_reason: Some("end_turn".to_string()),
        stop_sequence: None,
        usage: AnthropicUsageV1 {
            input_tokens,
            output_tokens,
        },
        metadata: json!({
            "hivemind": {
                "receiptRef": response.receipt_ref,
                "executionMetadata": response.metadata,
            }
        }),
    }
}

pub fn huggingface_inference_to_execution(
    request: &HuggingFaceInferenceRequestV1,
    model: impl Into<String>,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id: impl Into<String>,
) -> ExecutionRequestV1 {
    let model = model.into();
    let task = huggingface_task(request);
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: request_id.into(),
        package_ref: package_ref.into(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: execution_task_for_huggingface_task(&task).to_string(),
        input: json!({
            "inputs": request.inputs,
            "parameters": request.parameters,
            "options": request.options,
            "text": huggingface_input_text(&request.inputs),
            "model": model,
            "task": task,
            "metadata": request.metadata,
            "apiSurface": ApiSurface::HuggingFaceInference,
            "compatTask": "huggingface_inference",
        }),
        options: ExecutionOptions::default(),
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    }
}

pub fn huggingface_inference_to_ai_request(
    request: &HuggingFaceInferenceRequestV1,
    model: impl Into<String>,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    let model = model.into();
    let task = huggingface_task(request);
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: provider_requester(&request.metadata, default_requester),
        api_surface: ApiSurface::HuggingFaceInference,
        package_selector: ai_package_selector_from_model(&model),
        inputs: vec![ai_text_part_from_value(json!(huggingface_input_text(
            &request.inputs
        )))],
        messages: None,
        tools: None,
        response_format: None,
        stream: false,
        sampling: None,
        task: Some(execution_task_for_huggingface_task(&task).to_string()),
        constraints: AiRequestConstraintsV1::default(),
        privacy: AiRequestPrivacyV1::default(),
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: provider_metadata_with_payload(
            request.metadata.clone(),
            "huggingface",
            json!({
                "compatTask": "huggingface_inference",
                "inputs": request.inputs,
                "model": model,
                "parameters": request.parameters,
                "task": task,
            }),
        ),
    }
}

pub fn huggingface_inference_from_execution(
    model: impl Into<String>,
    request: &HuggingFaceInferenceRequestV1,
    response: &ExecutionResponseV1,
) -> HuggingFaceInferenceResponseV1 {
    let model = model.into();
    let task = huggingface_task(request);
    let results = if execution_task_for_huggingface_task(&task) == "embedding" {
        json!([response_embedding(response)])
    } else {
        json!([{
            "generated_text": response_message_content(response),
        }])
    };
    HuggingFaceInferenceResponseV1 {
        model,
        task,
        results,
        hivemind_metadata: json!({
            "receiptRef": response.receipt_ref,
            "executionMetadata": response.metadata,
        }),
    }
}

pub fn huggingface_error_response(
    error_type: impl Into<String>,
    message: impl Into<String>,
) -> HuggingFaceErrorResponseV1 {
    HuggingFaceErrorResponseV1 {
        error: message.into(),
        error_type: error_type.into(),
    }
}

pub fn huggingface_model_from_request(request: &HuggingFaceInferenceRequestV1) -> Option<String> {
    request
        .model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_string)
}

pub fn anthropic_error_response(
    error_type: impl Into<String>,
    message: impl Into<String>,
) -> AnthropicErrorResponseV1 {
    AnthropicErrorResponseV1 {
        response_type: "error".to_string(),
        error: AnthropicErrorDetailV1 {
            error_type: error_type.into(),
            message: message.into(),
        },
    }
}

pub fn gemini_generate_content_to_execution(
    request: &GeminiGenerateContentRequestV1,
    model: impl Into<String>,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id: impl Into<String>,
) -> ExecutionRequestV1 {
    let model = model.into();
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: request_id.into(),
        package_ref: package_ref.into(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: "chat".to_string(),
        input: json!({
            "contents": request.contents,
            "systemInstruction": request.system_instruction,
            "text": latest_gemini_user_text(&request.contents),
            "model": model,
            "generationConfig": request.generation_config,
            "safetySettings": request.safety_settings,
            "tools": request.tools,
            "metadata": request.metadata,
            "apiSurface": ApiSurface::GeminiGenerateContent,
            "compatTask": "gemini_generate_content",
        }),
        options: ExecutionOptions::default(),
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    }
}

pub fn gemini_generate_content_to_ai_request(
    request: &GeminiGenerateContentRequestV1,
    model: impl Into<String>,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    let model = model.into();
    let text = latest_gemini_user_text(&request.contents);
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: provider_requester(&request.metadata, default_requester),
        api_surface: ApiSurface::GeminiGenerateContent,
        package_selector: ai_package_selector_from_model(&model),
        inputs: ai_text_parts_from_text(text),
        messages: Some(
            request
                .contents
                .iter()
                .map(|content| json!(content))
                .collect(),
        ),
        tools: (!request.tools.is_empty()).then(|| request.tools.clone()),
        response_format: None,
        stream: false,
        sampling: request.generation_config.as_ref().and_then(|config| {
            ai_sampling_options(config.temperature, config.top_p, config.max_output_tokens)
        }),
        task: Some("chat".to_string()),
        constraints: AiRequestConstraintsV1::default(),
        privacy: AiRequestPrivacyV1::default(),
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: provider_metadata_with_payload(
            request.metadata.clone(),
            "gemini",
            json!({
                "compatTask": "gemini_generate_content",
                "generationConfig": request.generation_config,
                "model": model,
                "safetySettings": request.safety_settings,
                "systemInstruction": request.system_instruction,
            }),
        ),
    }
}

pub fn gemini_generate_content_from_execution(
    model: impl Into<String>,
    request: &GeminiGenerateContentRequestV1,
    response: &ExecutionResponseV1,
) -> GeminiGenerateContentResponseV1 {
    let text = response_message_content(response);
    let candidates_token_count = response
        .metrics
        .output_tokens
        .unwrap_or_else(|| count_tokens(&text));
    let prompt_token_count = response
        .metrics
        .input_tokens
        .unwrap_or_else(|| count_tokens(&gemini_prompt_text(request)));
    GeminiGenerateContentResponseV1 {
        candidates: vec![GeminiCandidateV1 {
            content: GeminiContentV1 {
                role: Some("model".to_string()),
                parts: vec![GeminiPartV1 {
                    text: Some(text),
                    inline_data: None,
                    file_data: None,
                }],
            },
            finish_reason: "STOP".to_string(),
            index: 0,
        }],
        usage_metadata: GeminiUsageMetadataV1 {
            prompt_token_count,
            candidates_token_count,
            total_token_count: prompt_token_count + candidates_token_count,
        },
        model_version: Some(model.into()),
        hivemind_metadata: json!({
            "receiptRef": response.receipt_ref,
            "executionMetadata": response.metadata,
        }),
    }
}

pub fn gemini_error_response(
    code: u16,
    status: impl Into<String>,
    message: impl Into<String>,
) -> GeminiErrorResponseV1 {
    GeminiErrorResponseV1 {
        error: GeminiErrorDetailV1 {
            code,
            status: status.into(),
            message: message.into(),
        },
    }
}

pub fn gemini_model_from_request(request: &GeminiGenerateContentRequestV1) -> Option<String> {
    request
        .model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_string)
}

pub fn gemini_live_model_from_request(
    request: &GeminiLiveSessionCreateRequestV1,
) -> Option<String> {
    trim_optional_string(&request.model)
}

pub fn gemini_live_session_record_from_request(
    request: &GeminiLiveSessionCreateRequestV1,
    default_requester: impl Into<String>,
) -> GeminiLiveSessionRecordV1 {
    GeminiLiveSessionRecordV1 {
        schema_version: "swarm-ai.gemini-live-session-record.v1".to_string(),
        request: request.clone(),
        session: gemini_live_session_from_request(request, default_requester),
    }
}

pub fn gemini_live_session_from_request(
    request: &GeminiLiveSessionCreateRequestV1,
    default_requester: impl Into<String>,
) -> RealtimeSessionV1 {
    let model = request
        .model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let package_ref = trim_optional_string(&request.package_ref).or_else(|| {
        model
            .filter(|value| looks_like_storage_ref(value))
            .map(ToOwned::to_owned)
    });
    let package_id = trim_optional_string(&request.package_id).or_else(|| {
        model
            .filter(|value| !looks_like_storage_ref(value))
            .map(ToOwned::to_owned)
    });
    let model_alias = model
        .filter(|value| !looks_like_storage_ref(value))
        .map(ToOwned::to_owned)
        .or_else(|| {
            (package_ref.is_none() && package_id.is_none() && request.service_ref.is_none())
                .then(|| "hivemind/realtime".to_string())
        });

    create_realtime_session(RealtimeSessionInitOptionsV1 {
        requester: requester_from_metadata_value(&request.metadata)
            .unwrap_or_else(|| default_requester.into()),
        package_ref,
        package_id,
        package_version: trim_optional_string(&request.package_version),
        service_ref: trim_optional_string(&request.service_ref),
        model_alias,
        modalities_in: gemini_live_modalities(
            &request.input_modalities,
            &[Modality::Audio, Modality::Text],
        ),
        modalities_out: gemini_live_modalities(
            &request.response_modalities,
            &[Modality::Audio, Modality::Text],
        ),
        transport: request
            .transport
            .as_deref()
            .and_then(realtime_transport_from_str),
        latency_target_ms: request.latency_target_ms,
        interruptions_allowed: request.interruptions_allowed,
        tool_refs: request.tools.iter().map(gemini_live_tool_ref).collect(),
        privacy_tier: Some(gemini_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        settlement_method: trim_optional_string(&request.settlement_method).or_else(|| {
            metadata_string_value(
                &request.metadata,
                &["settlement_method", "settlementMethod"],
            )
        }),
    })
}

pub fn gemini_live_session_to_ai_request(
    request: &GeminiLiveSessionCreateRequestV1,
    model: impl Into<String>,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    let model = model.into();
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: provider_requester(&request.metadata, default_requester),
        api_surface: ApiSurface::GeminiLive,
        package_selector: ai_package_selector_from_model(&model),
        inputs: Vec::new(),
        messages: None,
        tools: (!request.tools.is_empty()).then(|| request.tools.clone()),
        response_format: Some(json!({
            "inputModalities": request.input_modalities,
            "responseModalities": request.response_modalities,
            "transport": request.transport,
        })),
        stream: true,
        sampling: request.generation_config.as_ref().and_then(|config| {
            ai_sampling_options(config.temperature, config.top_p, config.max_output_tokens)
        }),
        task: Some("realtime".to_string()),
        constraints: AiRequestConstraintsV1 {
            max_latency_ms: request.latency_target_ms.map(u64::from),
            ..AiRequestConstraintsV1::default()
        },
        privacy: AiRequestPrivacyV1 {
            privacy_tier: gemini_privacy_tier(request.privacy_tier.as_deref(), &request.metadata),
            ..AiRequestPrivacyV1::default()
        },
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: provider_metadata_with_payload(
            request.metadata.clone(),
            "gemini",
            json!({
                "compatTask": "gemini_live",
                "contextWindowCompression": request.context_window_compression,
                "model": model,
                "realtimeInputConfig": request.realtime_input_config,
                "sessionResumption": request.session_resumption,
                "speechConfig": request.speech_config,
            }),
        ),
    }
}

pub fn gemini_live_session_from_record(record: &GeminiLiveSessionRecordV1) -> GeminiLiveSessionV1 {
    let verification = verify_realtime_session(&record.session);
    let plan = realtime_connection_plan_for_surface(&record.session, ApiSurface::GeminiLive);
    gemini_live_session_from_parts(
        &record.request,
        &record.session,
        &plan,
        verification.valid && plan.valid,
    )
}

pub fn gemini_live_session_from_parts(
    request: &GeminiLiveSessionCreateRequestV1,
    session: &RealtimeSessionV1,
    plan: &RealtimeConnectionPlanV1,
    valid: bool,
) -> GeminiLiveSessionV1 {
    let model = request
        .model
        .clone()
        .or_else(|| session.package_selector.model_alias.clone())
        .or_else(|| session.package_selector.package_id.clone())
        .or_else(|| session.package_selector.package_ref.clone())
        .or_else(|| session.package_selector.service_ref.clone())
        .unwrap_or_else(|| "hivemind/realtime".to_string());
    let input_modalities = session
        .modalities_in
        .iter()
        .map(gemini_modality_name)
        .collect();
    let response_modalities = session
        .modalities_out
        .iter()
        .map(gemini_modality_name)
        .collect();

    GeminiLiveSessionV1 {
        name: format!("sessions/{}", session.session_id),
        session_id: session.session_id.clone(),
        model,
        state: if valid {
            "CREATED".to_string()
        } else {
            "FAILED".to_string()
        },
        connection_uri: plan.connection_ref.clone(),
        transport: gemini_transport_name(&session.transport),
        input_modalities,
        response_modalities,
        created_at: session.created_at.clone(),
        hivemind_metadata: json!({
            "session": session,
            "verification": verify_realtime_session(session),
            "plan": plan,
            "compatibilityMode": "contract-only",
            "transportMode": "plan-only",
            "storageRole": "Swarm/Bee stores packages, tool manifests, receipts, and audit evidence; live transport is runner-side."
        }),
    }
}

fn trim_optional_string(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn ai_package_selector_from_model(model: &str) -> AiPackageSelectorV1 {
    let model = model.trim().to_string();
    if looks_like_storage_ref(&model) {
        AiPackageSelectorV1 {
            package_ref: Some(model),
            ..AiPackageSelectorV1::default()
        }
    } else {
        AiPackageSelectorV1 {
            model: Some(model),
            ..AiPackageSelectorV1::default()
        }
    }
}

fn provider_requester(metadata: &Value, default_requester: impl Into<String>) -> String {
    requester_from_metadata_value(metadata).unwrap_or_else(|| default_requester.into())
}

fn ai_sampling_options(
    temperature: Option<f64>,
    top_p: Option<f64>,
    max_output_tokens: Option<u64>,
) -> Option<AiSamplingOptionsV1> {
    if temperature.is_none() && top_p.is_none() && max_output_tokens.is_none() {
        return None;
    }
    Some(AiSamplingOptionsV1 {
        temperature,
        top_p,
        max_output_tokens,
        seed: None,
        stop: Vec::new(),
    })
}

fn ai_text_part_from_value(value: Value) -> AiInputPartV1 {
    AiInputPartV1 {
        part_type: AiInputPartType::Text,
        content: value,
        content_ref: None,
        mime_type: Some("text/plain".to_string()),
        hash: None,
        metadata: json!({}),
    }
}

fn ai_text_parts_from_text(text: String) -> Vec<AiInputPartV1> {
    if text.trim().is_empty() {
        Vec::new()
    } else {
        vec![AiInputPartV1::text(text)]
    }
}

fn provider_metadata_with_payload(mut metadata: Value, provider: &str, payload: Value) -> Value {
    if !metadata.is_object() {
        metadata = json!({ "value": metadata });
    }
    metadata[provider] = payload;
    metadata
}

fn requester_from_metadata_value(metadata: &Value) -> Option<String> {
    metadata_string_value(metadata, &["requester", "user", "owner"])
}

fn metadata_string_value(metadata: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| metadata.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn gemini_live_modalities(values: &[String], default: &[Modality]) -> Vec<Modality> {
    let mut modalities: Vec<Modality> = values
        .iter()
        .filter_map(|value| modality_from_provider_name(value))
        .collect();
    if modalities.is_empty() {
        modalities = default.to_vec();
    }
    dedup_modalities(&mut modalities);
    modalities
}

fn modality_from_provider_name(value: &str) -> Option<Modality> {
    match normalize_wire_name(value).as_str() {
        "text" => Some(Modality::Text),
        "chat" | "message" | "messages" => Some(Modality::Chat),
        "audio" | "voice" => Some(Modality::Audio),
        "image" | "vision" => Some(Modality::Image),
        "video" => Some(Modality::Video),
        "document" => Some(Modality::Document),
        "file" => Some(Modality::File),
        "tool" | "tool_call" | "function" | "function_call" => Some(Modality::ToolCall),
        "structured_output" | "json" => Some(Modality::StructuredOutput),
        _ => None,
    }
}

fn gemini_modality_name(modality: &Modality) -> String {
    match modality {
        Modality::Text => "text",
        Modality::Chat => "chat",
        Modality::StructuredOutput => "structured_output",
        Modality::Embedding => "embedding",
        Modality::Image => "image",
        Modality::Audio => "audio",
        Modality::Video => "video",
        Modality::Document => "document",
        Modality::File => "file",
        Modality::ToolCall => "tool_call",
        Modality::BrowserAction => "browser_action",
        Modality::VectorSearch => "vector_search",
        Modality::TrainingData => "training_data",
        Modality::EvaluationData => "evaluation_data",
    }
    .to_string()
}

fn realtime_transport_from_str(value: &str) -> Option<RealtimeTransport> {
    match normalize_wire_name(value).as_str() {
        "websocket" | "ws" => Some(RealtimeTransport::Websocket),
        "webrtc" => Some(RealtimeTransport::Webrtc),
        "http_stream" | "http" | "sse" | "server_event_stream" => {
            Some(RealtimeTransport::HttpStream)
        }
        "local" | "loopback" => Some(RealtimeTransport::Local),
        _ => None,
    }
}

fn gemini_transport_name(transport: &RealtimeTransport) -> String {
    match transport {
        RealtimeTransport::Websocket => "websocket",
        RealtimeTransport::Webrtc => "webrtc",
        RealtimeTransport::HttpStream => "http_stream",
        RealtimeTransport::Local => "local",
    }
    .to_string()
}

fn gemini_live_tool_ref(tool: &Value) -> String {
    match tool {
        Value::String(value) => local_or_external_gemini_tool_ref(value),
        Value::Object(object) => object
            .get("toolRef")
            .or_else(|| object.get("tool_ref"))
            .or_else(|| object.get("ref"))
            .or_else(|| object.get("$ref"))
            .or_else(|| object.get("name"))
            .or_else(|| object.get("type"))
            .and_then(Value::as_str)
            .map(local_or_external_gemini_tool_ref)
            .unwrap_or_else(|| {
                format!(
                    "local://gemini/live/tools/{}",
                    stable_provider_id("tool", tool)
                )
            }),
        _ => format!(
            "local://gemini/live/tools/{}",
            stable_provider_id("tool", tool)
        ),
    }
}

fn local_or_external_gemini_tool_ref(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "local://gemini/live/tools/unknown".to_string()
    } else if looks_like_storage_ref(value) {
        value.to_string()
    } else {
        format!("local://gemini/live/tools/{}", normalize_wire_name(value))
    }
}

fn gemini_privacy_tier(value: Option<&str>, metadata: &Value) -> PrivacyTier {
    value
        .or_else(|| {
            metadata
                .get("privacyTier")
                .or_else(|| metadata.get("privacy_tier"))
                .and_then(Value::as_str)
        })
        .map(privacy_tier_from_str)
        .unwrap_or(PrivacyTier::Standard)
}

fn privacy_tier_from_str(value: &str) -> PrivacyTier {
    match normalize_wire_name(value).as_str() {
        "local_only" => PrivacyTier::LocalOnly,
        "redacted_input" => PrivacyTier::RedactedInput,
        "no_log" => PrivacyTier::NoLog,
        "tee_confidential" => PrivacyTier::TeeConfidential,
        "fhe_encrypted" => PrivacyTier::FheEncrypted,
        "mpc_experimental" => PrivacyTier::MpcExperimental,
        _ => PrivacyTier::Standard,
    }
}

fn looks_like_storage_ref(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("sha256://")
        || value.starts_with("https://")
        || value.starts_with("swarm://")
}

fn normalize_wire_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

fn dedup_modalities(values: &mut Vec<Modality>) {
    let mut seen = Vec::new();
    values.retain(|value| {
        if seen.iter().any(|seen_value| seen_value == value) {
            false
        } else {
            seen.push(value.clone());
            true
        }
    });
}

fn stable_provider_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("provider compatibility value should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn latest_anthropic_user_text(messages: &[AnthropicMessageV1]) -> String {
    messages
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .or_else(|| messages.last())
        .map(|message| anthropic_content_text(&message.content))
        .unwrap_or_default()
}

fn anthropic_prompt_text(request: &AnthropicMessageRequestV1) -> String {
    let mut parts = Vec::new();
    if let Some(system) = &request.system {
        parts.push(anthropic_content_text(system));
    }
    parts.extend(
        request
            .messages
            .iter()
            .map(|message| anthropic_content_text(&message.content)),
    );
    parts.join(" ")
}

fn anthropic_content_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join(" "),
        Value::Object(object) => object
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| Value::Object(object.clone()).to_string()),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn latest_gemini_user_text(contents: &[GeminiContentV1]) -> String {
    contents
        .iter()
        .rev()
        .find(|content| content.role.as_deref() == Some("user"))
        .or_else(|| contents.last())
        .map(gemini_content_text)
        .unwrap_or_default()
}

fn gemini_prompt_text(request: &GeminiGenerateContentRequestV1) -> String {
    let mut parts = Vec::new();
    if let Some(system) = &request.system_instruction {
        parts.push(gemini_content_text(system));
    }
    parts.extend(request.contents.iter().map(gemini_content_text));
    parts.join(" ")
}

fn gemini_content_text(content: &GeminiContentV1) -> String {
    content
        .parts
        .iter()
        .filter_map(|part| part.text.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
}

fn response_message_content(response: &ExecutionResponseV1) -> String {
    response
        .output
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            response
                .output
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| response.output.to_string())
}

fn response_embedding(response: &ExecutionResponseV1) -> Vec<f32> {
    response
        .output
        .get("embedding")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_f64)
                .map(|value| value as f32)
                .collect()
        })
        .unwrap_or_default()
}

fn huggingface_task(request: &HuggingFaceInferenceRequestV1) -> String {
    request
        .task
        .as_deref()
        .map(str::trim)
        .filter(|task| !task.is_empty())
        .unwrap_or_else(|| infer_huggingface_task(&request.inputs))
        .to_string()
}

fn infer_huggingface_task(inputs: &Value) -> &'static str {
    match inputs {
        Value::Array(_) => "feature-extraction",
        _ => "text-generation",
    }
}

fn execution_task_for_huggingface_task(task: &str) -> &'static str {
    match task {
        "feature-extraction" | "sentence-similarity" | "embedding" | "embeddings" => "embedding",
        "text-classification" | "zero-shot-classification" | "classification" => "classification",
        _ => "chat",
    }
}

fn huggingface_input_text(inputs: &Value) -> String {
    match inputs {
        Value::String(text) => text.clone(),
        Value::Array(values) => values
            .iter()
            .map(huggingface_input_text)
            .collect::<Vec<_>>()
            .join(" "),
        Value::Object(object) => object
            .get("text")
            .or_else(|| object.get("inputs"))
            .map(huggingface_input_text)
            .unwrap_or_else(|| Value::Object(object.clone()).to_string()),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn count_tokens(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let null_keys = object
                .iter()
                .filter_map(|(key, value)| value.is_null().then(|| key.clone()))
                .collect::<Vec<_>>();
            for key in null_keys {
                object.remove(&key);
            }
            for value in object.values_mut() {
                strip_nulls(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                strip_nulls(value);
            }
        }
        _ => {}
    }
}

pub fn compact_json(mut value: Value) -> Value {
    strip_nulls(&mut value);
    if let Value::Object(object) = &mut value {
        remove_empty_objects(object);
    }
    value
}

fn remove_empty_objects(object: &mut Map<String, Value>) {
    let empty_keys = object
        .iter()
        .filter_map(|(key, value)| match value {
            Value::Object(object) if object.is_empty() => Some(key.clone()),
            Value::Array(values) if values.is_empty() => Some(key.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for key in empty_keys {
        object.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{ExecutionMetrics, ExecutionResponseV1};

    #[test]
    fn maps_anthropic_messages_to_execution_and_response() {
        let request = AnthropicMessageRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            messages: vec![AnthropicMessageV1 {
                role: "user".to_string(),
                content: json!([
                    { "type": "text", "text": "hello" },
                    { "type": "text", "text": "from anthropic" }
                ]),
            }],
            system: Some(json!("Be concise")),
            stream: false,
            max_tokens: Some(64),
            temperature: Some(0.2),
            metadata: json!({ "requester": "local-dev" }),
        };
        let execution = anthropic_messages_to_execution(
            &request,
            "bzz://package",
            "hivemind/hello-chat",
            "0.1.0",
            "msg-1",
        );
        assert_eq!(execution.task, "chat");
        assert_eq!(execution.input["apiSurface"], "anthropic_messages");
        assert_eq!(execution.input["text"], "hello from anthropic");

        let response = ExecutionResponseV1::succeeded(
            "msg-1",
            json!({ "message": { "content": "answer" } }),
            ExecutionMetrics {
                input_tokens: Some(2),
                output_tokens: Some(1),
                ..ExecutionMetrics::default()
            },
        );
        let message = anthropic_message_from_execution(&request, &response, "msg-out");
        assert_eq!(message.content[0].text, "answer");
        assert_eq!(message.usage.input_tokens, 2);
        assert_eq!(message.usage.output_tokens, 1);
    }

    #[test]
    fn projects_anthropic_messages_to_native_ai_request() {
        let request = AnthropicMessageRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            messages: vec![AnthropicMessageV1 {
                role: "user".to_string(),
                content: json!("hello native ai request"),
            }],
            system: Some(json!("Be concise")),
            stream: true,
            max_tokens: Some(64),
            temperature: Some(0.2),
            metadata: json!({ "requester": "anthropic-user" }),
        };

        let mut ai = anthropic_messages_to_ai_request(&request, "ai-anthropic", "fallback");
        hivemind_core::sign_ai_request(&mut ai).unwrap();
        let verification = hivemind_core::verify_ai_request(&ai);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(ai.requester, "anthropic-user");
        assert_eq!(ai.api_surface, ApiSurface::AnthropicMessages);
        assert_eq!(
            ai.package_selector.model.as_deref(),
            Some("hivemind/hello-chat")
        );
        assert_eq!(ai.inputs[0].content, "hello native ai request");
        assert_eq!(ai.messages.as_ref().unwrap()[0]["role"], "user");
        assert!(ai.stream);
        assert_eq!(ai.sampling.as_ref().unwrap().max_output_tokens, Some(64));
    }

    #[test]
    fn maps_gemini_generate_content_to_execution_and_response() {
        let request = GeminiGenerateContentRequestV1 {
            model: Some("hivemind/hello-chat".to_string()),
            contents: vec![GeminiContentV1 {
                role: Some("user".to_string()),
                parts: vec![GeminiPartV1 {
                    text: Some("hello gemini".to_string()),
                    inline_data: None,
                    file_data: None,
                }],
            }],
            system_instruction: None,
            generation_config: Some(GeminiGenerationConfigV1 {
                max_output_tokens: Some(32),
                temperature: Some(0.4),
                top_p: None,
            }),
            safety_settings: Vec::new(),
            tools: Vec::new(),
            metadata: json!({ "requester": "local-dev" }),
        };
        let model = gemini_model_from_request(&request).unwrap();
        let execution = gemini_generate_content_to_execution(
            &request,
            model.clone(),
            "bzz://package",
            "hivemind/hello-chat",
            "0.1.0",
            "gem-1",
        );
        assert_eq!(execution.task, "chat");
        assert_eq!(execution.input["apiSurface"], "gemini_generate_content");
        assert_eq!(execution.input["text"], "hello gemini");

        let response = ExecutionResponseV1::succeeded(
            "gem-1",
            json!({ "message": { "content": "gemini answer" } }),
            ExecutionMetrics {
                input_tokens: Some(2),
                output_tokens: Some(2),
                ..ExecutionMetrics::default()
            },
        );
        let generated = gemini_generate_content_from_execution(model, &request, &response);
        assert_eq!(
            generated.candidates[0].content.parts[0].text.as_deref(),
            Some("gemini answer")
        );
        assert_eq!(generated.usage_metadata.total_token_count, 4);
    }

    #[test]
    fn projects_gemini_generate_content_to_native_ai_request() {
        let request = GeminiGenerateContentRequestV1 {
            model: Some("hivemind/hello-chat".to_string()),
            contents: vec![GeminiContentV1 {
                role: Some("user".to_string()),
                parts: vec![GeminiPartV1 {
                    text: Some("hello gemini native".to_string()),
                    inline_data: None,
                    file_data: None,
                }],
            }],
            system_instruction: None,
            generation_config: Some(GeminiGenerationConfigV1 {
                max_output_tokens: Some(32),
                temperature: Some(0.4),
                top_p: Some(0.9),
            }),
            safety_settings: Vec::new(),
            tools: vec![json!({ "name": "lookup" })],
            metadata: json!({ "requester": "gemini-user" }),
        };

        let mut ai = gemini_generate_content_to_ai_request(
            &request,
            "hivemind/hello-chat",
            "ai-gemini",
            "fallback",
        );
        hivemind_core::sign_ai_request(&mut ai).unwrap();
        let verification = hivemind_core::verify_ai_request(&ai);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(ai.requester, "gemini-user");
        assert_eq!(ai.api_surface, ApiSurface::GeminiGenerateContent);
        assert_eq!(ai.inputs[0].content, "hello gemini native");
        assert_eq!(ai.tools.as_ref().unwrap()[0]["name"], "lookup");
        assert_eq!(ai.sampling.as_ref().unwrap().top_p, Some(0.9));
        assert_eq!(
            ai.metadata["gemini"]["compatTask"],
            "gemini_generate_content"
        );
    }

    #[test]
    fn maps_gemini_live_request_to_realtime_session_contract() {
        let request = GeminiLiveSessionCreateRequestV1 {
            model: Some("hivemind/realtime".to_string()),
            system_instruction: None,
            generation_config: Some(GeminiGenerationConfigV1 {
                max_output_tokens: Some(64),
                temperature: Some(0.3),
                top_p: None,
            }),
            input_modalities: vec!["audio".to_string(), "text".to_string()],
            response_modalities: vec!["audio".to_string(), "text".to_string()],
            speech_config: None,
            realtime_input_config: None,
            session_resumption: None,
            context_window_compression: None,
            tools: vec![json!({ "name": "lookup" })],
            package_ref: None,
            package_id: None,
            package_version: None,
            service_ref: None,
            transport: Some("websocket".to_string()),
            latency_target_ms: Some(150),
            interruptions_allowed: Some(true),
            privacy_tier: Some("no_log".to_string()),
            settlement_method: None,
            metadata: json!({ "requester": "local-dev" }),
        };

        let record = gemini_live_session_record_from_request(&request, "fallback");
        let response = gemini_live_session_from_record(&record);

        assert_eq!(
            record.schema_version,
            "swarm-ai.gemini-live-session-record.v1"
        );
        assert_eq!(record.session.requester, "local-dev");
        assert_eq!(
            record.session.package_selector.model_alias.as_deref(),
            Some("hivemind/realtime")
        );
        assert!(verify_realtime_session(&record.session).valid);
        assert_eq!(response.state, "CREATED");
        assert_eq!(response.transport, "websocket");
        assert_eq!(
            response.hivemind_metadata["plan"]["apiSurface"],
            "gemini_live"
        );
        assert_eq!(response.input_modalities, vec!["audio", "text"]);
        assert!(response.connection_uri.starts_with("local://realtime/"));
    }

    #[test]
    fn projects_gemini_live_session_to_native_ai_request() {
        let request = GeminiLiveSessionCreateRequestV1 {
            model: Some("hivemind/realtime".to_string()),
            system_instruction: None,
            generation_config: Some(GeminiGenerationConfigV1 {
                max_output_tokens: Some(64),
                temperature: Some(0.3),
                top_p: None,
            }),
            input_modalities: vec!["audio".to_string(), "text".to_string()],
            response_modalities: vec!["audio".to_string(), "text".to_string()],
            speech_config: None,
            realtime_input_config: None,
            session_resumption: None,
            context_window_compression: None,
            tools: Vec::new(),
            package_ref: None,
            package_id: None,
            package_version: None,
            service_ref: None,
            transport: Some("websocket".to_string()),
            latency_target_ms: Some(150),
            interruptions_allowed: Some(true),
            privacy_tier: Some("no_log".to_string()),
            settlement_method: None,
            metadata: json!({ "requester": "live-user" }),
        };

        let mut ai =
            gemini_live_session_to_ai_request(&request, "hivemind/realtime", "ai-live", "fallback");
        hivemind_core::sign_ai_request(&mut ai).unwrap();
        let verification = hivemind_core::verify_ai_request(&ai);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(ai.requester, "live-user");
        assert_eq!(ai.api_surface, ApiSurface::GeminiLive);
        assert_eq!(ai.task.as_deref(), Some("realtime"));
        assert!(ai.stream);
        assert_eq!(ai.constraints.max_latency_ms, Some(150));
        assert_eq!(ai.privacy.privacy_tier, PrivacyTier::NoLog);
        assert_eq!(
            ai.response_format.as_ref().unwrap()["transport"],
            "websocket"
        );
    }

    #[test]
    fn maps_huggingface_text_generation_to_execution_and_response() {
        let request = HuggingFaceInferenceRequestV1 {
            model: Some("hivemind/hello-chat".to_string()),
            inputs: json!("hello huggingface"),
            parameters: json!({ "max_new_tokens": 32 }),
            options: json!({ "wait_for_model": true }),
            task: Some("text-generation".to_string()),
            metadata: json!({ "requester": "local-dev" }),
        };
        let model = huggingface_model_from_request(&request).unwrap();
        let execution = huggingface_inference_to_execution(
            &request,
            model.clone(),
            "bzz://package",
            "hivemind/hello-chat",
            "0.1.0",
            "hf-1",
        );
        assert_eq!(execution.task, "chat");
        assert_eq!(execution.input["apiSurface"], "huggingface_inference");
        assert_eq!(execution.input["text"], "hello huggingface");

        let response = ExecutionResponseV1::succeeded(
            "hf-1",
            json!({ "message": { "content": "hf answer" } }),
            ExecutionMetrics::default(),
        );
        let generated = huggingface_inference_from_execution(model, &request, &response);
        assert_eq!(generated.results[0]["generated_text"], "hf answer");
    }

    #[test]
    fn projects_huggingface_inference_to_native_ai_request() {
        let request = HuggingFaceInferenceRequestV1 {
            model: Some("hivemind/hello-embedding".to_string()),
            inputs: json!(["hello", "embedding"]),
            parameters: json!({}),
            options: json!({}),
            task: Some("feature-extraction".to_string()),
            metadata: json!({ "requester": "hf-user" }),
        };

        let mut ai = huggingface_inference_to_ai_request(
            &request,
            "hivemind/hello-embedding",
            "ai-hf",
            "fallback",
        );
        hivemind_core::sign_ai_request(&mut ai).unwrap();
        let verification = hivemind_core::verify_ai_request(&ai);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(ai.requester, "hf-user");
        assert_eq!(ai.api_surface, ApiSurface::HuggingFaceInference);
        assert_eq!(ai.task.as_deref(), Some("embedding"));
        assert_eq!(ai.inputs[0].content, "hello embedding");
        assert_eq!(
            ai.metadata["huggingface"]["compatTask"],
            "huggingface_inference"
        );
    }

    #[test]
    fn maps_huggingface_feature_extraction_to_embedding_response() {
        let request = HuggingFaceInferenceRequestV1 {
            model: Some("hivemind/hello-embedding".to_string()),
            inputs: json!(["hello", "embedding"]),
            parameters: json!({}),
            options: json!({}),
            task: Some("feature-extraction".to_string()),
            metadata: json!({}),
        };
        let model = huggingface_model_from_request(&request).unwrap();
        let execution = huggingface_inference_to_execution(
            &request,
            model.clone(),
            "bzz://package",
            "hivemind/hello-embedding",
            "0.1.0",
            "hf-embed-1",
        );
        assert_eq!(execution.task, "embedding");
        assert_eq!(execution.input["text"], "hello embedding");

        let response = ExecutionResponseV1::succeeded(
            "hf-embed-1",
            json!({ "embedding": [0.1, -0.2, 0.3] }),
            ExecutionMetrics::default(),
        );
        let generated = huggingface_inference_from_execution(model, &request, &response);
        assert!(
            (generated.results[0][0].as_f64().unwrap() - 0.1).abs() < 0.00001,
            "first embedding value should round-trip approximately"
        );
        assert!(
            (generated.results[0][1].as_f64().unwrap() + 0.2).abs() < 0.00001,
            "second embedding value should round-trip approximately"
        );
    }
}
