use hivemind_core::{ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionRequestV1 {
    pub model: String,
    pub messages: Vec<ChatMessageV1>,
    #[serde(default)]
    pub stream: bool,
    #[serde(rename = "max_tokens", default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatMessageV1 {
    pub role: String,
    #[serde(default)]
    pub content: Value,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionResponseV1 {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatCompletionChoiceV1>,
    pub usage: OpenAiUsageV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionChoiceV1 {
    pub index: u32,
    pub message: ChatMessageV1,
    #[serde(rename = "finish_reason")]
    pub finish_reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmbeddingRequestV1 {
    pub model: String,
    pub input: Value,
    #[serde(rename = "encoding_format", default)]
    pub encoding_format: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmbeddingResponseV1 {
    pub object: String,
    pub data: Vec<EmbeddingDataV1>,
    pub model: String,
    pub usage: OpenAiUsageV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmbeddingDataV1 {
    pub object: String,
    pub index: u32,
    pub embedding: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct OpenAiUsageV1 {
    #[serde(rename = "prompt_tokens")]
    pub prompt_tokens: u64,
    #[serde(rename = "completion_tokens")]
    pub completion_tokens: u64,
    #[serde(rename = "total_tokens")]
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiErrorResponseV1 {
    pub error: OpenAiErrorDetailV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiErrorDetailV1 {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(default)]
    pub param: Option<String>,
    pub code: String,
}

pub fn chat_request_to_execution(
    request: &ChatCompletionRequestV1,
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
            "text": latest_message_text(&request.messages),
            "model": request.model,
            "maxOutputTokens": request.max_tokens,
            "temperature": request.temperature,
            "user": request.user,
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

pub fn chat_completion_from_execution(
    request: &ChatCompletionRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
    created: u64,
) -> ChatCompletionResponseV1 {
    let content = response_message_content(response);
    let completion_tokens = response
        .metrics
        .output_tokens
        .unwrap_or_else(|| count_tokens(&content));
    let prompt_tokens = response.metrics.input_tokens.unwrap_or_else(|| {
        request
            .messages
            .iter()
            .map(|message| count_tokens(&message_text(message)))
            .sum()
    });
    ChatCompletionResponseV1 {
        id: id.into(),
        object: "chat.completion".to_string(),
        created,
        model: request.model.clone(),
        choices: vec![ChatCompletionChoiceV1 {
            index: 0,
            message: ChatMessageV1 {
                role: "assistant".to_string(),
                content: Value::String(content),
                name: None,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: OpenAiUsageV1 {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        },
    }
}

pub fn embedding_requests_to_executions(
    request: &EmbeddingRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id_prefix: impl Into<String>,
) -> Vec<ExecutionRequestV1> {
    let package_ref = package_ref.into();
    let package_id = package_id.into();
    let package_version = package_version.into();
    let request_id_prefix = request_id_prefix.into();
    embedding_inputs(&request.input)
        .into_iter()
        .enumerate()
        .map(|(index, input)| ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: if index == 0 {
                request_id_prefix.clone()
            } else {
                format!("{request_id_prefix}-{index}")
            },
            package_ref: package_ref.clone(),
            package_id: package_id.clone(),
            package_version: package_version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input,
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        })
        .collect()
}

pub fn embedding_response_from_executions(
    request: &EmbeddingRequestV1,
    responses: &[ExecutionResponseV1],
) -> EmbeddingResponseV1 {
    let prompt_tokens = responses
        .iter()
        .map(|response| response.metrics.input_tokens.unwrap_or(0))
        .sum();
    EmbeddingResponseV1 {
        object: "list".to_string(),
        data: responses
            .iter()
            .enumerate()
            .map(|(index, response)| EmbeddingDataV1 {
                object: "embedding".to_string(),
                index: index as u32,
                embedding: response_embedding(response),
            })
            .collect(),
        model: request.model.clone(),
        usage: OpenAiUsageV1 {
            prompt_tokens,
            completion_tokens: 0,
            total_tokens: prompt_tokens,
        },
    }
}

pub fn error_response(
    code: impl Into<String>,
    message: impl Into<String>,
) -> OpenAiErrorResponseV1 {
    OpenAiErrorResponseV1 {
        error: OpenAiErrorDetailV1 {
            message: message.into(),
            error_type: "hivemind_compat_error".to_string(),
            param: None,
            code: code.into(),
        },
    }
}

fn embedding_inputs(input: &Value) -> Vec<Value> {
    match input {
        Value::String(text) => vec![json!({ "text": text })],
        Value::Array(values) if values.iter().all(Value::is_string) => values
            .iter()
            .filter_map(Value::as_str)
            .map(|text| json!({ "text": text }))
            .collect(),
        Value::Array(values) if values.iter().all(Value::is_number) => {
            vec![json!({ "tokens": values })]
        }
        other => vec![json!({ "input": other })],
    }
}

fn latest_message_text(messages: &[ChatMessageV1]) -> String {
    messages
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .or_else(|| messages.last())
        .map(message_text)
        .unwrap_or_default()
}

fn message_text(message: &ChatMessageV1) -> String {
    match &message.content {
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
        Value::Null => String::new(),
        other => other.to_string(),
    }
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

fn count_tokens(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{ExecutionMetrics, ExecutionStatus};

    #[test]
    fn maps_chat_request_and_response() {
        let request = ChatCompletionRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            messages: vec![ChatMessageV1 {
                role: "user".to_string(),
                content: Value::String("hello there".to_string()),
                name: None,
            }],
            stream: true,
            max_tokens: Some(64),
            temperature: Some(0.2),
            user: None,
        };

        let execution =
            chat_request_to_execution(&request, "bzz://pkg", "hivemind/hello-chat", "0.1.0", "r1");

        assert_eq!(execution.task, "chat");
        assert!(execution.options.stream);
        assert_eq!(execution.input["text"], "hello there");

        let response = ExecutionResponseV1::succeeded(
            "r1",
            json!({ "message": { "role": "assistant", "content": "hi back" } }),
            ExecutionMetrics {
                input_tokens: Some(2),
                output_tokens: Some(2),
                ..ExecutionMetrics::default()
            },
        );
        let completion = chat_completion_from_execution(&request, &response, "chatcmpl-r1", 1);

        assert_eq!(completion.object, "chat.completion");
        assert_eq!(completion.choices[0].message.content, "hi back");
        assert_eq!(completion.usage.total_tokens, 4);
    }

    #[test]
    fn maps_batched_embedding_request() {
        let request = EmbeddingRequestV1 {
            model: "hivemind/hello-embedding".to_string(),
            input: json!(["alpha", "beta"]),
            encoding_format: None,
            user: None,
        };

        let executions = embedding_requests_to_executions(
            &request,
            "bzz://pkg",
            "hivemind/hello-embedding",
            "0.1.0",
            "embd-1",
        );

        assert_eq!(executions.len(), 2);
        assert_eq!(executions[1].request_id, "embd-1-1");

        let responses: Vec<_> = executions
            .iter()
            .enumerate()
            .map(|(index, execution)| {
                let mut response = ExecutionResponseV1::succeeded(
                    execution.request_id.clone(),
                    json!({ "embedding": [index as f64, 1.0] }),
                    ExecutionMetrics {
                        input_tokens: Some(1),
                        ..ExecutionMetrics::default()
                    },
                );
                response.status = ExecutionStatus::Succeeded;
                response
            })
            .collect();
        let embedding = embedding_response_from_executions(&request, &responses);

        assert_eq!(embedding.object, "list");
        assert_eq!(embedding.data.len(), 2);
        assert_eq!(embedding.data[1].embedding, vec![1.0, 1.0]);
        assert_eq!(embedding.usage.prompt_tokens, 2);
    }
}
