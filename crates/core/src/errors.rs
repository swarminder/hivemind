use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    PackageNotFound,
    UnsupportedTarget,
    InvalidManifest,
    AccessDenied,
    RunnerOverloaded,
    DeadlineExceeded,
    ExecutionFailed,
    ValidationFailed,
    UnsupportedOperation,
    InvalidRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SwarmAiErrorV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub details: Value,
}

impl SwarmAiErrorV1 {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            schema_version: "swarm-ai.error.v1".to_string(),
            code,
            message: message.into(),
            details: json!({}),
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }
}

impl fmt::Display for SwarmAiErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0}")]
    Contract(SwarmAiErrorV1),
}
