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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StandardErrorCodeV1 {
    PackageNotFound,
    PackageVersionNotFound,
    ManifestInvalid,
    SignatureInvalid,
    AccessDenied,
    LicenseNotSatisfied,
    UnsupportedApi,
    UnsupportedModality,
    UnsupportedRuntime,
    UnsupportedModelFormat,
    InsufficientMemory,
    InsufficientVram,
    NoRunnerAvailable,
    QuoteExpired,
    LeaseInvalid,
    LeaseExpired,
    RunnerTimeout,
    RunnerUnhealthy,
    StreamInterrupted,
    PolicyBlocked,
    ValidationFailed,
    ReceiptInvalid,
    PaymentFailed,
    SettlementFailed,
    DisputeOpened,
    StorageUnavailable,
    ArtifactMissing,
    ArtifactHashMismatch,
    RateLimited,
    Cancelled,
    InternalError,
    InvalidRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StandardErrorDefinitionV1 {
    pub code: StandardErrorCodeV1,
    pub category: String,
    #[serde(rename = "httpStatus")]
    pub http_status: u16,
    pub retryable: bool,
    pub terminal: bool,
    pub description: String,
    #[serde(rename = "legacyCodes", default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_codes: Vec<ErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StandardErrorCatalogV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub codes: Vec<StandardErrorDefinitionV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SwarmAiErrorV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub code: ErrorCode,
    #[serde(
        rename = "standardCode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub standard_code: Option<StandardErrorCodeV1>,
    pub message: String,
    #[serde(default)]
    pub details: Value,
}

impl SwarmAiErrorV1 {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            schema_version: "swarm-ai.error.v1".to_string(),
            code,
            standard_code: Some(standard_error_code_for_error_code(code)),
            message: message.into(),
            details: json!({}),
        }
    }

    pub fn standard_code(&self) -> StandardErrorCodeV1 {
        self.standard_code
            .unwrap_or_else(|| standard_error_code_for_error_code(self.code))
    }

    pub fn with_standard_code(mut self, standard_code: StandardErrorCodeV1) -> Self {
        self.standard_code = Some(standard_code);
        self
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

pub fn standard_error_code_for_error_code(code: ErrorCode) -> StandardErrorCodeV1 {
    match code {
        ErrorCode::PackageNotFound => StandardErrorCodeV1::PackageNotFound,
        ErrorCode::UnsupportedTarget => StandardErrorCodeV1::NoRunnerAvailable,
        ErrorCode::InvalidManifest => StandardErrorCodeV1::ManifestInvalid,
        ErrorCode::AccessDenied => StandardErrorCodeV1::AccessDenied,
        ErrorCode::RunnerOverloaded => StandardErrorCodeV1::RunnerUnhealthy,
        ErrorCode::DeadlineExceeded => StandardErrorCodeV1::RunnerTimeout,
        ErrorCode::ExecutionFailed => StandardErrorCodeV1::InternalError,
        ErrorCode::ValidationFailed => StandardErrorCodeV1::ValidationFailed,
        ErrorCode::UnsupportedOperation => StandardErrorCodeV1::UnsupportedApi,
        ErrorCode::InvalidRequest => StandardErrorCodeV1::InvalidRequest,
    }
}

pub fn legacy_error_code_for_standard_code(code: StandardErrorCodeV1) -> ErrorCode {
    match code {
        StandardErrorCodeV1::PackageNotFound | StandardErrorCodeV1::PackageVersionNotFound => {
            ErrorCode::PackageNotFound
        }
        StandardErrorCodeV1::ManifestInvalid
        | StandardErrorCodeV1::SignatureInvalid
        | StandardErrorCodeV1::ArtifactHashMismatch => ErrorCode::InvalidManifest,
        StandardErrorCodeV1::AccessDenied
        | StandardErrorCodeV1::LicenseNotSatisfied
        | StandardErrorCodeV1::PolicyBlocked => ErrorCode::AccessDenied,
        StandardErrorCodeV1::UnsupportedApi
        | StandardErrorCodeV1::UnsupportedModality
        | StandardErrorCodeV1::UnsupportedRuntime
        | StandardErrorCodeV1::UnsupportedModelFormat
        | StandardErrorCodeV1::InsufficientMemory
        | StandardErrorCodeV1::InsufficientVram
        | StandardErrorCodeV1::NoRunnerAvailable => ErrorCode::UnsupportedTarget,
        StandardErrorCodeV1::QuoteExpired
        | StandardErrorCodeV1::LeaseExpired
        | StandardErrorCodeV1::RunnerTimeout => ErrorCode::DeadlineExceeded,
        StandardErrorCodeV1::RunnerUnhealthy | StandardErrorCodeV1::RateLimited => {
            ErrorCode::RunnerOverloaded
        }
        StandardErrorCodeV1::ValidationFailed | StandardErrorCodeV1::ReceiptInvalid => {
            ErrorCode::ValidationFailed
        }
        StandardErrorCodeV1::InvalidRequest | StandardErrorCodeV1::LeaseInvalid => {
            ErrorCode::InvalidRequest
        }
        StandardErrorCodeV1::StreamInterrupted
        | StandardErrorCodeV1::PaymentFailed
        | StandardErrorCodeV1::SettlementFailed
        | StandardErrorCodeV1::DisputeOpened
        | StandardErrorCodeV1::StorageUnavailable
        | StandardErrorCodeV1::ArtifactMissing
        | StandardErrorCodeV1::Cancelled
        | StandardErrorCodeV1::InternalError => ErrorCode::ExecutionFailed,
    }
}

pub fn standard_error_catalog() -> StandardErrorCatalogV1 {
    StandardErrorCatalogV1 {
        schema_version: "hivemind.standard-error-catalog.v1".to_string(),
        codes: all_standard_error_codes()
            .into_iter()
            .map(standard_error_definition)
            .collect(),
    }
}

pub fn all_standard_error_codes() -> Vec<StandardErrorCodeV1> {
    vec![
        StandardErrorCodeV1::PackageNotFound,
        StandardErrorCodeV1::PackageVersionNotFound,
        StandardErrorCodeV1::ManifestInvalid,
        StandardErrorCodeV1::SignatureInvalid,
        StandardErrorCodeV1::AccessDenied,
        StandardErrorCodeV1::LicenseNotSatisfied,
        StandardErrorCodeV1::UnsupportedApi,
        StandardErrorCodeV1::UnsupportedModality,
        StandardErrorCodeV1::UnsupportedRuntime,
        StandardErrorCodeV1::UnsupportedModelFormat,
        StandardErrorCodeV1::InsufficientMemory,
        StandardErrorCodeV1::InsufficientVram,
        StandardErrorCodeV1::NoRunnerAvailable,
        StandardErrorCodeV1::QuoteExpired,
        StandardErrorCodeV1::LeaseInvalid,
        StandardErrorCodeV1::LeaseExpired,
        StandardErrorCodeV1::RunnerTimeout,
        StandardErrorCodeV1::RunnerUnhealthy,
        StandardErrorCodeV1::StreamInterrupted,
        StandardErrorCodeV1::PolicyBlocked,
        StandardErrorCodeV1::ValidationFailed,
        StandardErrorCodeV1::ReceiptInvalid,
        StandardErrorCodeV1::PaymentFailed,
        StandardErrorCodeV1::SettlementFailed,
        StandardErrorCodeV1::DisputeOpened,
        StandardErrorCodeV1::StorageUnavailable,
        StandardErrorCodeV1::ArtifactMissing,
        StandardErrorCodeV1::ArtifactHashMismatch,
        StandardErrorCodeV1::RateLimited,
        StandardErrorCodeV1::Cancelled,
        StandardErrorCodeV1::InternalError,
        StandardErrorCodeV1::InvalidRequest,
    ]
}

pub fn standard_error_definition(code: StandardErrorCodeV1) -> StandardErrorDefinitionV1 {
    let (category, http_status, retryable, terminal, description) = match code {
        StandardErrorCodeV1::PackageNotFound => (
            "resolution",
            404,
            false,
            true,
            "The requested package, model, service, job, or evidence record was not found.",
        ),
        StandardErrorCodeV1::PackageVersionNotFound => (
            "resolution",
            404,
            false,
            true,
            "The requested package exists, but the requested version or channel could not be resolved.",
        ),
        StandardErrorCodeV1::ManifestInvalid => (
            "package",
            422,
            false,
            true,
            "A package, job, policy, or interface manifest failed structural validation.",
        ),
        StandardErrorCodeV1::SignatureInvalid => (
            "integrity",
            422,
            false,
            true,
            "A signature, stable id, or signed envelope failed verification.",
        ),
        StandardErrorCodeV1::AccessDenied => (
            "access",
            403,
            false,
            true,
            "The requester does not have the required access grant, entitlement, or runner scope.",
        ),
        StandardErrorCodeV1::LicenseNotSatisfied => (
            "access",
            402,
            false,
            true,
            "The package license requires payment, subscription, grant, or approval that was not supplied.",
        ),
        StandardErrorCodeV1::UnsupportedApi => (
            "compatibility",
            400,
            false,
            true,
            "No selected package or runner supports the requested API surface.",
        ),
        StandardErrorCodeV1::UnsupportedModality => (
            "compatibility",
            400,
            false,
            true,
            "No selected package or runner supports the requested modality.",
        ),
        StandardErrorCodeV1::UnsupportedRuntime => (
            "compatibility",
            400,
            false,
            true,
            "No selected artifact group or runner supports the requested runtime.",
        ),
        StandardErrorCodeV1::UnsupportedModelFormat => (
            "compatibility",
            400,
            false,
            true,
            "No selected artifact group or runner supports the requested model format.",
        ),
        StandardErrorCodeV1::InsufficientMemory => (
            "capacity",
            409,
            false,
            true,
            "The selected runner does not have enough system memory for the request.",
        ),
        StandardErrorCodeV1::InsufficientVram => (
            "capacity",
            409,
            false,
            true,
            "The selected runner does not have enough GPU memory for the request.",
        ),
        StandardErrorCodeV1::NoRunnerAvailable => (
            "routing",
            503,
            true,
            false,
            "No current runner, route, or miner offer satisfies the request and policy.",
        ),
        StandardErrorCodeV1::QuoteExpired => (
            "marketplace",
            409,
            true,
            false,
            "The selected quote expired before a lease or execution could proceed.",
        ),
        StandardErrorCodeV1::LeaseInvalid => (
            "execution",
            422,
            false,
            true,
            "The execution lease is malformed, mismatched, revoked, or outside its limits.",
        ),
        StandardErrorCodeV1::LeaseExpired => (
            "execution",
            409,
            true,
            false,
            "The execution lease expired before the runner completed the job.",
        ),
        StandardErrorCodeV1::RunnerTimeout => (
            "execution",
            504,
            true,
            false,
            "The selected runner did not respond or complete within the deadline.",
        ),
        StandardErrorCodeV1::RunnerUnhealthy => (
            "execution",
            503,
            true,
            false,
            "The selected runner is overloaded, unhealthy, or temporarily unavailable.",
        ),
        StandardErrorCodeV1::StreamInterrupted => (
            "streaming",
            502,
            true,
            false,
            "The streaming response was interrupted before terminal completion.",
        ),
        StandardErrorCodeV1::PolicyBlocked => (
            "policy",
            403,
            false,
            true,
            "Trust, privacy, security, or moderation policy blocked the request.",
        ),
        StandardErrorCodeV1::ValidationFailed => (
            "validation",
            422,
            false,
            true,
            "Required validation, replay, challenge, or proof checks failed.",
        ),
        StandardErrorCodeV1::ReceiptInvalid => (
            "audit",
            422,
            false,
            true,
            "The receipt is missing, malformed, mismatched, or failed integrity checks.",
        ),
        StandardErrorCodeV1::PaymentFailed => (
            "settlement",
            402,
            true,
            false,
            "Payment authorization, reservation, or transfer failed.",
        ),
        StandardErrorCodeV1::SettlementFailed => (
            "settlement",
            409,
            true,
            false,
            "Receipt-linked settlement, refund, or payout failed.",
        ),
        StandardErrorCodeV1::DisputeOpened => (
            "settlement",
            409,
            false,
            false,
            "Execution or settlement entered a dispute flow and is awaiting resolution.",
        ),
        StandardErrorCodeV1::StorageUnavailable => (
            "storage",
            503,
            true,
            false,
            "The configured storage provider, Bee node, or gateway is unavailable.",
        ),
        StandardErrorCodeV1::ArtifactMissing => (
            "storage",
            404,
            true,
            false,
            "A package artifact or referenced file could not be retrieved.",
        ),
        StandardErrorCodeV1::ArtifactHashMismatch => (
            "integrity",
            422,
            false,
            true,
            "A downloaded artifact did not match the expected content hash.",
        ),
        StandardErrorCodeV1::RateLimited => (
            "capacity",
            429,
            true,
            false,
            "The requester, route, runner, or gateway is rate limited.",
        ),
        StandardErrorCodeV1::Cancelled => (
            "execution",
            499,
            false,
            true,
            "The user, system, or runner cancelled execution.",
        ),
        StandardErrorCodeV1::InternalError => (
            "internal",
            500,
            true,
            false,
            "An unexpected internal failure occurred.",
        ),
        StandardErrorCodeV1::InvalidRequest => (
            "request",
            400,
            false,
            true,
            "The request is malformed or missing required fields.",
        ),
    };

    let legacy_code = legacy_error_code_for_standard_code(code);
    StandardErrorDefinitionV1 {
        code,
        category: category.to_string(),
        http_status,
        retryable,
        terminal,
        description: description.to_string(),
        legacy_codes: vec![legacy_code],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_error_catalog_contains_v02_codes() {
        let catalog = standard_error_catalog();

        assert_eq!(catalog.schema_version, "hivemind.standard-error-catalog.v1");
        assert!(catalog.codes.len() >= 31);
        assert!(
            catalog
                .codes
                .iter()
                .any(|definition| definition.code == StandardErrorCodeV1::LeaseExpired)
        );
        assert!(
            catalog
                .codes
                .iter()
                .any(|definition| definition.code == StandardErrorCodeV1::ArtifactHashMismatch)
        );
    }

    #[test]
    fn swarm_error_carries_standard_code_without_losing_legacy_code() {
        let error = SwarmAiErrorV1::new(ErrorCode::AccessDenied, "blocked");

        assert_eq!(error.code, ErrorCode::AccessDenied);
        assert_eq!(error.standard_code(), StandardErrorCodeV1::AccessDenied);
        assert_eq!(
            serde_json::to_value(&error).unwrap()["standardCode"],
            json!("access_denied")
        );
    }

    #[test]
    fn legacy_errors_without_standard_code_are_mapped() {
        let value = json!({
            "schemaVersion": "swarm-ai.error.v1",
            "code": "DEADLINE_EXCEEDED",
            "message": "timeout",
            "details": {}
        });

        let error: SwarmAiErrorV1 = serde_json::from_value(value).unwrap();

        assert_eq!(error.standard_code, None);
        assert_eq!(error.standard_code(), StandardErrorCodeV1::RunnerTimeout);
    }
}
