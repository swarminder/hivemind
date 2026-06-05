use crate::canonical::hash_canonical_json;
use crate::errors::{ErrorCode, SwarmAiErrorV1};
use crate::execution::{
    ExecutionMetrics, ExecutionRequestV1, ExecutionResponseV1, ExecutionStatus,
};
use crate::job::{ApiSurface, PriceV1};
use crate::manifest::PackageManifestV1;
use crate::policy::PolicyDecisionV1;
use crate::trust::IntegrityTier;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEV_RECEIPT_SIGNATURE_PREFIX: &str = "dev-signature-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BillingInfo {
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessInfo {
    #[serde(rename = "licenseGrantId", default)]
    pub license_grant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptPolicyEvidenceV1 {
    #[serde(rename = "policyDecisionId")]
    pub policy_decision_id: String,
    #[serde(rename = "policyDecision")]
    pub policy_decision: PolicyDecisionV1,
    #[serde(rename = "enforcedAt")]
    pub enforced_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "artifactGroup")]
    pub artifact_group: String,
    #[serde(rename = "packageManifestHash")]
    pub package_manifest_hash: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "routeId", default)]
    pub route_id: Option<String>,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    #[serde(rename = "outputHash")]
    pub output_hash: String,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    pub metrics: ExecutionMetrics,
    pub billing: BillingInfo,
    pub access: AccessInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ReceiptPolicyEvidenceV1>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ExecutionReceiptV2Context {
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "leaseId", default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(
        rename = "leaseContext",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_context: Option<ExecutionReceiptLeaseContextV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(
        rename = "apiSurface",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub api_surface: Option<ApiSurface>,
    #[serde(rename = "inputModalities", default)]
    pub input_modalities: Vec<String>,
    #[serde(rename = "outputModalities", default)]
    pub output_modalities: Vec<String>,
    #[serde(
        rename = "verificationMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_mode: Option<IntegrityTier>,
    #[serde(
        rename = "routeDecisionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub route_decision_ref: Option<String>,
    #[serde(rename = "traceRef", default, skip_serializing_if = "Option::is_none")]
    pub trace_ref: Option<String>,
    #[serde(rename = "toolCallRefs", default)]
    pub tool_call_refs: Vec<String>,
    #[serde(rename = "retrievalRefs", default)]
    pub retrieval_refs: Vec<String>,
    #[serde(
        rename = "attestationRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub attestation_ref: Option<String>,
    #[serde(rename = "proofRefs", default)]
    pub proof_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ExecutionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SwarmAiErrorV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptLeaseContextV2 {
    #[serde(rename = "quoteId", default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    #[serde(rename = "allowedInputRefs", default)]
    pub allowed_input_refs: Vec<String>,
    #[serde(
        rename = "allowedInputHashes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_input_hashes: Vec<String>,
    #[serde(rename = "allowedPackageRefs", default)]
    pub allowed_package_refs: Vec<String>,
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<PriceV1>,
    #[serde(
        rename = "startAfter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub start_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<String>,
    #[serde(
        rename = "settlementRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptTimingV2 {
    #[serde(rename = "queueMs")]
    pub queue_ms: u64,
    #[serde(rename = "loadMs")]
    pub load_ms: u64,
    #[serde(rename = "computeMs")]
    pub compute_ms: u64,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptUsageV2 {
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptCostV2 {
    pub amount: f64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptErrorV2 {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "leaseId", default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(
        rename = "leaseContext",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_context: Option<ExecutionReceiptLeaseContextV2>,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub requester: String,
    #[serde(rename = "packageRefs")]
    pub package_refs: Vec<String>,
    #[serde(rename = "modelArtifactRefs")]
    pub model_artifact_refs: Vec<String>,
    #[serde(rename = "artifactGroupIds")]
    pub artifact_group_ids: Vec<String>,
    #[serde(rename = "inputHashes")]
    pub input_hashes: Vec<String>,
    #[serde(rename = "outputHashes")]
    pub output_hashes: Vec<String>,
    #[serde(rename = "inputModalities")]
    pub input_modalities: Vec<String>,
    #[serde(rename = "outputModalities")]
    pub output_modalities: Vec<String>,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    pub status: ExecutionStatus,
    pub timing: ExecutionReceiptTimingV2,
    pub usage: ExecutionReceiptUsageV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<ExecutionReceiptCostV2>,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "verificationMode")]
    pub verification_mode: IntegrityTier,
    #[serde(
        rename = "hardwareClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hardware_claim: Option<Value>,
    #[serde(
        rename = "runtimeImageHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub runtime_image_hash: Option<String>,
    #[serde(
        rename = "engineVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub engine_version: Option<String>,
    #[serde(
        rename = "routeDecisionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub route_decision_ref: Option<String>,
    #[serde(rename = "traceRef", default, skip_serializing_if = "Option::is_none")]
    pub trace_ref: Option<String>,
    #[serde(rename = "toolCallRefs")]
    pub tool_call_refs: Vec<String>,
    #[serde(rename = "retrievalRefs")]
    pub retrieval_refs: Vec<String>,
    #[serde(rename = "policyRefs")]
    pub policy_refs: Vec<String>,
    #[serde(rename = "accessGrantRefs")]
    pub access_grant_refs: Vec<String>,
    #[serde(
        rename = "attestationRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub attestation_ref: Option<String>,
    #[serde(rename = "proofRefs")]
    pub proof_refs: Vec<String>,
    pub errors: Vec<ExecutionReceiptErrorV2>,
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReceiptDraft<'a> {
    pub request: &'a ExecutionRequestV1,
    pub response: &'a ExecutionResponseV1,
    pub manifest: &'a PackageManifestV1,
    pub artifact_group: &'a str,
    pub manifest_hash: &'a str,
    pub runner_id: &'a str,
    pub route_id: Option<String>,
    pub policy: Option<ReceiptPolicyEvidenceV1>,
    pub started_at: &'a str,
    pub finished_at: &'a str,
}

pub fn create_unsigned_receipt(draft: ReceiptDraft<'_>) -> ExecutionReceiptV1 {
    create_signed_receipt(draft)
}

pub fn create_signed_receipt(draft: ReceiptDraft<'_>) -> ExecutionReceiptV1 {
    let input_hash = hash_canonical_json(&draft.request.input);
    let output_hash = hash_canonical_json(&draft.response.output);
    let privacy_mode = serde_json::to_value(&draft.request.privacy.receipt_mode)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "hash-only".to_string());

    let mut receipt = ExecutionReceiptV1 {
        schema_version: "swarm-ai.receipt.v1".to_string(),
        receipt_id: String::new(),
        request_id: draft.request.request_id.clone(),
        package_id: draft.manifest.package_id.clone(),
        package_ref: draft.request.package_ref.clone(),
        artifact_group: draft.artifact_group.to_string(),
        package_manifest_hash: draft.manifest_hash.to_string(),
        runner_id: draft.runner_id.to_string(),
        route_id: draft.route_id,
        input_hash,
        output_hash,
        privacy_mode,
        started_at: draft.started_at.to_string(),
        finished_at: draft.finished_at.to_string(),
        metrics: draft.response.metrics.clone(),
        billing: BillingInfo {
            estimated_cost: 0.0,
            currency: "none".to_string(),
        },
        access: AccessInfo {
            license_grant_id: draft
                .request
                .access_grant
                .as_ref()
                .map(|grant| grant.grant_id.clone()),
        },
        policy: draft.policy,
        signature: String::new(),
    };

    sign_receipt(&mut receipt);
    receipt.receipt_id = canonical_receipt_id(&receipt).expect("receipt should serialize");
    receipt
}

pub fn sign_receipt(receipt: &mut ExecutionReceiptV1) {
    receipt.signature = expected_receipt_signature(receipt);
}

pub fn expected_receipt_signature(receipt: &ExecutionReceiptV1) -> String {
    dev_signature(
        "execution-receipt",
        &receipt.runner_id,
        &receipt_signing_value(receipt),
    )
}

pub fn canonical_receipt_id(receipt: &ExecutionReceiptV1) -> serde_json::Result<String> {
    let mut signed = receipt.clone();
    signed.receipt_id.clear();
    let value: Value = serde_json::to_value(signed)?;
    Ok(hash_canonical_json(&value))
}

pub fn policy_decision_id(policy: &PolicyDecisionV1) -> String {
    format!("policy-{}", stable_id(policy))
}

pub fn receipt_policy_evidence(
    policy: &PolicyDecisionV1,
    enforced_at: impl Into<String>,
) -> ReceiptPolicyEvidenceV1 {
    ReceiptPolicyEvidenceV1 {
        policy_decision_id: policy_decision_id(policy),
        policy_decision: policy.clone(),
        enforced_at: enforced_at.into(),
    }
}

pub fn execution_receipt_v2_from_v1(
    receipt: &ExecutionReceiptV1,
    context: ExecutionReceiptV2Context,
) -> ExecutionReceiptV2 {
    let job_id = context
        .job_id
        .unwrap_or_else(|| format!("job-for-{}", receipt.request_id));
    let requester = context.requester.unwrap_or_else(|| "unknown".to_string());
    let api_surface = context.api_surface.unwrap_or(ApiSurface::HivemindNative);
    let input_modalities = if context.input_modalities.is_empty() {
        vec!["text".to_string()]
    } else {
        context.input_modalities
    };
    let output_modalities = if context.output_modalities.is_empty() {
        vec!["json".to_string()]
    } else {
        context.output_modalities
    };
    let policy_refs = receipt
        .policy
        .as_ref()
        .map(|policy| vec![policy.policy_decision_id.clone()])
        .unwrap_or_default();
    let access_grant_refs = receipt
        .access
        .license_grant_id
        .clone()
        .map(|grant_id| vec![grant_id])
        .unwrap_or_default();
    let errors = context
        .error
        .as_ref()
        .map(|error| {
            vec![ExecutionReceiptErrorV2 {
                code: error.code,
                message: error.message.clone(),
                details: error.details.clone(),
            }]
        })
        .unwrap_or_default();

    ExecutionReceiptV2 {
        schema_version: "hivemind.execution_receipt.v2".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        job_id,
        request_id: receipt.request_id.clone(),
        lease_id: context.lease_id,
        lease_context: context.lease_context,
        runner_id: receipt.runner_id.clone(),
        requester,
        package_refs: vec![receipt.package_ref.clone()],
        model_artifact_refs: vec![receipt.package_manifest_hash.clone()],
        artifact_group_ids: vec![receipt.artifact_group.clone()],
        input_hashes: vec![receipt.input_hash.clone()],
        output_hashes: vec![receipt.output_hash.clone()],
        input_modalities,
        output_modalities,
        api_surface,
        started_at: receipt.started_at.clone(),
        completed_at: Some(receipt.finished_at.clone()),
        status: context.status.unwrap_or(ExecutionStatus::Succeeded),
        timing: ExecutionReceiptTimingV2 {
            queue_ms: receipt.metrics.queue_ms,
            load_ms: receipt.metrics.load_ms,
            compute_ms: receipt.metrics.compute_ms,
            total_ms: receipt.metrics.total_ms,
        },
        usage: ExecutionReceiptUsageV2 {
            input_tokens: receipt.metrics.input_tokens,
            output_tokens: receipt.metrics.output_tokens,
        },
        cost: Some(ExecutionReceiptCostV2 {
            amount: receipt.billing.estimated_cost,
            currency: receipt.billing.currency.clone(),
        }),
        privacy_mode: receipt.privacy_mode.clone(),
        verification_mode: context
            .verification_mode
            .unwrap_or(IntegrityTier::ReceiptOnly),
        hardware_claim: None,
        runtime_image_hash: None,
        engine_version: None,
        route_decision_ref: context.route_decision_ref.or_else(|| {
            receipt
                .route_id
                .as_ref()
                .map(|route_id| format!("local://route/{route_id}"))
        }),
        trace_ref: context.trace_ref,
        tool_call_refs: context.tool_call_refs,
        retrieval_refs: context.retrieval_refs,
        policy_refs,
        access_grant_refs,
        attestation_ref: context.attestation_ref,
        proof_refs: context.proof_refs,
        errors,
        signatures: vec![receipt.signature.clone()],
    }
}

fn receipt_signing_value(receipt: &ExecutionReceiptV1) -> Value {
    json!({
        "schemaVersion": receipt.schema_version,
        "requestId": receipt.request_id,
        "packageId": receipt.package_id,
        "packageRef": receipt.package_ref,
        "artifactGroup": receipt.artifact_group,
        "packageManifestHash": receipt.package_manifest_hash,
        "runnerId": receipt.runner_id,
        "routeId": receipt.route_id,
        "inputHash": receipt.input_hash,
        "outputHash": receipt.output_hash,
        "privacyMode": receipt.privacy_mode,
        "startedAt": receipt.started_at,
        "finishedAt": receipt.finished_at,
        "metrics": receipt.metrics,
        "billing": receipt.billing,
        "access": receipt.access,
        "policy": receipt.policy,
    })
}

fn stable_id(value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).unwrap_or_else(|_| json!(null));
    hash_canonical_json(&value).chars().take(24).collect()
}

fn dev_signature(label: &str, runner_id: &str, payload: &Value) -> String {
    let value = json!({
        "label": label,
        "runnerId": runner_id,
        "payload": payload,
    });
    format!(
        "{DEV_RECEIPT_SIGNATURE_PREFIX}:{label}:{}",
        hash_canonical_json(&value)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecutionMetrics;

    #[test]
    fn receipt_v2_projection_preserves_v1_audit_identity_with_context() {
        let mut receipt = ExecutionReceiptV1 {
            schema_version: "swarm-ai.receipt.v1".to_string(),
            receipt_id: String::new(),
            request_id: "request-v2-1".to_string(),
            package_id: "hivemind/hello-chat".to_string(),
            package_ref: "bzz://hello-chat".to_string(),
            artifact_group: "local-mock".to_string(),
            package_manifest_hash: "manifest-hash-1".to_string(),
            runner_id: "local-dev-runner".to_string(),
            route_id: Some("local-local-dev-runner".to_string()),
            input_hash: "input-hash-1".to_string(),
            output_hash: "output-hash-1".to_string(),
            privacy_mode: "hash-only".to_string(),
            started_at: "2026-06-02T00:00:00Z".to_string(),
            finished_at: "2026-06-02T00:00:01Z".to_string(),
            metrics: ExecutionMetrics {
                queue_ms: 1,
                load_ms: 2,
                compute_ms: 3,
                total_ms: 6,
                input_tokens: Some(4),
                output_tokens: Some(5),
            },
            billing: BillingInfo {
                estimated_cost: 0.01,
                currency: "USD".to_string(),
            },
            access: AccessInfo {
                license_grant_id: Some("grant-1".to_string()),
            },
            policy: None,
            signature: String::new(),
        };
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let v2 = execution_receipt_v2_from_v1(
            &receipt,
            ExecutionReceiptV2Context {
                job_id: Some("job-v2-1".to_string()),
                lease_id: Some("lease-v2-1".to_string()),
                lease_context: Some(ExecutionReceiptLeaseContextV2 {
                    quote_id: Some("quote-v2-1".to_string()),
                    allowed_input_refs: vec!["sha256://input-hash-1".to_string()],
                    allowed_input_hashes: vec!["input-hash-1".to_string()],
                    allowed_package_refs: vec!["bzz://hello-chat".to_string()],
                    max_cost: Some(PriceV1 {
                        amount: 0.02,
                        currency: "USD".to_string(),
                    }),
                    start_after: Some("2026-06-01T23:59:00Z".to_string()),
                    deadline: Some("2026-06-02T00:05:00Z".to_string()),
                    settlement_ref: Some("local://settlement/lease-v2-1".to_string()),
                }),
                requester: Some("local-dev".to_string()),
                api_surface: Some(ApiSurface::HivemindNative),
                input_modalities: vec!["text".to_string()],
                output_modalities: vec!["text".to_string()],
                trace_ref: Some("local://route/local-local-dev-runner".to_string()),
                ..Default::default()
            },
        );

        assert_eq!(v2.schema_version, "hivemind.execution_receipt.v2");
        assert_eq!(v2.receipt_id, receipt.receipt_id);
        assert_eq!(v2.job_id, "job-v2-1");
        assert_eq!(v2.lease_id.as_deref(), Some("lease-v2-1"));
        assert_eq!(v2.requester, "local-dev");
        assert_eq!(v2.package_refs, vec!["bzz://hello-chat"]);
        assert_eq!(v2.input_hashes, vec!["input-hash-1"]);
        assert_eq!(v2.output_hashes, vec!["output-hash-1"]);
        assert_eq!(v2.usage.input_tokens, Some(4));
        let lease_context = v2.lease_context.expect("lease context should be projected");
        assert_eq!(
            lease_context.allowed_input_refs,
            vec!["sha256://input-hash-1"]
        );
        assert_eq!(lease_context.allowed_input_hashes, vec!["input-hash-1"]);
        assert_eq!(lease_context.allowed_package_refs, vec!["bzz://hello-chat"]);
        assert_eq!(lease_context.max_cost.unwrap().amount, 0.02);
        assert_eq!(
            lease_context.start_after.as_deref(),
            Some("2026-06-01T23:59:00Z")
        );
        assert_eq!(
            lease_context.deadline.as_deref(),
            Some("2026-06-02T00:05:00Z")
        );
        assert_eq!(
            lease_context.settlement_ref.as_deref(),
            Some("local://settlement/lease-v2-1")
        );
        assert_eq!(v2.signatures, vec![receipt.signature]);
    }
}
