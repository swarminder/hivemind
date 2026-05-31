use crate::canonical::hash_canonical_json;
use crate::execution::{ExecutionMetrics, ExecutionRequestV1, ExecutionResponseV1};
use crate::manifest::PackageManifestV1;
use crate::policy::PolicyDecisionV1;
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
