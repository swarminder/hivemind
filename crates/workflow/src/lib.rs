use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    PermissionRequest, PriceV1, PrivacyTier, StandardErrorCodeV1, ValidationIssue,
    canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_policy::ToolPermissionGrantV1;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_TOOL_SIGNATURE_PREFIX: &str = "dev-tool-signature-v1";
const DEV_WORKFLOW_SIGNATURE_PREFIX: &str = "dev-workflow-signature-v1";
const DEV_TOOL_INVOCATION_SIGNATURE_PREFIX: &str = "dev-tool-invocation-signature-v1";
const DEV_TOOL_RESULT_SIGNATURE_PREFIX: &str = "dev-tool-result-signature-v1";
const DEV_AGENT_RUN_STATE_SIGNATURE_PREFIX: &str = "dev-agent-run-state-signature-v1";
const DEV_HUMAN_APPROVAL_SIGNATURE_PREFIX: &str = "dev-human-approval-signature-v1";
const DEV_MEMORY_WRITE_SIGNATURE_PREFIX: &str = "dev-memory-write-signature-v1";

pub const TOOL_INVOCATION_SCHEMA_VERSION: &str = "hivemind.tool_invocation.v1";
pub const TOOL_INVOCATION_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.tool_invocation_verification.v1";
pub const TOOL_RESULT_SCHEMA_VERSION: &str = "hivemind.tool_result.v1";
pub const TOOL_RESULT_VERIFICATION_SCHEMA_VERSION: &str = "hivemind.tool_result_verification.v1";
pub const AGENT_RUN_STATE_SCHEMA_VERSION: &str = "hivemind.agent_run_state.v1";
pub const AGENT_RUN_STATE_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.agent_run_state_verification.v1";
pub const HUMAN_APPROVAL_REQUEST_SCHEMA_VERSION: &str = "hivemind.human_approval_request.v1";
pub const HUMAN_APPROVAL_REQUEST_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.human_approval_request_verification.v1";
pub const MEMORY_WRITE_SCHEMA_VERSION: &str = "hivemind.memory_write.v1";
pub const MEMORY_WRITE_VERIFICATION_SCHEMA_VERSION: &str = "hivemind.memory_write_verification.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ToolExecutionMode {
    Browser,
    Local,
    RemoteRunner,
    MarketplaceRunner,
    ExternalHttp,
    Wasm,
    Container,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowStepKind {
    Package,
    Tool,
    Workflow,
    VectorSearch,
    HumanApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowFailurePolicy {
    FailFast,
    ContinueOnFailure,
    RetryStep,
    ManualReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowTracePolicy {
    Minimal,
    ReceiptsOnly,
    Full,
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "toolId")]
    pub tool_id: String,
    pub name: String,
    pub description: String,
    pub publisher: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema")]
    pub output_schema: Value,
    #[serde(default)]
    pub permissions: Vec<PermissionRequest>,
    #[serde(rename = "executionModes")]
    pub execution_modes: Vec<ToolExecutionMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<PriceV1>,
    #[serde(rename = "safetyPolicyRefs", default)]
    pub safety_policy_refs: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolManifestInitOptionsV1 {
    pub name: String,
    pub description: String,
    pub publisher: String,
    #[serde(rename = "executionModes", default)]
    pub execution_modes: Vec<ToolExecutionMode>,
    #[serde(rename = "safetyPolicyRefs", default)]
    pub safety_policy_refs: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<PermissionRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolManifestVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "toolId")]
    pub tool_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowStepV1 {
    #[serde(rename = "stepId")]
    pub step_id: String,
    pub name: String,
    pub kind: WorkflowStepKind,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "inputMapping", default)]
    pub input_mapping: Value,
    #[serde(rename = "dependsOn", default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowDependencyV1 {
    pub name: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub kind: WorkflowStepKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "workflowId")]
    pub workflow_id: String,
    pub name: String,
    pub publisher: String,
    pub steps: Vec<WorkflowStepV1>,
    pub dependencies: Vec<WorkflowDependencyV1>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema")]
    pub output_schema: Value,
    #[serde(rename = "failurePolicy")]
    pub failure_policy: WorkflowFailurePolicy,
    #[serde(rename = "tracePolicy")]
    pub trace_policy: WorkflowTracePolicy,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowManifestInitOptionsV1 {
    pub name: String,
    pub publisher: String,
    #[serde(rename = "toolRefs", default)]
    pub tool_refs: Vec<String>,
    #[serde(rename = "packageRefs", default)]
    pub package_refs: Vec<String>,
    #[serde(rename = "vectorStoreRefs", default)]
    pub vector_store_refs: Vec<String>,
    #[serde(rename = "failurePolicy", default)]
    pub failure_policy: Option<WorkflowFailurePolicy>,
    #[serde(rename = "tracePolicy", default)]
    pub trace_policy: Option<WorkflowTracePolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowManifestVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "workflowId")]
    pub workflow_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowPlanRequestV1 {
    pub workflow: WorkflowManifestV1,
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "workflowId")]
    pub workflow_id: String,
    #[serde(rename = "orderedSteps")]
    pub ordered_steps: Vec<WorkflowStepV1>,
    #[serde(rename = "toolRefs")]
    pub tool_refs: Vec<String>,
    #[serde(rename = "packageRefs")]
    pub package_refs: Vec<String>,
    #[serde(rename = "vectorStoreRefs")]
    pub vector_store_refs: Vec<String>,
    #[serde(rename = "approvalRequired")]
    pub approval_required: bool,
    #[serde(rename = "failurePolicy")]
    pub failure_policy: WorkflowFailurePolicy,
    #[serde(rename = "tracePolicy")]
    pub trace_policy: WorkflowTracePolicy,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ToolInvocationApprovalStatusV1 {
    NotRequired,
    Required,
    Approved,
    Rejected,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolInvocationPolicyDecisionV1 {
    pub allowed: bool,
    #[serde(rename = "requiredPermissions")]
    pub required_permissions: Vec<String>,
    #[serde(rename = "grantedPermissions")]
    pub granted_permissions: Vec<String>,
    #[serde(rename = "missingPermissions")]
    pub missing_permissions: Vec<String>,
    #[serde(rename = "grantRefs")]
    pub grant_refs: Vec<String>,
    #[serde(rename = "approvalRequired")]
    pub approval_required: bool,
    pub reason: String,
    #[serde(rename = "policyEvidenceRefs")]
    pub policy_evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolInvocationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "agentRunId")]
    pub agent_run_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "toolRef")]
    pub tool_ref: String,
    #[serde(rename = "toolId", default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    #[serde(rename = "toolName", default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub arguments: Value,
    #[serde(rename = "argumentHash")]
    pub argument_hash: String,
    #[serde(rename = "inputRefs")]
    pub input_refs: Vec<String>,
    #[serde(rename = "policyDecision")]
    pub policy_decision: ToolInvocationPolicyDecisionV1,
    #[serde(rename = "approvalStatus")]
    pub approval_status: ToolInvocationApprovalStatusV1,
    #[serde(
        rename = "humanApprovalRequestId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub human_approval_request_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolInvocationVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ToolResultStatusV1 {
    Succeeded,
    Failed,
    Refused,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resultId")]
    pub result_id: String,
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "agentRunId")]
    pub agent_run_id: String,
    #[serde(rename = "toolRef")]
    pub tool_ref: String,
    pub status: ToolResultStatusV1,
    #[serde(default)]
    pub output: Value,
    #[serde(rename = "outputHash")]
    pub output_hash: String,
    #[serde(rename = "outputRefs")]
    pub output_refs: Vec<String>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<StandardErrorCodeV1>,
    #[serde(
        rename = "errorMessage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub error_message: Option<String>,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "redactionPolicy")]
    pub redaction_policy: Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolResultVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resultId")]
    pub result_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AgentRunStatusV1 {
    Planning,
    WaitingForTool,
    WaitingForHuman,
    Running,
    Failed,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AgentMessageRoleV1 {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AgentMessageRecordV1 {
    pub role: AgentMessageRoleV1,
    #[serde(rename = "contentHash")]
    pub content_hash: String,
    #[serde(
        rename = "contentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_ref: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AgentRunErrorV1 {
    pub code: StandardErrorCodeV1,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AgentRunStateV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(
        rename = "workflowRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_ref: Option<String>,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    pub status: AgentRunStatusV1,
    #[serde(
        rename = "currentStep",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub current_step: Option<String>,
    pub messages: Vec<AgentMessageRecordV1>,
    #[serde(rename = "toolInvocationIds")]
    pub tool_invocation_ids: Vec<String>,
    #[serde(rename = "toolResultIds")]
    pub tool_result_ids: Vec<String>,
    #[serde(rename = "pendingApprovalIds")]
    pub pending_approval_ids: Vec<String>,
    #[serde(rename = "retrievalEventRefs")]
    pub retrieval_event_refs: Vec<String>,
    #[serde(rename = "memoryWriteIds")]
    pub memory_write_ids: Vec<String>,
    #[serde(rename = "receiptRefs")]
    pub receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentRunErrorV1>,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AgentRunStateVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HumanApprovalActionV1 {
    ToolCall,
    Payment,
    DataAccess,
    ExternalAction,
    MemoryWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HumanApprovalStatusV1 {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HumanApprovalRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "approvalId")]
    pub approval_id: String,
    #[serde(rename = "agentRunId")]
    pub agent_run_id: String,
    #[serde(
        rename = "invocationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub invocation_id: Option<String>,
    #[serde(rename = "actionType")]
    pub action_type: HumanApprovalActionV1,
    #[serde(rename = "requestedBy")]
    pub requested_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    pub status: HumanApprovalStatusV1,
    pub reason: String,
    #[serde(rename = "requestedAction")]
    pub requested_action: Value,
    #[serde(rename = "riskSummary")]
    pub risk_summary: Vec<String>,
    #[serde(rename = "policyEvidenceRefs")]
    pub policy_evidence_refs: Vec<String>,
    #[serde(rename = "requestedAt")]
    pub requested_at: String,
    #[serde(
        rename = "resolvedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolved_at: Option<String>,
    #[serde(
        rename = "decisionReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub decision_reason: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HumanApprovalRequestVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "approvalId")]
    pub approval_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryRetentionV1 {
    Ephemeral,
    Session,
    Project,
    LongTerm,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryWriteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "memoryWriteId")]
    pub memory_write_id: String,
    #[serde(rename = "agentRunId")]
    pub agent_run_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    pub namespace: String,
    #[serde(rename = "contentHash")]
    pub content_hash: String,
    #[serde(
        rename = "contentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_ref: Option<String>,
    pub retention: MemoryRetentionV1,
    pub privacy: PrivacyTier,
    #[serde(rename = "policyEvidenceRefs")]
    pub policy_evidence_refs: Vec<String>,
    pub allowed: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryWriteVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "memoryWriteId")]
    pub memory_write_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowRecordType {
    Tool,
    Workflow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowRecordSummaryV1 {
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: WorkflowRecordType,
    pub name: String,
    pub publisher: String,
    pub valid: bool,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowRecordStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "toolCount")]
    pub tool_count: usize,
    #[serde(rename = "workflowCount")]
    pub workflow_count: usize,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "approvalRequiredCount")]
    pub approval_required_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub records: Vec<WorkflowRecordSummaryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: WorkflowRecordType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolManifestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<WorkflowManifestV1>,
    #[serde(
        rename = "toolVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_verification: Option<ToolManifestVerificationV1>,
    #[serde(
        rename = "workflowVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_verification: Option<WorkflowManifestVerificationV1>,
    #[serde(
        rename = "workflowPlan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_plan: Option<WorkflowPlanV1>,
    pub path: String,
}

pub fn create_tool_manifest(options: ToolManifestInitOptionsV1) -> ToolManifestV1 {
    let mut safety_policy_refs = options.safety_policy_refs;
    safety_policy_refs.sort();
    safety_policy_refs.dedup();
    let mut tool = ToolManifestV1 {
        schema_version: "swarm-ai.tool.v1".to_string(),
        tool_id: String::new(),
        name: options.name,
        description: options.description,
        publisher: options.publisher,
        input_schema: json!({ "type": "object" }),
        output_schema: json!({ "type": "object" }),
        permissions: options.permissions,
        execution_modes: if options.execution_modes.is_empty() {
            vec![ToolExecutionMode::Local]
        } else {
            options.execution_modes
        },
        price: None,
        safety_policy_refs,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_tool_manifest(&mut tool);
    tool
}

pub fn create_workflow_manifest(options: WorkflowManifestInitOptionsV1) -> WorkflowManifestV1 {
    let mut steps = Vec::new();
    let mut dependencies = Vec::new();
    append_workflow_refs(
        &mut steps,
        &mut dependencies,
        "tool",
        WorkflowStepKind::Tool,
        options.tool_refs,
    );
    append_workflow_refs(
        &mut steps,
        &mut dependencies,
        "vector",
        WorkflowStepKind::VectorSearch,
        options.vector_store_refs,
    );
    append_workflow_refs(
        &mut steps,
        &mut dependencies,
        "package",
        WorkflowStepKind::Package,
        options.package_refs,
    );

    let mut workflow = WorkflowManifestV1 {
        schema_version: "swarm-ai.workflow.v1".to_string(),
        workflow_id: String::new(),
        name: options.name,
        publisher: options.publisher,
        steps,
        dependencies,
        input_schema: json!({ "type": "object" }),
        output_schema: json!({ "type": "object" }),
        failure_policy: options
            .failure_policy
            .unwrap_or(WorkflowFailurePolicy::FailFast),
        trace_policy: options
            .trace_policy
            .unwrap_or(WorkflowTracePolicy::ReceiptsOnly),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_workflow_manifest(&mut workflow);
    workflow
}

pub fn sign_tool_manifest(tool: &mut ToolManifestV1) {
    tool.signature = Some(expected_tool_signature(tool));
    tool.tool_id = canonical_tool_id(tool);
}

pub fn sign_workflow_manifest(workflow: &mut WorkflowManifestV1) {
    workflow.signature = Some(expected_workflow_signature(workflow));
    workflow.workflow_id = canonical_workflow_id(workflow);
}

pub fn sign_tool_with_identity(
    tool: &mut ToolManifestV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != tool.publisher {
        anyhow::bail!(
            "identity subject {} does not match tool publisher {}",
            identity.subject,
            tool.publisher
        );
    }
    let envelope = hivemind_identity::sign_value(identity, "tool", &tool_signing_value(tool))?;
    tool.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    tool.tool_id = canonical_tool_id(tool);
    Ok(envelope)
}

pub fn sign_workflow_with_identity(
    workflow: &mut WorkflowManifestV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != workflow.publisher {
        anyhow::bail!(
            "identity subject {} does not match workflow publisher {}",
            identity.subject,
            workflow.publisher
        );
    }
    let envelope =
        hivemind_identity::sign_value(identity, "workflow", &workflow_signing_value(workflow))?;
    workflow.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    workflow.workflow_id = canonical_workflow_id(workflow);
    Ok(envelope)
}

pub fn expected_tool_signature(tool: &ToolManifestV1) -> String {
    format!(
        "{DEV_TOOL_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&tool_signing_value(tool)))
    )
}

pub fn expected_workflow_signature(workflow: &WorkflowManifestV1) -> String {
    format!(
        "{DEV_WORKFLOW_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&workflow_signing_value(workflow)))
    )
}

pub fn canonical_tool_id(tool: &ToolManifestV1) -> String {
    stable_id("tool", &tool_signing_value(tool))
}

pub fn canonical_workflow_id(workflow: &WorkflowManifestV1) -> String {
    stable_id("workflow", &workflow_signing_value(workflow))
}

pub fn verify_tool_manifest(tool: &ToolManifestV1) -> ToolManifestVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_tool_signature(tool));
    let signature = tool
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if tool.schema_version != "swarm-ai.tool.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.tool.v1",
        ));
    }
    require_non_empty(&mut issues, "$.toolId", &tool.tool_id);
    if !tool.tool_id.is_empty() && tool.tool_id != canonical_tool_id(tool) {
        issues.push(issue(
            "$.toolId",
            "Tool id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.name", &tool.name);
    require_non_empty(&mut issues, "$.description", &tool.description);
    require_non_empty(&mut issues, "$.publisher", &tool.publisher);
    if !tool.input_schema.is_object() {
        issues.push(issue(
            "$.inputSchema",
            "inputSchema must be a JSON Schema object",
        ));
    }
    if !tool.output_schema.is_object() {
        issues.push(issue(
            "$.outputSchema",
            "outputSchema must be a JSON Schema object",
        ));
    }
    if tool.execution_modes.is_empty() {
        issues.push(issue(
            "$.executionModes",
            "Tool must declare at least one execution mode",
        ));
    }
    validate_permissions("$.permissions", &tool.permissions, &mut issues);
    validate_refs(
        "$.safetyPolicyRefs",
        &tool.safety_policy_refs,
        &mut issues,
        &mut warnings,
    );
    validate_created_at(&tool.created_at, &mut issues);
    verify_signature(
        signature,
        "tool",
        &tool_signing_value(tool),
        &tool.publisher,
        &mut expected_signature,
        &mut issues,
        "Tool signature does not match canonical dev signature or Ed25519 publisher identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Tool manifest is unsigned; verify publisher and toolId through a trusted source",
        ));
    }

    ToolManifestVerificationV1 {
        schema_version: "swarm-ai.tool-verification.v1".to_string(),
        tool_id: tool.tool_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn verify_workflow_manifest(workflow: &WorkflowManifestV1) -> WorkflowManifestVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_workflow_signature(workflow));
    let signature = workflow
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if workflow.schema_version != "swarm-ai.workflow.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.workflow.v1",
        ));
    }
    require_non_empty(&mut issues, "$.workflowId", &workflow.workflow_id);
    if !workflow.workflow_id.is_empty() && workflow.workflow_id != canonical_workflow_id(workflow) {
        issues.push(issue(
            "$.workflowId",
            "Workflow id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.name", &workflow.name);
    require_non_empty(&mut issues, "$.publisher", &workflow.publisher);
    if workflow.steps.is_empty() {
        issues.push(issue("$.steps", "Workflow must include at least one step"));
    }
    if !workflow.input_schema.is_object() {
        issues.push(issue(
            "$.inputSchema",
            "inputSchema must be a JSON Schema object",
        ));
    }
    if !workflow.output_schema.is_object() {
        issues.push(issue(
            "$.outputSchema",
            "outputSchema must be a JSON Schema object",
        ));
    }
    validate_workflow_graph(workflow, &mut issues);
    validate_refs_for_workflow(workflow, &mut issues, &mut warnings);
    validate_created_at(&workflow.created_at, &mut issues);
    verify_signature(
        signature,
        "workflow",
        &workflow_signing_value(workflow),
        &workflow.publisher,
        &mut expected_signature,
        &mut issues,
        "Workflow signature does not match canonical dev signature or Ed25519 publisher identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Workflow manifest is unsigned; verify publisher and workflowId through a trusted source",
        ));
    }

    WorkflowManifestVerificationV1 {
        schema_version: "swarm-ai.workflow-verification.v1".to_string(),
        workflow_id: workflow.workflow_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn workflow_plan(workflow: &WorkflowManifestV1) -> WorkflowPlanV1 {
    let verification = verify_workflow_manifest(workflow);
    let mut tool_refs = Vec::new();
    let mut package_refs = Vec::new();
    let mut vector_store_refs = Vec::new();
    let mut approval_required = false;
    for step in &workflow.steps {
        match step.kind {
            WorkflowStepKind::Tool => tool_refs.push(step.reference.clone()),
            WorkflowStepKind::Package => package_refs.push(step.reference.clone()),
            WorkflowStepKind::VectorSearch => vector_store_refs.push(step.reference.clone()),
            WorkflowStepKind::HumanApproval => approval_required = true,
            WorkflowStepKind::Workflow => {}
        }
    }
    dedup(&mut tool_refs);
    dedup(&mut package_refs);
    dedup(&mut vector_store_refs);

    WorkflowPlanV1 {
        schema_version: "swarm-ai.workflow-plan.v1".to_string(),
        workflow_id: workflow.workflow_id.clone(),
        ordered_steps: workflow.steps.clone(),
        tool_refs,
        package_refs,
        vector_store_refs,
        approval_required,
        failure_policy: workflow.failure_policy.clone(),
        trace_policy: workflow.trace_policy.clone(),
        valid: verification.valid,
        issues: verification.issues,
        warnings: verification.warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn tool_invocation_from_manifest(
    agent_run_id: impl Into<String>,
    agent_id: impl Into<String>,
    package_id: impl Into<String>,
    tool_ref: impl Into<String>,
    tool: &ToolManifestV1,
    arguments: Value,
    input_refs: Vec<String>,
    grants: &[ToolPermissionGrantV1],
    approval_required: bool,
    policy_evidence_refs: Vec<String>,
) -> ToolInvocationV1 {
    let agent_run_id = agent_run_id.into();
    let agent_id = agent_id.into();
    let package_id = package_id.into();
    let tool_ref = tool_ref.into();
    let policy_decision = tool_invocation_policy_decision(
        &agent_id,
        &package_id,
        &tool_ref,
        tool,
        grants,
        approval_required,
        policy_evidence_refs,
    );
    let approval_status = if !policy_decision.allowed {
        ToolInvocationApprovalStatusV1::Denied
    } else if policy_decision.approval_required {
        ToolInvocationApprovalStatusV1::Required
    } else {
        ToolInvocationApprovalStatusV1::NotRequired
    };
    let mut invocation = ToolInvocationV1 {
        schema_version: TOOL_INVOCATION_SCHEMA_VERSION.to_string(),
        invocation_id: String::new(),
        agent_run_id,
        agent_id,
        package_id,
        tool_ref,
        tool_id: Some(tool.tool_id.clone()),
        tool_name: Some(tool.name.clone()),
        argument_hash: hash_json_value(&arguments),
        arguments,
        input_refs,
        policy_decision,
        approval_status,
        human_approval_request_id: None,
        created_at: now_rfc3339(),
        signature: String::new(),
    };
    sign_tool_invocation(&mut invocation);
    invocation
}

pub fn tool_invocation_policy_decision(
    agent_id: &str,
    package_id: &str,
    tool_ref: &str,
    tool: &ToolManifestV1,
    grants: &[ToolPermissionGrantV1],
    approval_required: bool,
    policy_evidence_refs: Vec<String>,
) -> ToolInvocationPolicyDecisionV1 {
    let mut required_permissions = required_tool_permissions(tool);
    let mut granted_permissions = Vec::new();
    let mut grant_refs = Vec::new();
    for grant in grants {
        if !grant_matches_tool_call(grant, agent_id, package_id, tool_ref) {
            continue;
        }
        grant_refs.push(grant.grant_id.clone());
        granted_permissions.extend(grant.permissions.clone());
    }
    dedup(&mut required_permissions);
    dedup(&mut granted_permissions);
    dedup(&mut grant_refs);
    let missing_permissions = required_permissions
        .iter()
        .filter(|required| {
            !granted_permissions
                .iter()
                .any(|granted| granted == *required)
        })
        .cloned()
        .collect::<Vec<_>>();
    let allowed = missing_permissions.is_empty();
    let reason = if allowed && approval_required {
        "Tool permissions are satisfied, but human approval is required before execution"
            .to_string()
    } else if allowed {
        "Tool permissions are satisfied".to_string()
    } else {
        format!(
            "Tool invocation is blocked; missing permissions: {}",
            missing_permissions.join(", ")
        )
    };

    ToolInvocationPolicyDecisionV1 {
        allowed,
        required_permissions,
        granted_permissions,
        missing_permissions,
        grant_refs,
        approval_required,
        reason,
        policy_evidence_refs,
    }
}

pub fn tool_invocation_can_execute(
    invocation: &ToolInvocationV1,
    approval: Option<&HumanApprovalRequestV1>,
) -> bool {
    if !invocation.policy_decision.allowed {
        return false;
    }
    match invocation.approval_status {
        ToolInvocationApprovalStatusV1::NotRequired | ToolInvocationApprovalStatusV1::Approved => {
            true
        }
        ToolInvocationApprovalStatusV1::Required => approval.is_some_and(|approval| {
            approval.status == HumanApprovalStatusV1::Approved
                && approval.agent_run_id == invocation.agent_run_id
                && approval.invocation_id.as_deref() == Some(invocation.invocation_id.as_str())
        }),
        ToolInvocationApprovalStatusV1::Rejected | ToolInvocationApprovalStatusV1::Denied => false,
    }
}

pub fn sign_tool_invocation(invocation: &mut ToolInvocationV1) {
    invocation.signature = expected_tool_invocation_signature(invocation);
    invocation.invocation_id = canonical_tool_invocation_id(invocation);
}

pub fn expected_tool_invocation_signature(invocation: &ToolInvocationV1) -> String {
    runtime_dev_signature(
        DEV_TOOL_INVOCATION_SIGNATURE_PREFIX,
        &tool_invocation_signing_value(invocation),
    )
}

pub fn canonical_tool_invocation_id(invocation: &ToolInvocationV1) -> String {
    stable_id(
        "tool-invocation",
        &tool_invocation_signing_value(invocation),
    )
}

pub fn verify_tool_invocation(invocation: &ToolInvocationV1) -> ToolInvocationVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_signature = expected_tool_invocation_signature(invocation);
    if invocation.schema_version != TOOL_INVOCATION_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {TOOL_INVOCATION_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.invocationId", &invocation.invocation_id);
    if !invocation.invocation_id.trim().is_empty()
        && invocation.invocation_id != canonical_tool_invocation_id(invocation)
    {
        issues.push(issue(
            "$.invocationId",
            "Tool invocation id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.agentRunId", &invocation.agent_run_id);
    require_non_empty(&mut issues, "$.agentId", &invocation.agent_id);
    require_non_empty(&mut issues, "$.packageId", &invocation.package_id);
    require_non_empty(&mut issues, "$.toolRef", &invocation.tool_ref);
    validate_refs(
        "$.inputRefs",
        &invocation.input_refs,
        &mut issues,
        &mut warnings,
    );
    if invocation.argument_hash != hash_json_value(&invocation.arguments) {
        issues.push(issue(
            "$.argumentHash",
            "argumentHash does not match canonical arguments",
        ));
    }
    if invocation.policy_decision.allowed
        && !invocation.policy_decision.missing_permissions.is_empty()
    {
        issues.push(issue(
            "$.policyDecision.missingPermissions",
            "Allowed tool invocation must not list missing permissions",
        ));
    }
    if !invocation.policy_decision.allowed
        && invocation.approval_status != ToolInvocationApprovalStatusV1::Denied
    {
        issues.push(issue(
            "$.approvalStatus",
            "Denied tool invocation must use denied approvalStatus",
        ));
    }
    if invocation.policy_decision.approval_required
        && invocation.policy_decision.allowed
        && matches!(
            invocation.approval_status,
            ToolInvocationApprovalStatusV1::NotRequired
        )
    {
        issues.push(issue(
            "$.approvalStatus",
            "Approval-required tool invocation cannot be marked not-required",
        ));
    }
    validate_created_at_path(&invocation.created_at, "$.createdAt", &mut issues);
    verify_runtime_signature(
        &invocation.signature,
        &expected_signature,
        DEV_TOOL_INVOCATION_SIGNATURE_PREFIX,
        &mut issues,
        "ToolInvocationV1 signature does not match canonical dev signature",
    );

    ToolInvocationVerificationV1 {
        schema_version: TOOL_INVOCATION_VERIFICATION_SCHEMA_VERSION.to_string(),
        invocation_id: invocation.invocation_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: now_rfc3339(),
    }
}

pub fn tool_result_from_invocation(
    invocation: &ToolInvocationV1,
    status: ToolResultStatusV1,
    output: Value,
    output_refs: Vec<String>,
    error_code: Option<StandardErrorCodeV1>,
    error_message: Option<String>,
) -> ToolResultV1 {
    let now = now_rfc3339();
    let mut result = ToolResultV1 {
        schema_version: TOOL_RESULT_SCHEMA_VERSION.to_string(),
        result_id: String::new(),
        invocation_id: invocation.invocation_id.clone(),
        agent_run_id: invocation.agent_run_id.clone(),
        tool_ref: invocation.tool_ref.clone(),
        status,
        output_hash: hash_json_value(&output),
        output,
        output_refs,
        error_code,
        error_message,
        started_at: now.clone(),
        completed_at: now,
        duration_ms: 0,
        redaction_policy: json!({
            "mode": "hashes-and-refs",
            "redactSecrets": true
        }),
        signature: String::new(),
    };
    sign_tool_result(&mut result);
    result
}

pub fn sign_tool_result(result: &mut ToolResultV1) {
    result.signature = expected_tool_result_signature(result);
    result.result_id = canonical_tool_result_id(result);
}

pub fn expected_tool_result_signature(result: &ToolResultV1) -> String {
    runtime_dev_signature(
        DEV_TOOL_RESULT_SIGNATURE_PREFIX,
        &tool_result_signing_value(result),
    )
}

pub fn canonical_tool_result_id(result: &ToolResultV1) -> String {
    stable_id("tool-result", &tool_result_signing_value(result))
}

pub fn verify_tool_result(result: &ToolResultV1) -> ToolResultVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_signature = expected_tool_result_signature(result);
    if result.schema_version != TOOL_RESULT_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {TOOL_RESULT_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.resultId", &result.result_id);
    if !result.result_id.trim().is_empty() && result.result_id != canonical_tool_result_id(result) {
        issues.push(issue(
            "$.resultId",
            "Tool result id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.invocationId", &result.invocation_id);
    require_non_empty(&mut issues, "$.agentRunId", &result.agent_run_id);
    require_non_empty(&mut issues, "$.toolRef", &result.tool_ref);
    validate_refs(
        "$.outputRefs",
        &result.output_refs,
        &mut issues,
        &mut warnings,
    );
    if result.output_hash != hash_json_value(&result.output) {
        issues.push(issue(
            "$.outputHash",
            "outputHash does not match canonical output",
        ));
    }
    if matches!(
        result.status,
        ToolResultStatusV1::Failed | ToolResultStatusV1::Refused
    ) {
        if result.error_code.is_none() {
            issues.push(issue(
                "$.errorCode",
                "Failed or refused tool results require errorCode",
            ));
        }
        if result
            .error_message
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
        {
            issues.push(issue(
                "$.errorMessage",
                "Failed or refused tool results require errorMessage",
            ));
        }
    }
    validate_created_at_path(&result.started_at, "$.startedAt", &mut issues);
    validate_created_at_path(&result.completed_at, "$.completedAt", &mut issues);
    verify_runtime_signature(
        &result.signature,
        &expected_signature,
        DEV_TOOL_RESULT_SIGNATURE_PREFIX,
        &mut issues,
        "ToolResultV1 signature does not match canonical dev signature",
    );

    ToolResultVerificationV1 {
        schema_version: TOOL_RESULT_VERIFICATION_SCHEMA_VERSION.to_string(),
        result_id: result.result_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: now_rfc3339(),
    }
}

pub fn agent_run_state(
    run_id: impl Into<String>,
    agent_id: impl Into<String>,
    workflow_ref: Option<String>,
    package_ref: Option<String>,
) -> AgentRunStateV1 {
    let now = now_rfc3339();
    let mut state = AgentRunStateV1 {
        schema_version: AGENT_RUN_STATE_SCHEMA_VERSION.to_string(),
        run_id: run_id.into(),
        agent_id: agent_id.into(),
        workflow_ref,
        package_ref,
        status: AgentRunStatusV1::Planning,
        current_step: None,
        messages: Vec::new(),
        tool_invocation_ids: Vec::new(),
        tool_result_ids: Vec::new(),
        pending_approval_ids: Vec::new(),
        retrieval_event_refs: Vec::new(),
        memory_write_ids: Vec::new(),
        receipt_refs: Vec::new(),
        error: None,
        started_at: now.clone(),
        updated_at: now,
        completed_at: None,
        signature: String::new(),
    };
    sign_agent_run_state(&mut state);
    state
}

pub fn record_agent_tool_invocation(state: &mut AgentRunStateV1, invocation: &ToolInvocationV1) {
    push_unique(
        &mut state.tool_invocation_ids,
        invocation.invocation_id.clone(),
    );
    state.current_step = Some(invocation.tool_ref.clone());
    state.status = if invocation.approval_status == ToolInvocationApprovalStatusV1::Required {
        AgentRunStatusV1::WaitingForHuman
    } else if invocation.policy_decision.allowed {
        AgentRunStatusV1::WaitingForTool
    } else {
        state.error = Some(AgentRunErrorV1 {
            code: StandardErrorCodeV1::PolicyBlocked,
            message: invocation.policy_decision.reason.clone(),
        });
        AgentRunStatusV1::Failed
    };
    touch_agent_state(state);
}

pub fn record_agent_tool_result(state: &mut AgentRunStateV1, result: &ToolResultV1) {
    push_unique(&mut state.tool_result_ids, result.result_id.clone());
    state.current_step = Some(result.tool_ref.clone());
    match result.status {
        ToolResultStatusV1::Succeeded => {
            state.status = AgentRunStatusV1::Running;
        }
        ToolResultStatusV1::Failed | ToolResultStatusV1::Refused => {
            state.status = AgentRunStatusV1::Failed;
            state.error = Some(AgentRunErrorV1 {
                code: result
                    .error_code
                    .unwrap_or(StandardErrorCodeV1::InternalError),
                message: result
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "Tool execution failed".to_string()),
            });
        }
        ToolResultStatusV1::Cancelled => {
            state.status = AgentRunStatusV1::Cancelled;
            state.completed_at = Some(now_rfc3339());
        }
    }
    touch_agent_state(state);
}

pub fn record_agent_pending_approval(
    state: &mut AgentRunStateV1,
    approval: &HumanApprovalRequestV1,
) {
    if approval.status == HumanApprovalStatusV1::Pending {
        push_unique(
            &mut state.pending_approval_ids,
            approval.approval_id.clone(),
        );
        state.status = AgentRunStatusV1::WaitingForHuman;
    }
    touch_agent_state(state);
}

pub fn resume_agent_after_approval(state: &mut AgentRunStateV1, approval: &HumanApprovalRequestV1) {
    state
        .pending_approval_ids
        .retain(|approval_id| approval_id != &approval.approval_id);
    state.status = match approval.status {
        HumanApprovalStatusV1::Approved => AgentRunStatusV1::Running,
        HumanApprovalStatusV1::Rejected => {
            state.error = Some(AgentRunErrorV1 {
                code: StandardErrorCodeV1::PolicyBlocked,
                message: approval
                    .decision_reason
                    .clone()
                    .unwrap_or_else(|| "Human approval rejected".to_string()),
            });
            AgentRunStatusV1::Failed
        }
        HumanApprovalStatusV1::Expired | HumanApprovalStatusV1::Cancelled => {
            state.error = Some(AgentRunErrorV1 {
                code: StandardErrorCodeV1::Cancelled,
                message: "Human approval was not granted".to_string(),
            });
            AgentRunStatusV1::Cancelled
        }
        HumanApprovalStatusV1::Pending => AgentRunStatusV1::WaitingForHuman,
    };
    touch_agent_state(state);
}

pub fn record_agent_memory_write(state: &mut AgentRunStateV1, write: &MemoryWriteV1) {
    push_unique(&mut state.memory_write_ids, write.memory_write_id.clone());
    if !write.allowed {
        state.status = AgentRunStatusV1::Failed;
        state.error = Some(AgentRunErrorV1 {
            code: StandardErrorCodeV1::PolicyBlocked,
            message: "Memory write was blocked by policy".to_string(),
        });
    }
    touch_agent_state(state);
}

pub fn complete_agent_run(state: &mut AgentRunStateV1, receipt_ref: Option<String>) {
    if let Some(receipt_ref) = receipt_ref {
        push_unique(&mut state.receipt_refs, receipt_ref);
    }
    state.status = AgentRunStatusV1::Completed;
    state.completed_at = Some(now_rfc3339());
    touch_agent_state(state);
}

pub fn sign_agent_run_state(state: &mut AgentRunStateV1) {
    state.signature = expected_agent_run_state_signature(state);
    if state.run_id.trim().is_empty() {
        state.run_id = canonical_agent_run_state_id(state);
    }
}

pub fn expected_agent_run_state_signature(state: &AgentRunStateV1) -> String {
    runtime_dev_signature(
        DEV_AGENT_RUN_STATE_SIGNATURE_PREFIX,
        &agent_run_state_signing_value(state),
    )
}

pub fn canonical_agent_run_state_id(state: &AgentRunStateV1) -> String {
    stable_id("agent-run", &agent_run_state_signing_value(state))
}

pub fn verify_agent_run_state(state: &AgentRunStateV1) -> AgentRunStateVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_signature = expected_agent_run_state_signature(state);
    if state.schema_version != AGENT_RUN_STATE_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {AGENT_RUN_STATE_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.runId", &state.run_id);
    require_non_empty(&mut issues, "$.agentId", &state.agent_id);
    if let Some(workflow_ref) = &state.workflow_ref {
        validate_ref(
            "$.workflowRef".to_string(),
            workflow_ref,
            &mut issues,
            &mut warnings,
        );
    }
    if let Some(package_ref) = &state.package_ref {
        validate_ref(
            "$.packageRef".to_string(),
            package_ref,
            &mut issues,
            &mut warnings,
        );
    }
    validate_refs(
        "$.retrievalEventRefs",
        &state.retrieval_event_refs,
        &mut issues,
        &mut warnings,
    );
    validate_refs(
        "$.receiptRefs",
        &state.receipt_refs,
        &mut issues,
        &mut warnings,
    );
    if state.status == AgentRunStatusV1::WaitingForHuman && state.pending_approval_ids.is_empty() {
        issues.push(issue(
            "$.pendingApprovalIds",
            "waiting-for-human agent state requires pendingApprovalIds",
        ));
    }
    if state.status == AgentRunStatusV1::Completed && state.completed_at.is_none() {
        issues.push(issue(
            "$.completedAt",
            "completed agent state requires completedAt",
        ));
    }
    if state.status == AgentRunStatusV1::Failed && state.error.is_none() {
        issues.push(issue("$.error", "failed agent state requires error"));
    }
    validate_created_at_path(&state.started_at, "$.startedAt", &mut issues);
    validate_created_at_path(&state.updated_at, "$.updatedAt", &mut issues);
    if let Some(completed_at) = &state.completed_at {
        validate_created_at_path(completed_at, "$.completedAt", &mut issues);
    }
    verify_runtime_signature(
        &state.signature,
        &expected_signature,
        DEV_AGENT_RUN_STATE_SIGNATURE_PREFIX,
        &mut issues,
        "AgentRunStateV1 signature does not match canonical dev signature",
    );

    AgentRunStateVerificationV1 {
        schema_version: AGENT_RUN_STATE_VERIFICATION_SCHEMA_VERSION.to_string(),
        run_id: state.run_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: now_rfc3339(),
    }
}

pub fn human_approval_request_for_invocation(
    invocation: &ToolInvocationV1,
    reason: impl Into<String>,
    risk_summary: Vec<String>,
    policy_evidence_refs: Vec<String>,
) -> HumanApprovalRequestV1 {
    let mut request = HumanApprovalRequestV1 {
        schema_version: HUMAN_APPROVAL_REQUEST_SCHEMA_VERSION.to_string(),
        approval_id: String::new(),
        agent_run_id: invocation.agent_run_id.clone(),
        invocation_id: Some(invocation.invocation_id.clone()),
        action_type: HumanApprovalActionV1::ToolCall,
        requested_by: invocation.agent_id.clone(),
        approver: None,
        status: HumanApprovalStatusV1::Pending,
        reason: reason.into(),
        requested_action: json!({
            "toolRef": invocation.tool_ref,
            "toolName": invocation.tool_name,
            "argumentHash": invocation.argument_hash,
            "inputRefs": invocation.input_refs
        }),
        risk_summary,
        policy_evidence_refs,
        requested_at: now_rfc3339(),
        resolved_at: None,
        decision_reason: None,
        signature: String::new(),
    };
    sign_human_approval_request(&mut request);
    request
}

pub fn resolve_human_approval_request(
    request: &mut HumanApprovalRequestV1,
    approved: bool,
    approver: impl Into<String>,
    decision_reason: impl Into<String>,
) {
    request.status = if approved {
        HumanApprovalStatusV1::Approved
    } else {
        HumanApprovalStatusV1::Rejected
    };
    request.approver = Some(approver.into());
    request.resolved_at = Some(now_rfc3339());
    request.decision_reason = Some(decision_reason.into());
    sign_human_approval_request(request);
}

pub fn sign_human_approval_request(request: &mut HumanApprovalRequestV1) {
    request.signature = expected_human_approval_request_signature(request);
    request.approval_id = canonical_human_approval_request_id(request);
}

pub fn expected_human_approval_request_signature(request: &HumanApprovalRequestV1) -> String {
    runtime_dev_signature(
        DEV_HUMAN_APPROVAL_SIGNATURE_PREFIX,
        &human_approval_request_signing_value(request),
    )
}

pub fn canonical_human_approval_request_id(request: &HumanApprovalRequestV1) -> String {
    stable_id("human-approval", &human_approval_request_id_value(request))
}

pub fn verify_human_approval_request(
    request: &HumanApprovalRequestV1,
) -> HumanApprovalRequestVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_signature = expected_human_approval_request_signature(request);
    if request.schema_version != HUMAN_APPROVAL_REQUEST_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {HUMAN_APPROVAL_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.approvalId", &request.approval_id);
    if !request.approval_id.trim().is_empty()
        && request.approval_id != canonical_human_approval_request_id(request)
    {
        issues.push(issue(
            "$.approvalId",
            "Human approval id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.agentRunId", &request.agent_run_id);
    require_non_empty(&mut issues, "$.requestedBy", &request.requested_by);
    require_non_empty(&mut issues, "$.reason", &request.reason);
    if request.risk_summary.is_empty() {
        warnings.push(issue(
            "$.riskSummary",
            "Human approval request should summarize user-visible risk",
        ));
    }
    if request.status == HumanApprovalStatusV1::Pending && request.resolved_at.is_some() {
        issues.push(issue(
            "$.resolvedAt",
            "Pending approval must not include resolvedAt",
        ));
    }
    if matches!(
        request.status,
        HumanApprovalStatusV1::Approved | HumanApprovalStatusV1::Rejected
    ) {
        if request
            .approver
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
        {
            issues.push(issue("$.approver", "Resolved approval requires approver"));
        }
        if request.resolved_at.is_none() {
            issues.push(issue(
                "$.resolvedAt",
                "Resolved approval requires resolvedAt",
            ));
        }
    }
    validate_refs(
        "$.policyEvidenceRefs",
        &request.policy_evidence_refs,
        &mut issues,
        &mut warnings,
    );
    validate_created_at_path(&request.requested_at, "$.requestedAt", &mut issues);
    if let Some(resolved_at) = &request.resolved_at {
        validate_created_at_path(resolved_at, "$.resolvedAt", &mut issues);
    }
    verify_runtime_signature(
        &request.signature,
        &expected_signature,
        DEV_HUMAN_APPROVAL_SIGNATURE_PREFIX,
        &mut issues,
        "HumanApprovalRequestV1 signature does not match canonical dev signature",
    );

    HumanApprovalRequestVerificationV1 {
        schema_version: HUMAN_APPROVAL_REQUEST_VERIFICATION_SCHEMA_VERSION.to_string(),
        approval_id: request.approval_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: now_rfc3339(),
    }
}

pub fn memory_write_from_content(
    agent_run_id: impl Into<String>,
    agent_id: impl Into<String>,
    namespace: impl Into<String>,
    content: &Value,
    content_ref: Option<String>,
    retention: MemoryRetentionV1,
    privacy: PrivacyTier,
    policy_evidence_refs: Vec<String>,
) -> MemoryWriteV1 {
    let namespace = namespace.into();
    let allowed = memory_write_policy_allows(&namespace, &privacy, &policy_evidence_refs);
    let mut write = MemoryWriteV1 {
        schema_version: MEMORY_WRITE_SCHEMA_VERSION.to_string(),
        memory_write_id: String::new(),
        agent_run_id: agent_run_id.into(),
        agent_id: agent_id.into(),
        namespace,
        content_hash: hash_json_value(content),
        content_ref,
        retention,
        privacy,
        policy_evidence_refs,
        allowed,
        created_at: now_rfc3339(),
        signature: String::new(),
    };
    sign_memory_write(&mut write);
    write
}

pub fn memory_write_policy_allows(
    namespace: &str,
    privacy: &PrivacyTier,
    policy_evidence_refs: &[String],
) -> bool {
    !namespace.trim().is_empty()
        && (matches!(privacy, PrivacyTier::Public | PrivacyTier::Standard)
            || !policy_evidence_refs.is_empty())
}

pub fn sign_memory_write(write: &mut MemoryWriteV1) {
    write.signature = expected_memory_write_signature(write);
    write.memory_write_id = canonical_memory_write_id(write);
}

pub fn expected_memory_write_signature(write: &MemoryWriteV1) -> String {
    runtime_dev_signature(
        DEV_MEMORY_WRITE_SIGNATURE_PREFIX,
        &memory_write_signing_value(write),
    )
}

pub fn canonical_memory_write_id(write: &MemoryWriteV1) -> String {
    stable_id("memory-write", &memory_write_signing_value(write))
}

pub fn verify_memory_write(write: &MemoryWriteV1) -> MemoryWriteVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_signature = expected_memory_write_signature(write);
    if write.schema_version != MEMORY_WRITE_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {MEMORY_WRITE_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.memoryWriteId", &write.memory_write_id);
    if !write.memory_write_id.trim().is_empty()
        && write.memory_write_id != canonical_memory_write_id(write)
    {
        issues.push(issue(
            "$.memoryWriteId",
            "Memory write id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.agentRunId", &write.agent_run_id);
    require_non_empty(&mut issues, "$.agentId", &write.agent_id);
    require_non_empty(&mut issues, "$.namespace", &write.namespace);
    require_non_empty(&mut issues, "$.contentHash", &write.content_hash);
    if let Some(content_ref) = &write.content_ref {
        validate_ref(
            "$.contentRef".to_string(),
            content_ref,
            &mut issues,
            &mut warnings,
        );
    }
    validate_refs(
        "$.policyEvidenceRefs",
        &write.policy_evidence_refs,
        &mut issues,
        &mut warnings,
    );
    if write.allowed
        != memory_write_policy_allows(
            &write.namespace,
            &write.privacy,
            &write.policy_evidence_refs,
        )
    {
        issues.push(issue(
            "$.allowed",
            "Memory write allowed flag does not match local policy check",
        ));
    }
    if !write.allowed {
        warnings.push(issue(
            "$.allowed",
            "Memory write is a signed audit record for a blocked write",
        ));
    }
    validate_created_at_path(&write.created_at, "$.createdAt", &mut issues);
    verify_runtime_signature(
        &write.signature,
        &expected_signature,
        DEV_MEMORY_WRITE_SIGNATURE_PREFIX,
        &mut issues,
        "MemoryWriteV1 signature does not match canonical dev signature",
    );

    MemoryWriteVerificationV1 {
        schema_version: MEMORY_WRITE_VERIFICATION_SCHEMA_VERSION.to_string(),
        memory_write_id: write.memory_write_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: now_rfc3339(),
    }
}

pub fn list_workflow_records(workflow_dir: &Path) -> anyhow::Result<WorkflowRecordStoreSummaryV1> {
    let mut files = Vec::new();
    collect_workflow_record_files(workflow_dir, &mut files)?;
    files.sort();

    let mut records = Vec::new();
    let mut tool_count = 0;
    let mut workflow_count = 0;
    let mut valid_count = 0;
    let mut approval_required_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(document) = read_workflow_record_file(&path)? else {
            continue;
        };
        let path_string = path.display().to_string();
        match document {
            WorkflowRecordDocument::Tool(tool) => {
                let verification = verify_tool_manifest(&tool);
                let mutable_refs = mutable_tool_refs(&tool);
                if verification.valid {
                    valid_count += 1;
                }
                tool_count += 1;
                mutable_ref_count += mutable_refs.len();
                warning_count += verification.warnings.len();
                records.push(tool_index_entry(
                    &tool,
                    &verification,
                    mutable_refs.len(),
                    path_string,
                ));
            }
            WorkflowRecordDocument::Workflow(workflow) => {
                let verification = verify_workflow_manifest(&workflow);
                let plan = workflow_plan(&workflow);
                let mutable_refs = mutable_workflow_refs(&workflow);
                if verification.valid {
                    valid_count += 1;
                }
                if plan.approval_required {
                    approval_required_count += 1;
                }
                workflow_count += 1;
                mutable_ref_count += mutable_refs.len();
                warning_count += verification.warnings.len() + plan.warnings.len();
                records.push(workflow_index_entry(
                    &workflow,
                    &verification,
                    &plan,
                    mutable_refs.len(),
                    path_string,
                ));
            }
        }
    }

    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.record_id.cmp(&right.record_id))
            .then(left.path.cmp(&right.path))
    });

    Ok(WorkflowRecordStoreSummaryV1 {
        schema_version: "swarm-ai.workflow-record-store-summary.v1".to_string(),
        root: workflow_dir.display().to_string(),
        tool_count,
        workflow_count,
        record_count: records.len(),
        valid_count,
        invalid_count: records.len().saturating_sub(valid_count),
        approval_required_count,
        mutable_ref_count,
        warning_count,
        records,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_workflow_record(
    workflow_dir: &Path,
    record_id: &str,
) -> anyhow::Result<Option<WorkflowRecordLookupV1>> {
    let record_id = record_id.trim();
    if record_id.is_empty() {
        anyhow::bail!("recordId is required");
    }

    let mut files = Vec::new();
    collect_workflow_record_files(workflow_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(document) = read_workflow_record_file(&path)? else {
            continue;
        };
        match document {
            WorkflowRecordDocument::Tool(tool) if tool.tool_id == record_id => {
                let verification = verify_tool_manifest(&tool);
                return Ok(Some(WorkflowRecordLookupV1 {
                    schema_version: "swarm-ai.workflow-record-lookup.v1".to_string(),
                    record_id: tool.tool_id.clone(),
                    record_type: WorkflowRecordType::Tool,
                    tool: Some(tool),
                    workflow: None,
                    tool_verification: Some(verification),
                    workflow_verification: None,
                    workflow_plan: None,
                    path: path.display().to_string(),
                }));
            }
            WorkflowRecordDocument::Workflow(workflow) if workflow.workflow_id == record_id => {
                let verification = verify_workflow_manifest(&workflow);
                let plan = workflow_plan(&workflow);
                return Ok(Some(WorkflowRecordLookupV1 {
                    schema_version: "swarm-ai.workflow-record-lookup.v1".to_string(),
                    record_id: workflow.workflow_id.clone(),
                    record_type: WorkflowRecordType::Workflow,
                    tool: None,
                    workflow: Some(workflow),
                    tool_verification: None,
                    workflow_verification: Some(verification),
                    workflow_plan: Some(plan),
                    path: path.display().to_string(),
                }));
            }
            _ => {}
        }
    }

    Ok(None)
}

enum WorkflowRecordDocument {
    Tool(ToolManifestV1),
    Workflow(WorkflowManifestV1),
}

fn collect_workflow_record_files(
    workflow_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    if !workflow_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(workflow_dir)
        .with_context(|| format!("failed to read {}", workflow_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_workflow_record_files(&path, files)?;
        } else if file_type.is_file() && is_json_path(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_json_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

fn read_workflow_record_file(path: &Path) -> anyhow::Result<Option<WorkflowRecordDocument>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    match schema_version {
        "swarm-ai.tool.v1" => serde_json::from_value(value)
            .map(WorkflowRecordDocument::Tool)
            .map(Some)
            .with_context(|| format!("failed to parse tool manifest {}", path.display())),
        "swarm-ai.workflow.v1" => serde_json::from_value(value)
            .map(WorkflowRecordDocument::Workflow)
            .map(Some)
            .with_context(|| format!("failed to parse workflow manifest {}", path.display())),
        _ => Ok(None),
    }
}

fn tool_index_entry(
    tool: &ToolManifestV1,
    verification: &ToolManifestVerificationV1,
    mutable_ref_count: usize,
    path: String,
) -> WorkflowRecordSummaryV1 {
    WorkflowRecordSummaryV1 {
        record_id: tool.tool_id.clone(),
        record_type: WorkflowRecordType::Tool,
        name: tool.name.clone(),
        publisher: tool.publisher.clone(),
        valid: verification.valid,
        warning_count: verification.warnings.len(),
        mutable_ref_count,
        signature_present: tool.signature.is_some(),
        created_at: tool.created_at.clone(),
        path,
    }
}

fn workflow_index_entry(
    workflow: &WorkflowManifestV1,
    verification: &WorkflowManifestVerificationV1,
    plan: &WorkflowPlanV1,
    mutable_ref_count: usize,
    path: String,
) -> WorkflowRecordSummaryV1 {
    WorkflowRecordSummaryV1 {
        record_id: workflow.workflow_id.clone(),
        record_type: WorkflowRecordType::Workflow,
        name: workflow.name.clone(),
        publisher: workflow.publisher.clone(),
        valid: verification.valid,
        warning_count: verification.warnings.len() + plan.warnings.len(),
        mutable_ref_count,
        signature_present: workflow.signature.is_some(),
        created_at: workflow.created_at.clone(),
        path,
    }
}

fn mutable_tool_refs(tool: &ToolManifestV1) -> Vec<String> {
    let mut refs = tool
        .safety_policy_refs
        .iter()
        .filter(|reference| looks_mutable_ref(reference))
        .cloned()
        .collect::<Vec<_>>();
    dedup(&mut refs);
    refs
}

fn mutable_workflow_refs(workflow: &WorkflowManifestV1) -> Vec<String> {
    let mut refs = workflow_refs(workflow)
        .into_iter()
        .filter(|reference| looks_mutable_ref(reference))
        .collect::<Vec<_>>();
    dedup(&mut refs);
    refs
}

fn workflow_refs(workflow: &WorkflowManifestV1) -> Vec<String> {
    let mut refs = workflow
        .steps
        .iter()
        .map(|step| step.reference.clone())
        .chain(
            workflow
                .dependencies
                .iter()
                .map(|dependency| dependency.reference.clone()),
        )
        .collect::<Vec<_>>();
    dedup(&mut refs);
    refs
}

fn append_workflow_refs(
    steps: &mut Vec<WorkflowStepV1>,
    dependencies: &mut Vec<WorkflowDependencyV1>,
    prefix: &str,
    kind: WorkflowStepKind,
    mut refs: Vec<String>,
) {
    refs.sort();
    refs.dedup();
    for reference in refs {
        let step_id = format!("{prefix}-{}", steps.len() + 1);
        steps.push(WorkflowStepV1 {
            step_id: step_id.clone(),
            name: format!("{prefix} step {}", steps.len() + 1),
            kind: kind.clone(),
            reference: reference.clone(),
            input_mapping: json!({}),
            depends_on: steps
                .last()
                .map(|previous| vec![previous.step_id.clone()])
                .unwrap_or_default(),
            required: true,
            timeout_ms: None,
        });
        dependencies.push(WorkflowDependencyV1 {
            name: step_id,
            reference,
            kind: kind.clone(),
            version: None,
        });
    }
}

fn tool_signing_value(tool: &ToolManifestV1) -> Value {
    let mut value = serde_json::to_value(tool).expect("tool manifest should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("toolId");
        object.remove("signature");
    }
    value
}

fn workflow_signing_value(workflow: &WorkflowManifestV1) -> Value {
    let mut value = serde_json::to_value(workflow).expect("workflow manifest should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("workflowId");
        object.remove("signature");
    }
    value
}

fn tool_invocation_signing_value(invocation: &ToolInvocationV1) -> Value {
    let mut value = serde_json::to_value(invocation).expect("tool invocation should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("invocationId");
        object.remove("signature");
    }
    value
}

fn tool_result_signing_value(result: &ToolResultV1) -> Value {
    let mut value = serde_json::to_value(result).expect("tool result should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("resultId");
        object.remove("signature");
    }
    value
}

fn agent_run_state_signing_value(state: &AgentRunStateV1) -> Value {
    let mut value = serde_json::to_value(state).expect("agent run state should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("signature");
        if state.run_id.starts_with("agent-run-") || state.run_id.trim().is_empty() {
            object.remove("runId");
        }
    }
    value
}

fn human_approval_request_signing_value(request: &HumanApprovalRequestV1) -> Value {
    let mut value = serde_json::to_value(request).expect("human approval request should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("approvalId");
        object.remove("signature");
    }
    value
}

fn human_approval_request_id_value(request: &HumanApprovalRequestV1) -> Value {
    let mut value = serde_json::to_value(request).expect("human approval request should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("approvalId");
        object.remove("signature");
        object.remove("approver");
        object.remove("status");
        object.remove("resolvedAt");
        object.remove("decisionReason");
    }
    value
}

fn memory_write_signing_value(write: &MemoryWriteV1) -> Value {
    let mut value = serde_json::to_value(write).expect("memory write should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("memoryWriteId");
        object.remove("signature");
    }
    value
}

fn runtime_dev_signature(prefix: &str, value: &Value) -> String {
    format!(
        "{prefix}:{}",
        hash_canonical_json(&canonicalize_json(value))
    )
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("workflow object should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: &'static str, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn validate_permissions(
    base_path: &str,
    permissions: &[PermissionRequest],
    issues: &mut Vec<ValidationIssue>,
) {
    for (index, permission) in permissions.iter().enumerate() {
        let path = format!("{base_path}[{index}].name");
        if permission.name.trim().is_empty() {
            issues.push(issue(path, "Permission name is required"));
        }
    }
}

fn required_tool_permissions(tool: &ToolManifestV1) -> Vec<String> {
    let mut permissions = tool
        .permissions
        .iter()
        .filter(|permission| permission.required)
        .map(|permission| permission.name.clone())
        .collect::<Vec<_>>();
    if permissions.is_empty() {
        permissions = tool
            .permissions
            .iter()
            .map(|permission| permission.name.clone())
            .collect();
    }
    dedup(&mut permissions);
    permissions
}

fn grant_matches_tool_call(
    grant: &ToolPermissionGrantV1,
    agent_id: &str,
    package_id: &str,
    tool_ref: &str,
) -> bool {
    grant.tool_ref == tool_ref
        && grant.granted_to == agent_id
        && grant.package_id == package_id
        && !grant_expired(grant)
}

fn grant_expired(grant: &ToolPermissionGrantV1) -> bool {
    let Some(expires_at) = grant.expires_at.as_deref() else {
        return false;
    };
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .map(|expires_at| expires_at.with_timezone(&Utc) < Utc::now())
        .unwrap_or(true)
}

fn validate_created_at_path(
    created_at: &str,
    path: &'static str,
    issues: &mut Vec<ValidationIssue>,
) {
    if chrono::DateTime::parse_from_rfc3339(created_at).is_err() {
        issues.push(issue(path, "Timestamp must be an RFC3339 timestamp"));
    }
}

fn verify_runtime_signature(
    signature: &str,
    expected_signature: &str,
    expected_prefix: &str,
    issues: &mut Vec<ValidationIssue>,
    mismatch_message: &'static str,
) {
    let signature = signature.trim();
    if signature.is_empty() {
        issues.push(issue("$.signature", "Signature is required"));
    } else if signature == expected_signature {
    } else if signature.starts_with(expected_prefix) {
        issues.push(issue("$.signature", mismatch_message));
    } else {
        issues.push(issue(
            "$.signature",
            "Signature is not a supported local-dev workflow runtime signature",
        ));
    }
}

fn hash_json_value(value: &Value) -> String {
    hash_canonical_json(&canonicalize_json(value))
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn touch_agent_state(state: &mut AgentRunStateV1) {
    state.updated_at = now_rfc3339();
    sign_agent_run_state(state);
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn validate_workflow_graph(workflow: &WorkflowManifestV1, issues: &mut Vec<ValidationIssue>) {
    let mut seen = BTreeSet::new();
    for (index, step) in workflow.steps.iter().enumerate() {
        let base = format!("$.steps[{index}]");
        if step.step_id.trim().is_empty() {
            issues.push(issue(format!("{base}.stepId"), "Step id is required"));
        }
        if !seen.insert(step.step_id.clone()) {
            issues.push(issue(format!("{base}.stepId"), "Step id must be unique"));
        }
        require_non_empty_owned(issues, format!("{base}.name"), &step.name);
        require_non_empty_owned(issues, format!("{base}.ref"), &step.reference);
        if !step.input_mapping.is_object() {
            issues.push(issue(
                format!("{base}.inputMapping"),
                "inputMapping must be an object",
            ));
        }
        for dependency in &step.depends_on {
            if !workflow
                .steps
                .iter()
                .any(|candidate| candidate.step_id == *dependency)
            {
                issues.push(issue(
                    format!("{base}.dependsOn"),
                    "Step dependency does not reference a workflow step",
                ));
            }
        }
    }
}

fn require_non_empty_owned(issues: &mut Vec<ValidationIssue>, path: String, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn validate_refs_for_workflow(
    workflow: &WorkflowManifestV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    for (index, step) in workflow.steps.iter().enumerate() {
        validate_ref(
            format!("$.steps[{index}].ref"),
            &step.reference,
            issues,
            warnings,
        );
    }
    for (index, dependency) in workflow.dependencies.iter().enumerate() {
        validate_ref(
            format!("$.dependencies[{index}].ref"),
            &dependency.reference,
            issues,
            warnings,
        );
    }
}

fn validate_refs(
    base_path: &str,
    refs: &[String],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    for (index, reference) in refs.iter().enumerate() {
        validate_ref(format!("{base_path}[{index}]"), reference, issues, warnings);
    }
}

fn validate_ref(
    path: String,
    reference: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if reference.trim().is_empty() {
        issues.push(issue(path, "Reference must not be empty"));
    } else if !looks_like_ref(reference) {
        warnings.push(issue(
            path,
            "Reference is not a recognized bzz://, local://, ipfs://, sha256://, or https:// reference",
        ));
    } else if looks_mutable_ref(reference) {
        warnings.push(issue(
            path,
            "Mutable reference should be resolved to immutable content before exact replay",
        ));
    }
}

fn validate_created_at(created_at: &str, issues: &mut Vec<ValidationIssue>) {
    if chrono::DateTime::parse_from_rfc3339(created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "createdAt must be an RFC3339 timestamp",
        ));
    }
}

fn verify_signature(
    signature: Option<&str>,
    domain: &str,
    signing_value: &Value,
    expected_signer: &str,
    expected_signature: &mut Option<String>,
    issues: &mut Vec<ValidationIssue>,
    mismatch_message: &'static str,
) {
    let Some(signature) = signature else {
        return;
    };
    if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
        let verification = hivemind_identity::verify_value_signature_string(
            signature,
            domain,
            signing_value,
            Some(expected_signer),
        );
        *expected_signature = Some(format!(
            "ed25519-payload-hash:{}",
            verification.payload_hash
        ));
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if Some(signature) != expected_signature.as_deref() {
        issues.push(issue("$.signature", mismatch_message));
    }
}

fn looks_like_ref(reference: &str) -> bool {
    reference.starts_with("bzz://")
        || reference.starts_with("local://")
        || reference.starts_with("ipfs://")
        || reference.starts_with("sha256://")
        || reference.starts_with("https://")
}

fn looks_mutable_ref(reference: &str) -> bool {
    reference.starts_with("https://")
        || reference.contains(":latest")
        || reference.contains("/latest")
        || reference.contains(":stable")
        || reference.contains("/stable")
}

fn signature_issue_path(path: &str) -> String {
    if path == "$" {
        return "$.signature".to_string();
    }
    if let Some(rest) = path.strip_prefix("$.") {
        return format!("$.signature.{rest}");
    }
    format!("$.signature.{path}")
}

fn dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_signed_tool_manifest() {
        let tool = create_tool_manifest(ToolManifestInitOptionsV1 {
            name: "Repository Search".to_string(),
            description: "Searches a repository index".to_string(),
            publisher: "0xToolPublisher".to_string(),
            execution_modes: vec![ToolExecutionMode::Local],
            safety_policy_refs: vec!["bzz://safety-policy".to_string()],
            permissions: vec![PermissionRequest {
                name: "filesystem-read".to_string(),
                purpose: Some("Read indexed repository files".to_string()),
                required: true,
                limits: json!({ "scope": "workspace" }),
            }],
        });

        let verification = verify_tool_manifest(&tool);

        assert!(verification.valid, "{verification:#?}");
        assert!(tool.tool_id.starts_with("tool-"));
        assert_eq!(
            tool.signature.as_deref(),
            Some(expected_tool_signature(&tool).as_str())
        );
    }

    #[test]
    fn identity_signed_workflow_verifies_and_detects_tampering() {
        let mut workflow = workflow();
        let identity =
            hivemind_identity::identity_from_seed("0xWorkflowPublisher", b"workflow-seed").unwrap();

        let envelope = sign_workflow_with_identity(&mut workflow, &identity).unwrap();
        let verification = verify_workflow_manifest(&workflow);

        assert_eq!(envelope.signer, workflow.publisher);
        assert!(verification.valid, "{verification:#?}");

        workflow.steps[0].reference = "bzz://changed-tool".to_string();
        let tampered = verify_workflow_manifest(&workflow);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.workflowId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn workflow_plan_collects_refs_and_detects_graph_errors() {
        let mut workflow = workflow();
        workflow.steps.push(WorkflowStepV1 {
            step_id: "approval".to_string(),
            name: "Approve action".to_string(),
            kind: WorkflowStepKind::HumanApproval,
            reference: "local://approval/manual".to_string(),
            input_mapping: json!({}),
            depends_on: vec!["missing-step".to_string()],
            required: true,
            timeout_ms: None,
        });
        sign_workflow_manifest(&mut workflow);

        let plan = workflow_plan(&workflow);

        assert!(!plan.valid);
        assert!(plan.approval_required);
        assert!(plan.tool_refs.contains(&"bzz://tool".to_string()));
        assert!(plan.package_refs.contains(&"bzz://package".to_string()));
        assert!(plan.vector_store_refs.contains(&"bzz://vector".to_string()));
    }

    #[test]
    fn agent_tool_runtime_requires_permission_and_records_result() {
        let tool = protected_tool();
        let denied = tool_invocation_from_manifest(
            "agent-run-1",
            "agent-1",
            "agent/package",
            "bzz://repo-tool",
            &tool,
            json!({ "query": "secret" }),
            vec!["bzz://input-context".to_string()],
            &[],
            false,
            vec!["local://policy/tool-runtime".to_string()],
        );

        assert!(!denied.policy_decision.allowed);
        assert_eq!(
            denied.approval_status,
            ToolInvocationApprovalStatusV1::Denied
        );
        assert!(!tool_invocation_can_execute(&denied, None));
        assert!(verify_tool_invocation(&denied).valid);

        let refused = tool_result_from_invocation(
            &denied,
            ToolResultStatusV1::Refused,
            json!({}),
            Vec::new(),
            Some(StandardErrorCodeV1::PolicyBlocked),
            Some("Tool permission grant is missing".to_string()),
        );
        assert!(verify_tool_result(&refused).valid);

        let grant = hivemind_policy::tool_permission_grant(
            "bzz://repo-tool",
            "agent/package",
            "agent-1",
            vec!["local.shell".to_string()],
            json!({ "workspace": "repo" }),
            now_rfc3339(),
            None,
        );
        let allowed = tool_invocation_from_manifest(
            "agent-run-1",
            "agent-1",
            "agent/package",
            "bzz://repo-tool",
            &tool,
            json!({ "query": "status" }),
            Vec::new(),
            &[grant],
            false,
            vec!["local://policy/tool-runtime".to_string()],
        );
        assert!(allowed.policy_decision.allowed);
        assert!(tool_invocation_can_execute(&allowed, None));
        assert!(verify_tool_invocation(&allowed).valid);

        let result = tool_result_from_invocation(
            &allowed,
            ToolResultStatusV1::Succeeded,
            json!({ "matches": [] }),
            vec!["bzz://tool-output".to_string()],
            None,
            None,
        );
        assert!(verify_tool_result(&result).valid);

        let mut state = agent_run_state(
            "agent-run-1",
            "agent-1",
            Some("bzz://workflow".to_string()),
            Some("bzz://agent-package".to_string()),
        );
        record_agent_tool_invocation(&mut state, &allowed);
        record_agent_tool_result(&mut state, &result);
        complete_agent_run(&mut state, Some("local://receipt/agent-run-1".to_string()));
        let verification = verify_agent_run_state(&state);
        assert!(verification.valid, "{verification:#?}");
        assert_eq!(state.status, AgentRunStatusV1::Completed);
        assert!(state.tool_invocation_ids.contains(&allowed.invocation_id));
        assert!(state.tool_result_ids.contains(&result.result_id));
    }

    #[test]
    fn human_approval_pauses_and_resumes_agent_run() {
        let tool = protected_tool();
        let grant = hivemind_policy::tool_permission_grant(
            "bzz://repo-tool",
            "agent/package",
            "agent-1",
            vec!["local.shell".to_string()],
            json!({ "workspace": "repo" }),
            now_rfc3339(),
            None,
        );
        let invocation = tool_invocation_from_manifest(
            "agent-run-approval",
            "agent-1",
            "agent/package",
            "bzz://repo-tool",
            &tool,
            json!({ "command": "delete branch" }),
            Vec::new(),
            &[grant],
            true,
            vec!["local://policy/tool-runtime".to_string()],
        );
        let mut approval = human_approval_request_for_invocation(
            &invocation,
            "Approve shell-like repository action",
            vec!["The tool can read and modify repository state".to_string()],
            vec!["local://policy/tool-runtime".to_string()],
        );

        let mut state = agent_run_state(
            "agent-run-approval",
            "agent-1",
            Some("bzz://workflow".to_string()),
            None,
        );
        record_agent_tool_invocation(&mut state, &invocation);
        record_agent_pending_approval(&mut state, &approval);
        assert_eq!(state.status, AgentRunStatusV1::WaitingForHuman);
        assert!(!tool_invocation_can_execute(&invocation, None));
        assert!(verify_agent_run_state(&state).valid);
        assert!(verify_human_approval_request(&approval).valid);

        resolve_human_approval_request(
            &mut approval,
            true,
            "0xHumanApprover",
            "User approved the scoped repository action",
        );
        assert!(tool_invocation_can_execute(&invocation, Some(&approval)));
        resume_agent_after_approval(&mut state, &approval);

        assert_eq!(state.status, AgentRunStatusV1::Running);
        assert!(state.pending_approval_ids.is_empty());
        assert!(verify_human_approval_request(&approval).valid);
        assert!(verify_agent_run_state(&state).valid);
    }

    #[test]
    fn memory_writes_are_scoped_signed_and_policy_checked() {
        let allowed = memory_write_from_content(
            "agent-run-memory",
            "agent-1",
            "project/readme",
            &json!({ "fact": "Hivemind stores audit history on Swarm" }),
            Some("bzz://memory-chunk".to_string()),
            MemoryRetentionV1::Project,
            PrivacyTier::LocalOnly,
            vec!["local://policy/memory".to_string()],
        );
        assert!(allowed.allowed);
        assert!(verify_memory_write(&allowed).valid);

        let blocked = memory_write_from_content(
            "agent-run-memory",
            "agent-1",
            "private/session",
            &json!({ "secret": true }),
            None,
            MemoryRetentionV1::Session,
            PrivacyTier::LocalOnly,
            Vec::new(),
        );
        let verification = verify_memory_write(&blocked);
        assert!(verification.valid, "{verification:#?}");
        assert!(!blocked.allowed);
        assert!(!verification.warnings.is_empty());

        let mut tampered = allowed.clone();
        tampered.namespace = "project/other".to_string();
        let tampered_verification = verify_memory_write(&tampered);
        assert!(!tampered_verification.valid);
        assert!(
            tampered_verification
                .issues
                .iter()
                .any(|issue| { issue.path == "$.memoryWriteId" || issue.path == "$.signature" })
        );
    }

    #[test]
    fn unsigned_tool_still_requires_canonical_id() {
        let mut tool = create_tool_manifest(ToolManifestInitOptionsV1 {
            name: "Search".to_string(),
            description: "Searches content".to_string(),
            publisher: "0xToolPublisher".to_string(),
            execution_modes: vec![ToolExecutionMode::Local],
            safety_policy_refs: Vec::new(),
            permissions: Vec::new(),
        });
        tool.signature = None;
        tool.description = "changed".to_string();

        let verification = verify_tool_manifest(&tool);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.toolId")
        );
    }

    #[test]
    fn workflow_record_store_lists_and_gets_tools_and_workflows() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-workflow-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let mut tool = create_tool_manifest(ToolManifestInitOptionsV1 {
            name: "Repository Search".to_string(),
            description: "Searches a repository index".to_string(),
            publisher: "0xToolPublisher".to_string(),
            execution_modes: vec![ToolExecutionMode::Local],
            safety_policy_refs: vec!["https://example.com/policies/latest".to_string()],
            permissions: Vec::new(),
        });
        sign_tool_manifest(&mut tool);

        let mut workflow = workflow();
        workflow.steps.push(WorkflowStepV1 {
            step_id: "approval".to_string(),
            name: "Approve answer".to_string(),
            kind: WorkflowStepKind::HumanApproval,
            reference: "local://approval/manual".to_string(),
            input_mapping: json!({}),
            depends_on: vec!["package-3".to_string()],
            required: true,
            timeout_ms: None,
        });
        sign_workflow_manifest(&mut workflow);

        fs::write(
            dir.join("repo-search.tool.json"),
            serde_json::to_vec_pretty(&tool).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("nested").join("rag.workflow.json"),
            serde_json::to_vec_pretty(&workflow).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity.keypair.v1",
                "subject": "0xToolPublisher"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_workflow_records(&dir).unwrap();
        assert_eq!(summary.tool_count, 1);
        assert_eq!(summary.workflow_count, 1);
        assert_eq!(summary.record_count, 2);
        assert_eq!(summary.valid_count, 2);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.approval_required_count, 1);
        assert_eq!(summary.mutable_ref_count, 1);
        assert!(summary.warning_count > 0);

        let tool_lookup = get_workflow_record(&dir, &tool.tool_id).unwrap().unwrap();
        assert_eq!(tool_lookup.record_type, WorkflowRecordType::Tool);
        assert!(tool_lookup.tool_verification.unwrap().valid);
        assert!(tool_lookup.tool.is_some());
        assert!(tool_lookup.workflow.is_none());

        let workflow_lookup = get_workflow_record(&dir, &workflow.workflow_id)
            .unwrap()
            .unwrap();
        assert_eq!(workflow_lookup.record_type, WorkflowRecordType::Workflow);
        assert!(workflow_lookup.workflow_verification.unwrap().valid);
        assert!(workflow_lookup.workflow_plan.unwrap().approval_required);
        assert!(workflow_lookup.workflow.is_some());
        assert!(workflow_lookup.tool.is_none());
        assert!(get_workflow_record(&dir, "missing").unwrap().is_none());

        let _ = fs::remove_dir_all(dir);
    }

    fn workflow() -> WorkflowManifestV1 {
        create_workflow_manifest(WorkflowManifestInitOptionsV1 {
            name: "RAG answer workflow".to_string(),
            publisher: "0xWorkflowPublisher".to_string(),
            tool_refs: vec!["bzz://tool".to_string()],
            package_refs: vec!["bzz://package".to_string()],
            vector_store_refs: vec!["bzz://vector".to_string()],
            failure_policy: Some(WorkflowFailurePolicy::FailFast),
            trace_policy: Some(WorkflowTracePolicy::Full),
        })
    }

    fn protected_tool() -> ToolManifestV1 {
        create_tool_manifest(ToolManifestInitOptionsV1 {
            name: "Repository Shell".to_string(),
            description: "Runs a restricted repository command".to_string(),
            publisher: "0xToolPublisher".to_string(),
            execution_modes: vec![ToolExecutionMode::Local],
            safety_policy_refs: vec!["bzz://safety-policy".to_string()],
            permissions: vec![PermissionRequest {
                name: "local.shell".to_string(),
                purpose: Some("Run restricted repository commands".to_string()),
                required: true,
                limits: json!({ "workspace": "repo" }),
            }],
        })
    }
}
