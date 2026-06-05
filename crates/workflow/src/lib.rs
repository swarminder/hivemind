use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    PermissionRequest, PriceV1, ValidationIssue, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_TOOL_SIGNATURE_PREFIX: &str = "dev-tool-signature-v1";
const DEV_WORKFLOW_SIGNATURE_PREFIX: &str = "dev-workflow-signature-v1";

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
}
