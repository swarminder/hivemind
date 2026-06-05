use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{
    ErrorCode, ExecutionLeaseRequestV1, ExecutionLeaseV1, ExecutionResponseV1, ExecutionStatus,
    JobOrderV1, JobQuoteV1, SwarmAiErrorV1, ValidationIssue,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JobRecordStatusV1 {
    Created,
    Quoted,
    Leased,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: JobRecordStatusV1,
    #[serde(rename = "jobOrder")]
    pub job_order: JobOrderV1,
    #[serde(default)]
    pub quotes: Vec<JobQuoteV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<ExecutionLeaseV1>,
    #[serde(
        rename = "executionStatus",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub execution_status: Option<ExecutionStatus>,
    #[serde(
        rename = "selectedRouteId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub selected_route_id: Option<String>,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(
        rename = "receiptRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receipt_ref: Option<String>,
    #[serde(rename = "streamRef", default, skip_serializing_if = "Option::is_none")]
    pub stream_ref: Option<String>,
    #[serde(
        rename = "streamEventCount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_event_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SwarmAiErrorV1>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStoreEntryV1 {
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: JobRecordStatusV1,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub task: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(rename = "jobPath")]
    pub job_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "jobCount")]
    pub job_count: usize,
    pub jobs: Vec<JobStoreEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobLookupResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "jobPath")]
    pub job_path: String,
    pub record: JobRecordV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobCancellationRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "cancelledBy")]
    pub cancelled_by: String,
    pub reason: String,
    #[serde(
        rename = "requestedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub requested_at: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobCancellationResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "transitioned")]
    pub transitioned: bool,
    #[serde(rename = "terminalAlready")]
    pub terminal_already: bool,
    #[serde(rename = "previousStatus")]
    pub previous_status: JobRecordStatusV1,
    #[serde(rename = "currentStatus")]
    pub current_status: JobRecordStatusV1,
    pub record: JobRecordV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobExpirationSweepRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(
        rename = "observedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub observed_at: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JobExpirationKindV1 {
    QuoteExpired,
    LeaseExpired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobExpirationEntryV1 {
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "expirationKind")]
    pub expiration_kind: JobExpirationKindV1,
    #[serde(rename = "expiredAt")]
    pub expired_at: String,
    #[serde(rename = "previousStatus")]
    pub previous_status: JobRecordStatusV1,
    #[serde(rename = "currentStatus")]
    pub current_status: JobRecordStatusV1,
    pub record: JobRecordV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobExpirationSweepResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    #[serde(rename = "scannedJobCount")]
    pub scanned_job_count: usize,
    #[serde(rename = "expiredJobCount")]
    pub expired_job_count: usize,
    #[serde(rename = "expiredJobs")]
    pub expired_jobs: Vec<JobExpirationEntryV1>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStoreAuditRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(
        rename = "observedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub observed_at: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobAuditFindingV1 {
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: JobRecordStatusV1,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStaleCandidateV1 {
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: JobRecordStatusV1,
    #[serde(rename = "expirationKind")]
    pub expiration_kind: JobExpirationKindV1,
    #[serde(rename = "expiredAt")]
    pub expired_at: String,
    #[serde(rename = "evidenceRefs")]
    pub evidence_refs: Vec<JobLifecycleEvidenceRefV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStoreAuditSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    #[serde(rename = "jobCount")]
    pub job_count: usize,
    #[serde(rename = "activeJobCount")]
    pub active_job_count: usize,
    #[serde(rename = "terminalJobCount")]
    pub terminal_job_count: usize,
    #[serde(rename = "statusCounts")]
    pub status_counts: BTreeMap<String, usize>,
    #[serde(rename = "receiptLinkedJobCount")]
    pub receipt_linked_job_count: usize,
    #[serde(rename = "streamLinkedJobCount")]
    pub stream_linked_job_count: usize,
    #[serde(rename = "validationLinkedJobCount")]
    pub validation_linked_job_count: usize,
    #[serde(rename = "disputeLinkedJobCount")]
    pub dispute_linked_job_count: usize,
    #[serde(rename = "settlementLinkedJobCount")]
    pub settlement_linked_job_count: usize,
    #[serde(rename = "jobsRequiringValidationCount")]
    pub jobs_requiring_validation_count: usize,
    #[serde(rename = "jobsMissingRequiredValidationCount")]
    pub jobs_missing_required_validation_count: usize,
    #[serde(rename = "timelineWarningCount")]
    pub timeline_warning_count: usize,
    #[serde(rename = "jobsWithWarnings")]
    pub jobs_with_warnings: Vec<JobAuditFindingV1>,
    #[serde(rename = "staleJobCount")]
    pub stale_job_count: usize,
    #[serde(rename = "staleQuotedJobCount")]
    pub stale_quoted_job_count: usize,
    #[serde(rename = "staleLeasedJobCount")]
    pub stale_leased_job_count: usize,
    #[serde(rename = "staleJobs")]
    pub stale_jobs: Vec<JobStaleCandidateV1>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JobEvidenceKindV1 {
    ValidationReport,
    DisputeEvidence,
    SettlementEvent,
    SettlementResolution,
    Receipt,
    StreamEvents,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobEvidenceLinkRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "evidenceKind")]
    pub evidence_kind: JobEvidenceKindV1,
    #[serde(
        rename = "evidenceId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub evidence_id: Option<String>,
    #[serde(rename = "evidenceRef")]
    pub evidence_ref: String,
    #[serde(rename = "linkedBy")]
    pub linked_by: String,
    #[serde(rename = "linkedAt", default, skip_serializing_if = "Option::is_none")]
    pub linked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobEvidenceLinkResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "evidenceKind")]
    pub evidence_kind: JobEvidenceKindV1,
    #[serde(rename = "evidenceRef")]
    pub evidence_ref: String,
    pub record: JobRecordV1,
    pub timeline: JobLifecycleTimelineV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JobLifecyclePhaseV1 {
    Created,
    Quoted,
    Leased,
    Running,
    Streamed,
    ReceiptCaptured,
    ValidationLinked,
    DisputeOpened,
    Settled,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobLifecycleEvidenceRefV1 {
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobLifecycleEventV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    pub sequence: u64,
    pub phase: JobLifecyclePhaseV1,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    pub summary: String,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<JobLifecycleEvidenceRefV1>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobLifecycleTimelineV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "currentStatus")]
    pub current_status: JobRecordStatusV1,
    #[serde(rename = "eventCount")]
    pub event_count: usize,
    pub events: Vec<JobLifecycleEventV1>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JobProductionStageKindV1 {
    RequestReceived,
    PackageResolved,
    PolicyChecked,
    JobOrderCreated,
    RunnerDiscovery,
    QuoteRanking,
    PaymentReserved,
    LeaseIssued,
    ExecutionStarted,
    StreamingEventsEmitted,
    ReceiptProduced,
    ValidationPerformed,
    Settlement,
    ReputationUpdated,
    EvidenceStored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JobProductionStageStatusV1 {
    Complete,
    Pending,
    Blocked,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobProductionLifecycleStageV1 {
    pub stage: JobProductionStageKindV1,
    pub status: JobProductionStageStatusV1,
    pub summary: String,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<JobLifecycleEvidenceRefV1>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobProductionLifecycleV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "currentStatus")]
    pub current_status: JobRecordStatusV1,
    #[serde(rename = "readyForSettlement")]
    pub ready_for_settlement: bool,
    #[serde(rename = "requiresOperatorAction")]
    pub requires_operator_action: bool,
    #[serde(rename = "completedStageCount")]
    pub completed_stage_count: usize,
    #[serde(rename = "pendingStageCount")]
    pub pending_stage_count: usize,
    #[serde(rename = "blockedStageCount")]
    pub blocked_stage_count: usize,
    #[serde(rename = "skippedStageCount")]
    pub skipped_stage_count: usize,
    pub stages: Vec<JobProductionLifecycleStageV1>,
    pub timeline: JobLifecycleTimelineV1,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobProductionLifecycleStoreEntryV1 {
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "currentStatus")]
    pub current_status: JobRecordStatusV1,
    #[serde(rename = "readyForSettlement")]
    pub ready_for_settlement: bool,
    #[serde(rename = "requiresOperatorAction")]
    pub requires_operator_action: bool,
    #[serde(rename = "completedStageCount")]
    pub completed_stage_count: usize,
    #[serde(rename = "pendingStageCount")]
    pub pending_stage_count: usize,
    #[serde(rename = "blockedStageCount")]
    pub blocked_stage_count: usize,
    #[serde(rename = "skippedStageCount")]
    pub skipped_stage_count: usize,
    #[serde(rename = "blockedStages")]
    pub blocked_stages: Vec<JobProductionStageKindV1>,
    #[serde(rename = "pendingStages")]
    pub pending_stages: Vec<JobProductionStageKindV1>,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobProductionLifecycleStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    #[serde(rename = "jobCount")]
    pub job_count: usize,
    #[serde(rename = "readyForSettlementCount")]
    pub ready_for_settlement_count: usize,
    #[serde(rename = "requiresOperatorActionCount")]
    pub requires_operator_action_count: usize,
    #[serde(rename = "blockedJobCount")]
    pub blocked_job_count: usize,
    #[serde(rename = "completedStageCount")]
    pub completed_stage_count: usize,
    #[serde(rename = "pendingStageCount")]
    pub pending_stage_count: usize,
    #[serde(rename = "blockedStageCount")]
    pub blocked_stage_count: usize,
    #[serde(rename = "skippedStageCount")]
    pub skipped_stage_count: usize,
    #[serde(rename = "stageStatusCounts")]
    pub stage_status_counts: BTreeMap<String, BTreeMap<String, usize>>,
    pub jobs: Vec<JobProductionLifecycleStoreEntryV1>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
}

pub fn job_record_from_order(order: JobOrderV1, observed_at: impl Into<String>) -> JobRecordV1 {
    let observed_at = observed_at.into();
    JobRecordV1 {
        schema_version: "swarm-ai.job-record.v1".to_string(),
        job_id: order.job_id.clone(),
        request_id: order.request_id.clone(),
        status: JobRecordStatusV1::Created,
        job_order: order,
        quotes: Vec::new(),
        lease: None,
        execution_status: None,
        selected_route_id: None,
        runner_id: None,
        receipt_id: None,
        receipt_ref: None,
        stream_ref: None,
        stream_event_count: None,
        error: None,
        created_at: observed_at.clone(),
        updated_at: observed_at,
        completed_at: None,
        metadata: json!({ "source": "job-order" }),
    }
}

pub fn job_record_with_quotes(
    order: JobOrderV1,
    quotes: Vec<JobQuoteV1>,
    observed_at: impl Into<String>,
) -> JobRecordV1 {
    let mut record = job_record_from_order(order, observed_at);
    record.status = JobRecordStatusV1::Quoted;
    record.quotes = quotes;
    record.metadata = json!({ "source": "job-quotes" });
    record
}

pub fn job_record_with_lease(
    request: &ExecutionLeaseRequestV1,
    lease: ExecutionLeaseV1,
    observed_at: impl Into<String>,
) -> JobRecordV1 {
    let observed_at = observed_at.into();
    let mut record = job_record_from_order(request.job_order.clone(), observed_at.clone());
    record.status = JobRecordStatusV1::Leased;
    record.quotes = vec![request.quote.clone()];
    record.lease = Some(lease);
    record.updated_at = observed_at;
    record.metadata = json!({
        "source": "execution-lease",
        "settlementRef": request.settlement_ref,
        "deadline": request.deadline
    });
    record
}

pub fn job_record_from_execution_response(
    response: &ExecutionResponseV1,
    observed_at: impl Into<String>,
) -> Option<JobRecordV1> {
    let order: JobOrderV1 =
        serde_json::from_value(response.metadata.get("jobOrder")?.clone()).ok()?;
    let observed_at = observed_at.into();
    let mut record = job_record_from_order(order, observed_at.clone());
    record.status = job_status_from_execution(&response.status);
    record.execution_status = Some(response.status.clone());
    record.selected_route_id =
        json_path_str(&response.metadata, &["routeExecution", "selectedRouteId"])
            .map(str::to_string);
    record.quotes = response_job_quotes(&response.metadata);
    record.lease = response_execution_lease(&response.metadata);
    record.runner_id = selected_runner_id(&response.metadata);
    record.receipt_id = json_path_str(&response.metadata, &["receiptStore", "receiptId"])
        .or_else(|| json_path_str(&response.metadata, &["receipt", "receiptId"]))
        .map(str::to_string);
    record.receipt_ref = json_path_str(&response.metadata, &["receiptStore", "receiptRef"])
        .map(str::to_string)
        .or_else(|| response.receipt_ref.clone());
    record.stream_event_count =
        json_path_u64(&response.metadata, &["streamEventSummary", "eventCount"]);
    record.stream_ref = first_storage_ref(&response.metadata).or_else(|| {
        record.stream_event_count.map(|_| {
            format!(
                "local://stream-events/{}",
                safe_file_component(&record.job_id)
            )
        })
    });
    record.error = response.error.clone();
    if matches!(
        record.status,
        JobRecordStatusV1::Succeeded | JobRecordStatusV1::Failed | JobRecordStatusV1::Cancelled
    ) {
        record.completed_at = Some(observed_at.clone());
    }
    record.updated_at = observed_at;
    record.metadata = execution_metadata_summary(&response.metadata);
    Some(record)
}

pub fn job_cancellation_request(
    job_id: impl Into<String>,
    cancelled_by: impl Into<String>,
    reason: impl Into<String>,
) -> JobCancellationRequestV1 {
    JobCancellationRequestV1 {
        schema_version: "swarm-ai.job-cancellation-request.v1".to_string(),
        job_id: job_id.into(),
        cancelled_by: cancelled_by.into(),
        reason: reason.into(),
        requested_at: None,
        metadata: json!({}),
    }
}

pub fn cancel_job_record(
    job_dir: &Path,
    request: &JobCancellationRequestV1,
    observed_at: impl Into<String>,
) -> Result<Option<JobCancellationResultV1>> {
    let observed_at = observed_at.into();
    if request.job_id.trim().is_empty() {
        anyhow::bail!("jobId is required");
    }
    if request.cancelled_by.trim().is_empty() {
        anyhow::bail!("cancelledBy is required");
    }
    if request.reason.trim().is_empty() {
        anyhow::bail!("reason is required");
    }

    let Some(lookup) = get_job_record(job_dir, &request.job_id)? else {
        return Ok(None);
    };
    let mut record = lookup.record;
    let previous_status = record.status.clone();
    let terminal_already = is_terminal_status(&previous_status);
    let transitioned = !terminal_already;

    if transitioned {
        record.status = JobRecordStatusV1::Cancelled;
        record.execution_status = Some(ExecutionStatus::Cancelled);
        record.updated_at = observed_at.clone();
        record.completed_at = Some(observed_at.clone());
        if !record.metadata.is_object() {
            record.metadata = json!({});
        }
        record.metadata["cancellation"] = json!({
            "schemaVersion": "swarm-ai.job-cancellation.v1",
            "cancelledBy": request.cancelled_by,
            "reason": request.reason,
            "requestedAt": request.requested_at.clone().unwrap_or_else(|| observed_at.clone()),
            "cancelledAt": observed_at,
            "metadata": request.metadata
        });
        write_job_record(job_dir, &record)?;
    }

    Ok(Some(JobCancellationResultV1 {
        schema_version: "swarm-ai.job-cancellation-result.v1".to_string(),
        job_id: record.job_id.clone(),
        transitioned,
        terminal_already,
        previous_status,
        current_status: record.status.clone(),
        record,
    }))
}

pub fn job_expiration_sweep_request() -> JobExpirationSweepRequestV1 {
    JobExpirationSweepRequestV1 {
        schema_version: "swarm-ai.job-expiration-sweep-request.v1".to_string(),
        observed_at: None,
        metadata: json!({}),
    }
}

pub fn expire_stale_job_records(
    job_dir: &Path,
    request: &JobExpirationSweepRequestV1,
) -> Result<JobExpirationSweepResultV1> {
    if request.schema_version != "swarm-ai.job-expiration-sweep-request.v1" {
        anyhow::bail!("job expiration sweep request schemaVersion is not supported");
    }
    let observed_at = request.observed_at.clone().unwrap_or_else(now_timestamp);
    let observed_ts = parse_timestamp(&observed_at)
        .with_context(|| format!("failed to parse observedAt {observed_at}"))?;
    let summary = list_job_records(job_dir)?;
    let scanned_job_count = summary.job_count;
    let mut expired_jobs = Vec::new();
    let mut warnings = Vec::new();

    for entry in summary.jobs {
        let Some(lookup) = get_job_record(job_dir, &entry.job_id)? else {
            continue;
        };
        let mut record = lookup.record;
        let Some(expiration) = stale_job_expiration(&record, observed_ts, &mut warnings) else {
            continue;
        };
        let previous_status = record.status.clone();
        record.status = JobRecordStatusV1::Failed;
        record.execution_status = Some(ExecutionStatus::Failed);
        record.completed_at = Some(observed_at.clone());
        record.updated_at = observed_at.clone();
        record.error = Some(expiration_error(&expiration));
        if !record.metadata.is_object() {
            record.metadata = json!({});
        }
        record.metadata["expiration"] = expiration_metadata(&record, &expiration, &observed_at);
        write_job_record(job_dir, &record)?;
        expired_jobs.push(JobExpirationEntryV1 {
            job_id: record.job_id.clone(),
            request_id: record.request_id.clone(),
            expiration_kind: expiration.kind,
            expired_at: expiration.expired_at,
            previous_status,
            current_status: record.status.clone(),
            record,
        });
    }

    Ok(JobExpirationSweepResultV1 {
        schema_version: "swarm-ai.job-expiration-sweep-result.v1".to_string(),
        observed_at,
        scanned_job_count,
        expired_job_count: expired_jobs.len(),
        expired_jobs,
        warnings,
    })
}

pub fn job_store_audit_request() -> JobStoreAuditRequestV1 {
    JobStoreAuditRequestV1 {
        schema_version: "swarm-ai.job-store-audit-request.v1".to_string(),
        observed_at: None,
        metadata: json!({}),
    }
}

pub fn audit_job_store(
    job_dir: &Path,
    request: &JobStoreAuditRequestV1,
) -> Result<JobStoreAuditSummaryV1> {
    if request.schema_version != "swarm-ai.job-store-audit-request.v1" {
        anyhow::bail!("job store audit request schemaVersion is not supported");
    }
    let observed_at = request.observed_at.clone().unwrap_or_else(now_timestamp);
    let observed_ts = parse_timestamp(&observed_at)
        .with_context(|| format!("failed to parse observedAt {observed_at}"))?;
    let summary = list_job_records(job_dir)?;
    let mut status_counts = BTreeMap::new();
    let mut active_job_count = 0usize;
    let mut terminal_job_count = 0usize;
    let mut receipt_linked_job_count = 0usize;
    let mut stream_linked_job_count = 0usize;
    let mut validation_linked_job_count = 0usize;
    let mut dispute_linked_job_count = 0usize;
    let mut settlement_linked_job_count = 0usize;
    let mut jobs_requiring_validation_count = 0usize;
    let mut jobs_missing_required_validation_count = 0usize;
    let mut timeline_warning_count = 0usize;
    let mut jobs_with_warnings = Vec::new();
    let mut stale_jobs = Vec::new();
    let mut warnings = Vec::new();

    for entry in &summary.jobs {
        let Some(lookup) = get_job_record(job_dir, &entry.job_id)? else {
            continue;
        };
        let record = lookup.record;
        *status_counts.entry(status_key(&record.status)).or_insert(0) += 1;
        if is_terminal_status(&record.status) {
            terminal_job_count += 1;
        } else {
            active_job_count += 1;
        }
        if record.receipt_id.is_some() || record.receipt_ref.is_some() {
            receipt_linked_job_count += 1;
        }
        if record.stream_ref.is_some() || record.stream_event_count.is_some() {
            stream_linked_job_count += 1;
        }
        let has_validation = !validation_evidence_refs(&record.metadata).is_empty();
        if has_validation {
            validation_linked_job_count += 1;
        }
        if !dispute_evidence_refs(&record.metadata).is_empty() {
            dispute_linked_job_count += 1;
        }
        if !settlement_evidence_refs(&record.metadata).is_empty() {
            settlement_linked_job_count += 1;
        }
        if record.job_order.validation_required {
            jobs_requiring_validation_count += 1;
            if !has_validation {
                jobs_missing_required_validation_count += 1;
            }
        }

        let timeline = job_lifecycle_timeline(&record);
        timeline_warning_count += timeline.warnings.len();
        if !timeline.warnings.is_empty() {
            jobs_with_warnings.push(JobAuditFindingV1 {
                job_id: record.job_id.clone(),
                request_id: record.request_id.clone(),
                status: record.status.clone(),
                warning_count: timeline.warnings.len(),
                warnings: timeline.warnings,
            });
        }

        if let Some(expiration) = stale_job_expiration(&record, observed_ts, &mut warnings) {
            stale_jobs.push(JobStaleCandidateV1 {
                job_id: record.job_id.clone(),
                request_id: record.request_id.clone(),
                status: record.status.clone(),
                expiration_kind: expiration.kind,
                expired_at: expiration.expired_at,
                evidence_refs: expiration.evidence_refs,
            });
        }
    }

    let stale_quoted_job_count = stale_jobs
        .iter()
        .filter(|job| job.expiration_kind == JobExpirationKindV1::QuoteExpired)
        .count();
    let stale_leased_job_count = stale_jobs
        .iter()
        .filter(|job| job.expiration_kind == JobExpirationKindV1::LeaseExpired)
        .count();

    Ok(JobStoreAuditSummaryV1 {
        schema_version: "swarm-ai.job-store-audit-summary.v1".to_string(),
        root: summary.root,
        observed_at,
        job_count: summary.job_count,
        active_job_count,
        terminal_job_count,
        status_counts,
        receipt_linked_job_count,
        stream_linked_job_count,
        validation_linked_job_count,
        dispute_linked_job_count,
        settlement_linked_job_count,
        jobs_requiring_validation_count,
        jobs_missing_required_validation_count,
        timeline_warning_count,
        jobs_with_warnings,
        stale_job_count: stale_jobs.len(),
        stale_quoted_job_count,
        stale_leased_job_count,
        stale_jobs,
        warnings,
    })
}

pub fn audit_job_production_lifecycles(
    job_dir: &Path,
    request: &JobStoreAuditRequestV1,
) -> Result<JobProductionLifecycleStoreSummaryV1> {
    if request.schema_version != "swarm-ai.job-store-audit-request.v1" {
        anyhow::bail!("job store audit request schemaVersion is not supported");
    }
    let observed_at = request.observed_at.clone().unwrap_or_else(now_timestamp);
    parse_timestamp(&observed_at)
        .with_context(|| format!("failed to parse observedAt {observed_at}"))?;
    let summary = list_job_records(job_dir)?;
    let mut stage_status_counts = BTreeMap::<String, BTreeMap<String, usize>>::new();
    let mut jobs = Vec::new();
    let mut ready_for_settlement_count = 0usize;
    let mut requires_operator_action_count = 0usize;
    let mut blocked_job_count = 0usize;
    let mut completed_stage_count = 0usize;
    let mut pending_stage_count = 0usize;
    let mut blocked_stage_count = 0usize;
    let mut skipped_stage_count = 0usize;
    let mut warnings = Vec::new();

    for entry in &summary.jobs {
        let Some(lookup) = get_job_record(job_dir, &entry.job_id)? else {
            continue;
        };
        let lifecycle = job_production_lifecycle(&lookup.record);
        ready_for_settlement_count += lifecycle.ready_for_settlement as usize;
        requires_operator_action_count += lifecycle.requires_operator_action as usize;
        if lifecycle.blocked_stage_count > 0 {
            blocked_job_count += 1;
        }
        completed_stage_count += lifecycle.completed_stage_count;
        pending_stage_count += lifecycle.pending_stage_count;
        blocked_stage_count += lifecycle.blocked_stage_count;
        skipped_stage_count += lifecycle.skipped_stage_count;
        warnings.extend(lifecycle.warnings.iter().map(|warning| {
            validation_warning(
                format!("$.jobs[{}].{}", lifecycle.job_id, warning.path),
                warning.message.clone(),
            )
        }));

        for stage in &lifecycle.stages {
            *stage_status_counts
                .entry(production_stage_key(&stage.stage))
                .or_default()
                .entry(production_stage_status_key(&stage.status))
                .or_insert(0) += 1;
        }

        jobs.push(production_lifecycle_store_entry(&lifecycle));
    }

    jobs.sort_by(|left, right| {
        right
            .requires_operator_action
            .cmp(&left.requires_operator_action)
            .then(right.blocked_stage_count.cmp(&left.blocked_stage_count))
            .then(right.pending_stage_count.cmp(&left.pending_stage_count))
            .then(left.job_id.cmp(&right.job_id))
    });

    Ok(JobProductionLifecycleStoreSummaryV1 {
        schema_version: "swarm-ai.job-production-lifecycle-store-summary.v1".to_string(),
        root: job_dir.display().to_string(),
        observed_at,
        job_count: jobs.len(),
        ready_for_settlement_count,
        requires_operator_action_count,
        blocked_job_count,
        completed_stage_count,
        pending_stage_count,
        blocked_stage_count,
        skipped_stage_count,
        stage_status_counts,
        jobs,
        warnings,
    })
}

pub fn job_evidence_link_request(
    job_id: impl Into<String>,
    evidence_kind: JobEvidenceKindV1,
    evidence_ref: impl Into<String>,
    linked_by: impl Into<String>,
) -> JobEvidenceLinkRequestV1 {
    JobEvidenceLinkRequestV1 {
        schema_version: "swarm-ai.job-evidence-link-request.v1".to_string(),
        job_id: job_id.into(),
        evidence_kind,
        evidence_id: None,
        evidence_ref: evidence_ref.into(),
        linked_by: linked_by.into(),
        linked_at: None,
        summary: None,
        metadata: json!({}),
    }
}

pub fn link_job_evidence(
    job_dir: &Path,
    request: &JobEvidenceLinkRequestV1,
    observed_at: impl Into<String>,
) -> Result<Option<JobEvidenceLinkResultV1>> {
    let observed_at = observed_at.into();
    if request.job_id.trim().is_empty() {
        anyhow::bail!("jobId is required");
    }
    if request.evidence_ref.trim().is_empty() {
        anyhow::bail!("evidenceRef is required");
    }
    if request.linked_by.trim().is_empty() {
        anyhow::bail!("linkedBy is required");
    }

    let Some(lookup) = get_job_record(job_dir, &request.job_id)? else {
        return Ok(None);
    };
    let mut record = lookup.record;
    if !record.metadata.is_object() {
        record.metadata = json!({});
    }
    let linked_at = request
        .linked_at
        .clone()
        .unwrap_or_else(|| observed_at.clone());
    let evidence_link = json!({
        "schemaVersion": "swarm-ai.job-evidence-link.v1",
        "jobId": request.job_id,
        "evidenceKind": request.evidence_kind,
        "evidenceId": request.evidence_id,
        "evidenceRef": request.evidence_ref,
        "linkedBy": request.linked_by,
        "linkedAt": linked_at,
        "summary": request.summary,
        "metadata": request.metadata
    });
    append_metadata_array(&mut record.metadata, "evidenceLinks", evidence_link.clone());
    apply_evidence_link_metadata(&mut record, request, &linked_at);
    record.updated_at = observed_at;
    write_job_record(job_dir, &record)?;
    let timeline = job_lifecycle_timeline(&record);

    Ok(Some(JobEvidenceLinkResultV1 {
        schema_version: "swarm-ai.job-evidence-link-result.v1".to_string(),
        job_id: record.job_id.clone(),
        evidence_kind: request.evidence_kind.clone(),
        evidence_ref: request.evidence_ref.clone(),
        record,
        timeline,
    }))
}

pub fn job_lifecycle_timeline(record: &JobRecordV1) -> JobLifecycleTimelineV1 {
    let mut events = Vec::new();
    let mut warnings = Vec::new();

    push_lifecycle_event(
        &mut events,
        record,
        JobLifecyclePhaseV1::Created,
        record.created_at.clone(),
        "Job order created",
        vec![
            lifecycle_evidence("request-id", &record.request_id),
            lifecycle_evidence("package-ref", &record.job_order.package_ref),
        ],
        json!({
            "requester": record.job_order.requester,
            "task": record.job_order.task,
            "apiSurface": record.job_order.api_surface,
            "privacyTier": record.job_order.privacy.privacy_tier,
            "requiredVerificationTier": record.job_order.required_verification_tier
        }),
    );

    if !record.quotes.is_empty() {
        push_lifecycle_event(
            &mut events,
            record,
            JobLifecyclePhaseV1::Quoted,
            record.updated_at.clone(),
            format!("{} runner quote(s) captured", record.quotes.len()),
            record
                .quotes
                .iter()
                .map(|quote| lifecycle_evidence("quote-id", &quote.quote_id))
                .collect(),
            json!({
                "quoteCount": record.quotes.len(),
                "runnerIds": record.quotes.iter().map(|quote| quote.runner_id.clone()).collect::<Vec<_>>()
            }),
        );
    } else if matches!(record.status, JobRecordStatusV1::Quoted) {
        warnings.push(validation_warning(
            "$.quotes",
            "job status is quoted but no quotes are attached",
        ));
    }

    if let Some(lease) = &record.lease {
        push_lifecycle_event(
            &mut events,
            record,
            JobLifecyclePhaseV1::Leased,
            record.updated_at.clone(),
            "Execution lease reserved",
            vec![
                lifecycle_evidence("lease-id", &lease.lease_id),
                lifecycle_evidence("quote-id", &lease.quote_id),
                lifecycle_evidence("settlement-ref", &lease.settlement_ref),
            ],
            json!({
                "runnerId": lease.runner_id,
                "requester": lease.requester,
                "allowedInputRefs": lease.allowed_input_refs,
                "allowedInputHashes": lease.allowed_input_hashes,
                "startAfter": lease.start_after,
                "deadline": lease.deadline,
                "maxCost": lease.max_cost
            }),
        );
    } else if matches!(record.status, JobRecordStatusV1::Leased) {
        warnings.push(validation_warning(
            "$.lease",
            "job status is leased but no lease is attached",
        ));
    }

    if record.selected_route_id.is_some()
        || record.runner_id.is_some()
        || matches!(record.status, JobRecordStatusV1::Partial)
    {
        let mut evidence = Vec::new();
        if let Some(route_id) = &record.selected_route_id {
            evidence.push(lifecycle_evidence("route-id", route_id));
        }
        if let Some(runner_id) = &record.runner_id {
            evidence.push(lifecycle_evidence("runner-id", runner_id));
        }
        push_lifecycle_event(
            &mut events,
            record,
            JobLifecyclePhaseV1::Running,
            record.updated_at.clone(),
            "Execution attempt linked",
            evidence,
            json!({
                "executionStatus": record.execution_status,
                "selectedRouteId": record.selected_route_id,
                "runnerId": record.runner_id
            }),
        );
    }

    if record.stream_ref.is_some() || record.stream_event_count.is_some() {
        let mut evidence = Vec::new();
        if let Some(stream_ref) = &record.stream_ref {
            evidence.push(lifecycle_evidence("stream-ref", stream_ref));
        }
        let event_count = record.stream_event_count.unwrap_or_default();
        push_lifecycle_event(
            &mut events,
            record,
            JobLifecyclePhaseV1::Streamed,
            record
                .completed_at
                .clone()
                .unwrap_or_else(|| record.updated_at.clone()),
            if record.stream_event_count.is_some() {
                format!("{event_count} stream event(s) available")
            } else {
                "Stream events available".to_string()
            },
            evidence,
            json!({
                "streamEventCount": record.stream_event_count,
                "streamEventStore": record.metadata.get("streamEventStore").cloned()
            }),
        );
    }

    if record.receipt_id.is_some() || record.receipt_ref.is_some() {
        let mut evidence = Vec::new();
        if let Some(receipt_id) = &record.receipt_id {
            evidence.push(lifecycle_evidence("receipt-id", receipt_id));
        }
        if let Some(receipt_ref) = &record.receipt_ref {
            evidence.push(lifecycle_evidence("receipt-ref", receipt_ref));
        }
        push_lifecycle_event(
            &mut events,
            record,
            JobLifecyclePhaseV1::ReceiptCaptured,
            record
                .completed_at
                .clone()
                .unwrap_or_else(|| record.updated_at.clone()),
            "Execution receipt captured",
            evidence,
            json!({
                "receiptStore": record.metadata.get("receiptStore").cloned()
            }),
        );
    }

    push_metadata_lifecycle_event(
        &mut events,
        record,
        JobLifecyclePhaseV1::ValidationLinked,
        "Validation evidence linked",
        validation_evidence_refs(&record.metadata),
        json!({
            "validationRequired": record.job_order.validation_required,
            "validation": record.metadata.get("validation").cloned(),
            "validationReport": record.metadata.get("validationReport").cloned(),
            "validationReportStore": record.metadata.get("validationReportStore").cloned()
        }),
    );

    push_metadata_lifecycle_event(
        &mut events,
        record,
        JobLifecyclePhaseV1::DisputeOpened,
        "Dispute evidence linked",
        dispute_evidence_refs(&record.metadata),
        json!({
            "dispute": record.metadata.get("dispute").cloned(),
            "disputeStore": record.metadata.get("disputeStore").cloned(),
            "receiptDispute": record.metadata.get("receiptDispute").cloned()
        }),
    );

    push_metadata_lifecycle_event(
        &mut events,
        record,
        JobLifecyclePhaseV1::Settled,
        "Settlement evidence linked",
        settlement_evidence_refs(&record.metadata),
        json!({
            "settlement": record.metadata.get("settlement").cloned(),
            "settlementEvent": record.metadata.get("settlementEvent").cloned(),
            "settlementResolution": record.metadata.get("settlementResolution").cloned()
        }),
    );

    match record.status {
        JobRecordStatusV1::Succeeded => push_lifecycle_event(
            &mut events,
            record,
            JobLifecyclePhaseV1::Succeeded,
            record
                .completed_at
                .clone()
                .unwrap_or_else(|| record.updated_at.clone()),
            "Job completed successfully",
            record
                .receipt_id
                .as_ref()
                .map(|receipt_id| vec![lifecycle_evidence("receipt-id", receipt_id)])
                .unwrap_or_default(),
            json!({ "executionStatus": record.execution_status }),
        ),
        JobRecordStatusV1::Failed => {
            let expiration = record.metadata.get("expiration");
            push_lifecycle_event(
                &mut events,
                record,
                JobLifecyclePhaseV1::Failed,
                record
                    .completed_at
                    .clone()
                    .unwrap_or_else(|| record.updated_at.clone()),
                expiration
                    .and_then(|value| json_path_str(value, &["expirationKind"]))
                    .map(|kind| format!("Job failed: {kind}"))
                    .unwrap_or_else(|| "Job failed".to_string()),
                expiration_evidence_refs(record),
                json!({
                    "error": record.error,
                    "expiration": expiration.cloned()
                }),
            );
        }
        JobRecordStatusV1::Cancelled => {
            let cancellation = record.metadata.get("cancellation");
            push_lifecycle_event(
                &mut events,
                record,
                JobLifecyclePhaseV1::Cancelled,
                cancellation
                    .and_then(|value| json_path_str(value, &["cancelledAt"]))
                    .map(str::to_string)
                    .or_else(|| record.completed_at.clone())
                    .unwrap_or_else(|| record.updated_at.clone()),
                cancellation
                    .and_then(|value| json_path_str(value, &["reason"]))
                    .map(|reason| format!("Job cancelled: {reason}"))
                    .unwrap_or_else(|| "Job cancelled".to_string()),
                cancellation_evidence_refs(record),
                json!({ "cancellation": cancellation.cloned() }),
            );
        }
        JobRecordStatusV1::Partial => push_lifecycle_event(
            &mut events,
            record,
            JobLifecyclePhaseV1::Partial,
            record.updated_at.clone(),
            "Job is partially complete",
            Vec::new(),
            json!({ "executionStatus": record.execution_status }),
        ),
        JobRecordStatusV1::Created | JobRecordStatusV1::Quoted | JobRecordStatusV1::Leased => {}
    }

    if is_terminal_status(&record.status) && record.completed_at.is_none() {
        warnings.push(validation_warning(
            "$.completedAt",
            "terminal job status is missing completedAt",
        ));
    }
    if matches!(record.status, JobRecordStatusV1::Succeeded) && record.receipt_id.is_none() {
        warnings.push(validation_warning(
            "$.receiptId",
            "successful job is missing a receipt id",
        ));
    }
    if (record.receipt_id.is_some() || record.receipt_ref.is_some()) && record.stream_ref.is_none()
    {
        warnings.push(validation_warning(
            "$.streamRef",
            "receipt is captured but no persisted stream reference is attached",
        ));
    }
    if matches!(record.status, JobRecordStatusV1::Cancelled)
        && record.metadata.get("cancellation").is_none()
    {
        warnings.push(validation_warning(
            "$.metadata.cancellation",
            "cancelled job is missing cancellation metadata",
        ));
    }
    if record.job_order.validation_required && validation_evidence_refs(&record.metadata).is_empty()
    {
        warnings.push(validation_warning(
            "$.metadata.validation",
            "job requested validation but no validation evidence is linked",
        ));
    }

    JobLifecycleTimelineV1 {
        schema_version: "swarm-ai.job-lifecycle-timeline.v1".to_string(),
        job_id: record.job_id.clone(),
        request_id: record.request_id.clone(),
        current_status: record.status.clone(),
        event_count: events.len(),
        events,
        warnings,
    }
}

pub fn job_production_lifecycle(record: &JobRecordV1) -> JobProductionLifecycleV1 {
    let timeline = job_lifecycle_timeline(record);
    let mut stages = Vec::new();
    let terminal = is_terminal_status(&record.status);
    let has_route = record.selected_route_id.is_some()
        || record.runner_id.is_some()
        || record.metadata.get("routePlan").is_some()
        || record.metadata.get("routeExecution").is_some();
    let has_receipt = record.receipt_id.is_some() || record.receipt_ref.is_some();
    let has_stream = record.stream_ref.is_some() || record.stream_event_count.is_some();
    let validation_refs = validation_evidence_refs(&record.metadata);
    let settlement_refs = settlement_evidence_refs(&record.metadata);
    let validation_satisfied = !record.job_order.validation_required || !validation_refs.is_empty();
    let settlement_is_free = is_free_local_settlement(&record.job_order.settlement_method);
    let payment_refs = payment_evidence_refs(record);
    let reputation_refs = reputation_evidence_refs(&record.metadata);
    let stored_evidence_refs = stored_evidence_refs(record);

    stages.push(production_stage(
        JobProductionStageKindV1::RequestReceived,
        JobProductionStageStatusV1::Complete,
        "User request is represented by requestId",
        vec![lifecycle_evidence("request-id", &record.request_id)],
        Vec::new(),
    ));
    stages.push(production_stage(
        JobProductionStageKindV1::PackageResolved,
        non_empty_complete(&record.job_order.package_ref, terminal),
        "Package reference is resolved into the job order",
        vec![
            lifecycle_evidence("package-id", &record.job_order.package_id),
            lifecycle_evidence("package-ref", &record.job_order.package_ref),
        ],
        missing_when_empty(
            &record.job_order.package_ref,
            "$.jobOrder.packageRef",
            "job order is missing an immutable package reference",
        ),
    ));

    let mut policy_warnings = Vec::new();
    if record.job_order.access_grant_ref.is_none()
        && record.metadata.get("policyDecision").is_none()
        && record.metadata.get("trustPolicy").is_none()
        && record.metadata.get("routePlan").is_none()
    {
        policy_warnings.push(validation_warning(
            "$.metadata.policy",
            "no explicit access, trust policy, or route policy evidence is linked",
        ));
    }
    stages.push(production_stage(
        JobProductionStageKindV1::PolicyChecked,
        JobProductionStageStatusV1::Complete,
        "Job order carries privacy, verification, access, budget, and validation constraints",
        policy_evidence_refs(record),
        policy_warnings,
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::JobOrderCreated,
        JobProductionStageStatusV1::Complete,
        "Marketplace-ready job order created",
        vec![lifecycle_evidence("job-id", &record.job_id)],
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::RunnerDiscovery,
        if has_route || !record.quotes.is_empty() {
            JobProductionStageStatusV1::Complete
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if has_route || !record.quotes.is_empty() {
            "Runner discovery or route evidence is linked"
        } else {
            "Runner discovery evidence has not been linked"
        },
        route_evidence_refs(record),
        if has_route || !record.quotes.is_empty() {
            Vec::new()
        } else {
            vec![validation_warning(
                "$.metadata.routePlan",
                "job has no route plan, selected route, runner, or quote evidence",
            )]
        },
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::QuoteRanking,
        if !record.quotes.is_empty() {
            JobProductionStageStatusV1::Complete
        } else if terminal && record.job_order.settlement_method == "free-local-dev" {
            JobProductionStageStatusV1::Skipped
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if record.quotes.is_empty() {
            "No runner quote set is attached"
        } else {
            "Runner quotes are attached for ranking"
        },
        record
            .quotes
            .iter()
            .map(|quote| lifecycle_evidence("quote-id", &quote.quote_id))
            .collect(),
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::PaymentReserved,
        if settlement_is_free {
            JobProductionStageStatusV1::Skipped
        } else if !payment_refs.is_empty() {
            JobProductionStageStatusV1::Complete
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if settlement_is_free {
            "Payment reservation is skipped for the local development settlement method"
        } else if payment_refs.is_empty() {
            "Payment authorization or escrow evidence is not linked"
        } else {
            "Payment reservation evidence is linked"
        },
        payment_refs,
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::LeaseIssued,
        if record.lease.is_some() {
            JobProductionStageStatusV1::Complete
        } else if terminal && record.job_order.settlement_method == "free-local-dev" {
            JobProductionStageStatusV1::Skipped
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else if record.quotes.is_empty() {
            JobProductionStageStatusV1::Pending
        } else {
            JobProductionStageStatusV1::Pending
        },
        if record.lease.is_some() {
            "Execution lease is attached"
        } else {
            "Execution lease has not been attached"
        },
        record
            .lease
            .as_ref()
            .map(|lease| {
                let mut evidence = vec![
                    lifecycle_evidence("lease-id", &lease.lease_id),
                    lifecycle_evidence("quote-id", &lease.quote_id),
                ];
                for input_ref in &lease.allowed_input_refs {
                    evidence.push(lifecycle_evidence("input-ref", input_ref));
                }
                evidence
            })
            .unwrap_or_default(),
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::ExecutionStarted,
        if record.execution_status.is_some() || has_route || terminal {
            JobProductionStageStatusV1::Complete
        } else {
            JobProductionStageStatusV1::Pending
        },
        if record.execution_status.is_some() || has_route || terminal {
            "Execution attempt is represented in the job record"
        } else {
            "Execution has not started"
        },
        execution_evidence_refs(record),
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::StreamingEventsEmitted,
        if has_stream {
            JobProductionStageStatusV1::Complete
        } else if !record.job_order.constraints.stream && terminal {
            JobProductionStageStatusV1::Skipped
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if has_stream {
            "Persisted stream event evidence is linked"
        } else {
            "Persisted stream event evidence is not linked"
        },
        stream_evidence_refs(record),
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::ReceiptProduced,
        if has_receipt {
            JobProductionStageStatusV1::Complete
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if has_receipt {
            "Execution receipt evidence is linked"
        } else {
            "Execution receipt evidence is not linked"
        },
        receipt_evidence_refs(record),
        if has_receipt {
            Vec::new()
        } else {
            vec![validation_warning(
                "$.receiptId",
                "job has no receipt id or receipt reference",
            )]
        },
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::ValidationPerformed,
        if !record.job_order.validation_required {
            JobProductionStageStatusV1::Skipped
        } else if !validation_refs.is_empty() {
            JobProductionStageStatusV1::Complete
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if record.job_order.validation_required {
            "Validation is required by the job order"
        } else {
            "Validation is not required by the job order"
        },
        validation_refs,
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::Settlement,
        if settlement_is_free {
            JobProductionStageStatusV1::Skipped
        } else if !settlement_refs.is_empty() {
            JobProductionStageStatusV1::Complete
        } else if terminal && has_receipt && validation_satisfied {
            JobProductionStageStatusV1::Pending
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if settlement_is_free {
            "Settlement is skipped for the local development settlement method"
        } else if settlement_refs.is_empty() {
            "Settlement evidence is not linked"
        } else {
            "Settlement evidence is linked"
        },
        settlement_refs.clone(),
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::ReputationUpdated,
        if !reputation_refs.is_empty() {
            JobProductionStageStatusV1::Complete
        } else if settlement_is_free || settlement_refs.is_empty() {
            JobProductionStageStatusV1::Pending
        } else {
            JobProductionStageStatusV1::Pending
        },
        if reputation_refs.is_empty() {
            "Reputation update evidence is not linked"
        } else {
            "Reputation update evidence is linked"
        },
        reputation_refs,
        Vec::new(),
    ));

    stages.push(production_stage(
        JobProductionStageKindV1::EvidenceStored,
        if !stored_evidence_refs.is_empty() {
            JobProductionStageStatusV1::Complete
        } else if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        },
        if stored_evidence_refs.is_empty() {
            "No persisted receipt, stream, validation, or settlement evidence is linked"
        } else {
            "Persisted lifecycle evidence is linked"
        },
        stored_evidence_refs,
        Vec::new(),
    ));

    let completed_stage_count = stage_count(&stages, JobProductionStageStatusV1::Complete);
    let pending_stage_count = stage_count(&stages, JobProductionStageStatusV1::Pending);
    let blocked_stage_count = stage_count(&stages, JobProductionStageStatusV1::Blocked);
    let skipped_stage_count = stage_count(&stages, JobProductionStageStatusV1::Skipped);
    let ready_for_settlement = !settlement_is_free
        && matches!(record.status, JobRecordStatusV1::Succeeded)
        && has_receipt
        && validation_satisfied
        && settlement_evidence_refs(&record.metadata).is_empty();
    let requires_operator_action = blocked_stage_count > 0 || ready_for_settlement;
    let mut warnings = timeline.warnings.clone();
    for stage in &stages {
        warnings.extend(stage.warnings.clone());
    }

    JobProductionLifecycleV1 {
        schema_version: "swarm-ai.job-production-lifecycle.v1".to_string(),
        job_id: record.job_id.clone(),
        request_id: record.request_id.clone(),
        current_status: record.status.clone(),
        ready_for_settlement,
        requires_operator_action,
        completed_stage_count,
        pending_stage_count,
        blocked_stage_count,
        skipped_stage_count,
        stages,
        timeline,
        warnings,
    }
}

pub fn upsert_job_record(job_dir: &Path, mut record: JobRecordV1) -> Result<PathBuf> {
    if let Some(existing) = get_job_record(job_dir, &record.job_id)?.map(|lookup| lookup.record) {
        record.created_at = existing.created_at;
        if record.quotes.is_empty() {
            record.quotes = existing.quotes;
        }
        if record.lease.is_none() {
            record.lease = existing.lease;
        }
    }
    write_job_record(job_dir, &record)
}

pub fn write_job_record(job_dir: &Path, record: &JobRecordV1) -> Result<PathBuf> {
    fs::create_dir_all(job_dir)
        .with_context(|| format!("failed to create {}", job_dir.display()))?;
    let path = job_path(job_dir, &record.job_id);
    fs::write(&path, serde_json::to_vec_pretty(record)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn get_job_record(job_dir: &Path, job_id: &str) -> Result<Option<JobLookupResultV1>> {
    let job_id = job_id.trim();
    if job_id.is_empty() {
        anyhow::bail!("jobId is required");
    }
    let direct_path = job_path(job_dir, job_id);
    if direct_path.exists() {
        let record = read_job_record(&direct_path)?;
        if record.job_id == job_id {
            return Ok(Some(job_lookup(record, direct_path)));
        }
    }
    if !job_dir.exists() {
        return Ok(None);
    }
    for entry in
        fs::read_dir(job_dir).with_context(|| format!("failed to read {}", job_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let record = read_job_record(&path)?;
            if record.job_id == job_id {
                return Ok(Some(job_lookup(record, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_job_records(job_dir: &Path) -> Result<JobStoreSummaryV1> {
    let mut jobs = Vec::new();
    if job_dir.exists() {
        for entry in fs::read_dir(job_dir)
            .with_context(|| format!("failed to read {}", job_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let record = read_job_record(&path)?;
                jobs.push(job_entry(&record, path.display().to_string()));
            }
        }
    }
    jobs.sort_by(|left, right| {
        left.updated_at
            .cmp(&right.updated_at)
            .then(left.job_id.cmp(&right.job_id))
    });
    Ok(JobStoreSummaryV1 {
        schema_version: "swarm-ai.job-store-summary.v1".to_string(),
        root: job_dir.display().to_string(),
        job_count: jobs.len(),
        jobs,
    })
}

pub fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Debug, Clone)]
struct StaleJobExpiration {
    kind: JobExpirationKindV1,
    expired_at: String,
    evidence_refs: Vec<JobLifecycleEvidenceRefV1>,
}

fn stale_job_expiration(
    record: &JobRecordV1,
    observed_at: DateTime<Utc>,
    warnings: &mut Vec<ValidationIssue>,
) -> Option<StaleJobExpiration> {
    if is_terminal_status(&record.status) {
        return None;
    }
    if let Some(lease) = &record.lease {
        match parse_timestamp(&lease.deadline) {
            Ok(deadline) if deadline <= observed_at => {
                return Some(StaleJobExpiration {
                    kind: JobExpirationKindV1::LeaseExpired,
                    expired_at: lease.deadline.clone(),
                    evidence_refs: vec![
                        lifecycle_evidence("lease-id", &lease.lease_id),
                        lifecycle_evidence("quote-id", &lease.quote_id),
                    ],
                });
            }
            Ok(_) => return None,
            Err(error) => warnings.push(validation_warning(
                format!("$.jobs[{}].lease.deadline", record.job_id),
                format!("lease deadline is not RFC3339: {error}"),
            )),
        }
    }

    if !matches!(record.status, JobRecordStatusV1::Quoted) || record.quotes.is_empty() {
        return None;
    }

    let mut expired_quotes = Vec::new();
    let mut invalid_quote_count = 0usize;
    for quote in &record.quotes {
        match parse_timestamp(&quote.expires_at) {
            Ok(expires_at) if expires_at <= observed_at => expired_quotes.push(quote),
            Ok(_) => return None,
            Err(error) => {
                invalid_quote_count += 1;
                warnings.push(validation_warning(
                    format!(
                        "$.jobs[{}].quotes[{}].expiresAt",
                        record.job_id, quote.quote_id
                    ),
                    format!("quote expiration is not RFC3339: {error}"),
                ));
            }
        }
    }
    if invalid_quote_count == 0 && expired_quotes.len() == record.quotes.len() {
        let expired_at = expired_quotes
            .iter()
            .map(|quote| quote.expires_at.as_str())
            .max()
            .unwrap_or(&record.updated_at)
            .to_string();
        return Some(StaleJobExpiration {
            kind: JobExpirationKindV1::QuoteExpired,
            expired_at,
            evidence_refs: expired_quotes
                .iter()
                .map(|quote| lifecycle_evidence("quote-id", &quote.quote_id))
                .collect(),
        });
    }
    None
}

fn expiration_error(expiration: &StaleJobExpiration) -> SwarmAiErrorV1 {
    let message = match expiration.kind {
        JobExpirationKindV1::QuoteExpired => "all job quotes expired before a lease was issued",
        JobExpirationKindV1::LeaseExpired => "execution lease expired before terminal execution",
    };
    SwarmAiErrorV1::new(ErrorCode::DeadlineExceeded, message).with_details(json!({
        "expirationKind": expiration.kind,
        "expiredAt": expiration.expired_at,
        "evidenceRefs": expiration.evidence_refs.clone()
    }))
}

fn expiration_metadata(
    record: &JobRecordV1,
    expiration: &StaleJobExpiration,
    observed_at: &str,
) -> Value {
    json!({
        "schemaVersion": "swarm-ai.job-expiration.v1",
        "jobId": record.job_id,
        "expirationKind": expiration.kind,
        "expiredAt": expiration.expired_at,
        "observedAt": observed_at,
        "evidenceRefs": expiration.evidence_refs.clone()
    })
}

fn parse_timestamp(value: &str) -> std::result::Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|timestamp| timestamp.with_timezone(&Utc))
}

fn push_lifecycle_event(
    events: &mut Vec<JobLifecycleEventV1>,
    record: &JobRecordV1,
    phase: JobLifecyclePhaseV1,
    observed_at: String,
    summary: impl Into<String>,
    evidence_refs: Vec<JobLifecycleEvidenceRefV1>,
    metadata: Value,
) {
    events.push(JobLifecycleEventV1 {
        schema_version: "swarm-ai.job-lifecycle-event.v1".to_string(),
        job_id: record.job_id.clone(),
        sequence: events.len() as u64,
        phase,
        observed_at,
        summary: summary.into(),
        evidence_refs,
        metadata,
    });
}

fn push_metadata_lifecycle_event(
    events: &mut Vec<JobLifecycleEventV1>,
    record: &JobRecordV1,
    phase: JobLifecyclePhaseV1,
    summary: impl Into<String>,
    evidence_refs: Vec<JobLifecycleEvidenceRefV1>,
    metadata: Value,
) {
    if evidence_refs.is_empty() {
        return;
    }
    push_lifecycle_event(
        events,
        record,
        phase,
        record
            .completed_at
            .clone()
            .unwrap_or_else(|| record.updated_at.clone()),
        summary,
        evidence_refs,
        metadata,
    );
}

fn lifecycle_evidence(
    kind: impl Into<String>,
    reference: impl Into<String>,
) -> JobLifecycleEvidenceRefV1 {
    JobLifecycleEvidenceRefV1 {
        kind: kind.into(),
        reference: reference.into(),
    }
}

fn validation_evidence_refs(metadata: &Value) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    push_metadata_ref(
        &mut evidence,
        "validation-report-id",
        metadata,
        &["validationReport", "reportId"],
    );
    push_metadata_ref(
        &mut evidence,
        "validation-report-ref",
        metadata,
        &["validationReport", "reportRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "validation-report-id",
        metadata,
        &["validationReportStore", "reportId"],
    );
    push_metadata_ref(
        &mut evidence,
        "validation-report-ref",
        metadata,
        &["validationReportStore", "reportRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "validation-report-id",
        metadata,
        &["validation", "reportId"],
    );
    push_metadata_ref(
        &mut evidence,
        "validation-ref",
        metadata,
        &["validation", "validationRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "validation-report-id",
        metadata,
        &["validationReportId"],
    );
    push_metadata_ref(
        &mut evidence,
        "validation-ref",
        metadata,
        &["validationRef"],
    );
    evidence
}

fn dispute_evidence_refs(metadata: &Value) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    push_metadata_ref(
        &mut evidence,
        "dispute-id",
        metadata,
        &["dispute", "disputeId"],
    );
    push_metadata_ref(
        &mut evidence,
        "dispute-ref",
        metadata,
        &["dispute", "disputeRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "dispute-id",
        metadata,
        &["disputeStore", "disputeId"],
    );
    push_metadata_ref(
        &mut evidence,
        "dispute-ref",
        metadata,
        &["disputeStore", "disputeRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "dispute-id",
        metadata,
        &["receiptDispute", "disputeId"],
    );
    push_metadata_ref(&mut evidence, "dispute-ref", metadata, &["disputeRef"]);
    evidence
}

fn settlement_evidence_refs(metadata: &Value) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    push_metadata_ref(
        &mut evidence,
        "settlement-id",
        metadata,
        &["settlement", "settlementId"],
    );
    push_metadata_ref(
        &mut evidence,
        "settlement-ref",
        metadata,
        &["settlement", "settlementRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "settlement-event-id",
        metadata,
        &["settlementEvent", "eventId"],
    );
    push_metadata_ref(
        &mut evidence,
        "settlement-resolution-id",
        metadata,
        &["settlementResolution", "resolutionId"],
    );
    push_metadata_ref(
        &mut evidence,
        "settlement-ref",
        metadata,
        &["settlementStore", "settlementRef"],
    );
    evidence
}

fn cancellation_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    if let Some(stream_ref) = &record.stream_ref {
        evidence.push(lifecycle_evidence("stream-ref", stream_ref));
    }
    push_metadata_ref(
        &mut evidence,
        "cancelled-by",
        &record.metadata,
        &["cancellation", "cancelledBy"],
    );
    evidence
}

fn expiration_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    record
        .metadata
        .get("expiration")
        .and_then(|expiration| expiration.get("evidenceRefs"))
        .and_then(Value::as_array)
        .map(|evidence_refs| {
            evidence_refs
                .iter()
                .filter_map(|value| {
                    let kind = value.get("kind").and_then(Value::as_str)?;
                    let reference = value.get("ref").and_then(Value::as_str)?;
                    Some(lifecycle_evidence(kind, reference))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn push_metadata_ref(
    evidence: &mut Vec<JobLifecycleEvidenceRefV1>,
    kind: &str,
    metadata: &Value,
    path: &[&str],
) {
    if let Some(reference) = json_path_str(metadata, path) {
        evidence.push(lifecycle_evidence(kind, reference));
    }
}

fn production_stage(
    stage: JobProductionStageKindV1,
    status: JobProductionStageStatusV1,
    summary: impl Into<String>,
    evidence_refs: Vec<JobLifecycleEvidenceRefV1>,
    warnings: Vec<ValidationIssue>,
) -> JobProductionLifecycleStageV1 {
    JobProductionLifecycleStageV1 {
        stage,
        status,
        summary: summary.into(),
        evidence_refs,
        warnings,
    }
}

fn stage_count(
    stages: &[JobProductionLifecycleStageV1],
    status: JobProductionStageStatusV1,
) -> usize {
    stages.iter().filter(|stage| stage.status == status).count()
}

fn production_lifecycle_store_entry(
    lifecycle: &JobProductionLifecycleV1,
) -> JobProductionLifecycleStoreEntryV1 {
    JobProductionLifecycleStoreEntryV1 {
        job_id: lifecycle.job_id.clone(),
        request_id: lifecycle.request_id.clone(),
        current_status: lifecycle.current_status.clone(),
        ready_for_settlement: lifecycle.ready_for_settlement,
        requires_operator_action: lifecycle.requires_operator_action,
        completed_stage_count: lifecycle.completed_stage_count,
        pending_stage_count: lifecycle.pending_stage_count,
        blocked_stage_count: lifecycle.blocked_stage_count,
        skipped_stage_count: lifecycle.skipped_stage_count,
        blocked_stages: lifecycle
            .stages
            .iter()
            .filter(|stage| stage.status == JobProductionStageStatusV1::Blocked)
            .map(|stage| stage.stage.clone())
            .collect(),
        pending_stages: lifecycle
            .stages
            .iter()
            .filter(|stage| stage.status == JobProductionStageStatusV1::Pending)
            .map(|stage| stage.stage.clone())
            .collect(),
        warning_count: lifecycle.warnings.len(),
    }
}

fn production_stage_key(stage: &JobProductionStageKindV1) -> String {
    serde_json::to_value(stage)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{stage:?}"))
}

fn production_stage_status_key(status: &JobProductionStageStatusV1) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{status:?}"))
}

fn non_empty_complete(value: &str, terminal: bool) -> JobProductionStageStatusV1 {
    if value.trim().is_empty() {
        if terminal {
            JobProductionStageStatusV1::Blocked
        } else {
            JobProductionStageStatusV1::Pending
        }
    } else {
        JobProductionStageStatusV1::Complete
    }
}

fn missing_when_empty(value: &str, path: &str, message: &str) -> Vec<ValidationIssue> {
    if value.trim().is_empty() {
        vec![validation_warning(path, message)]
    } else {
        Vec::new()
    }
}

fn is_free_local_settlement(method: &str) -> bool {
    matches!(
        method.trim(),
        "" | "free" | "free-local-dev" | "local-dev" | "none"
    )
}

fn policy_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    if let Some(access_grant_ref) = &record.job_order.access_grant_ref {
        evidence.push(lifecycle_evidence("access-grant-ref", access_grant_ref));
    }
    evidence.push(lifecycle_evidence(
        "privacy-tier",
        serde_json::to_value(&record.job_order.privacy.privacy_tier)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{:?}", record.job_order.privacy.privacy_tier)),
    ));
    evidence.push(lifecycle_evidence(
        "verification-tier",
        serde_json::to_value(&record.job_order.required_verification_tier)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{:?}", record.job_order.required_verification_tier)),
    ));
    push_metadata_ref(
        &mut evidence,
        "trust-policy-id",
        &record.metadata,
        &["trustPolicy", "policyId"],
    );
    push_metadata_ref(
        &mut evidence,
        "policy-decision",
        &record.metadata,
        &["policyDecision", "decision"],
    );
    push_metadata_ref(
        &mut evidence,
        "route-policy-mode",
        &record.metadata,
        &["routePlan", "policyMode"],
    );
    evidence
}

fn route_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    if let Some(route_id) = &record.selected_route_id {
        evidence.push(lifecycle_evidence("route-id", route_id));
    }
    if let Some(runner_id) = &record.runner_id {
        evidence.push(lifecycle_evidence("runner-id", runner_id));
    }
    push_metadata_ref(
        &mut evidence,
        "route-id",
        &record.metadata,
        &["routeExecution", "selectedRouteId"],
    );
    for quote in &record.quotes {
        evidence.push(lifecycle_evidence("quote-runner-id", &quote.runner_id));
    }
    evidence
}

fn payment_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    push_metadata_ref(
        &mut evidence,
        "payment-authorization-id",
        &record.metadata,
        &["paymentAuthorization", "authorizationId"],
    );
    push_metadata_ref(
        &mut evidence,
        "payment-ref",
        &record.metadata,
        &["paymentAuthorization", "paymentRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "escrow-ref",
        &record.metadata,
        &["paymentAuthorization", "escrowRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "payment-ref",
        &record.metadata,
        &["paymentRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "escrow-ref",
        &record.metadata,
        &["escrowRef"],
    );
    if let Some(lease) = &record.lease {
        if !lease.settlement_ref.trim().is_empty() {
            evidence.push(lifecycle_evidence("settlement-ref", &lease.settlement_ref));
        }
    }
    evidence
}

fn execution_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = route_evidence_refs(record);
    if let Some(status) = &record.execution_status {
        evidence.push(lifecycle_evidence(
            "execution-status",
            serde_json::to_value(status)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_else(|| format!("{status:?}")),
        ));
    }
    evidence
}

fn stream_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    if let Some(stream_ref) = &record.stream_ref {
        evidence.push(lifecycle_evidence("stream-ref", stream_ref));
    }
    push_metadata_ref(
        &mut evidence,
        "stream-ref",
        &record.metadata,
        &["streamEventStore", "storageRefs", "0"],
    );
    if let Some(count) = record.stream_event_count {
        evidence.push(lifecycle_evidence("stream-event-count", count.to_string()));
    }
    evidence
}

fn receipt_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    if let Some(receipt_id) = &record.receipt_id {
        evidence.push(lifecycle_evidence("receipt-id", receipt_id));
    }
    if let Some(receipt_ref) = &record.receipt_ref {
        evidence.push(lifecycle_evidence("receipt-ref", receipt_ref));
    }
    push_metadata_ref(
        &mut evidence,
        "receipt-id",
        &record.metadata,
        &["linkedReceipt", "evidenceId"],
    );
    push_metadata_ref(
        &mut evidence,
        "receipt-ref",
        &record.metadata,
        &["linkedReceipt", "evidenceRef"],
    );
    evidence
}

fn reputation_evidence_refs(metadata: &Value) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = Vec::new();
    push_metadata_ref(
        &mut evidence,
        "runner-reputation-ref",
        metadata,
        &["reputation", "runnerReputationRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "reputation-profile-ref",
        metadata,
        &["reputationProfile", "profileRef"],
    );
    push_metadata_ref(
        &mut evidence,
        "validator-score-ref",
        metadata,
        &["runnerReputation", "validatorScoreRef"],
    );
    evidence
}

fn stored_evidence_refs(record: &JobRecordV1) -> Vec<JobLifecycleEvidenceRefV1> {
    let mut evidence = receipt_evidence_refs(record);
    evidence.extend(stream_evidence_refs(record));
    evidence.extend(validation_evidence_refs(&record.metadata));
    evidence.extend(settlement_evidence_refs(&record.metadata));
    evidence
}

fn apply_evidence_link_metadata(
    record: &mut JobRecordV1,
    request: &JobEvidenceLinkRequestV1,
    linked_at: &str,
) {
    let evidence_id = request.evidence_id.clone();
    let evidence_ref = request.evidence_ref.clone();
    let common = json!({
        "schemaVersion": "swarm-ai.job-evidence-link.v1",
        "evidenceKind": request.evidence_kind,
        "evidenceId": evidence_id,
        "evidenceRef": evidence_ref,
        "linkedBy": request.linked_by,
        "linkedAt": linked_at,
        "summary": request.summary,
        "metadata": request.metadata
    });
    match &request.evidence_kind {
        JobEvidenceKindV1::ValidationReport => {
            record.metadata["validationReport"] = json!({
                "reportId": evidence_id,
                "reportRef": evidence_ref,
                "link": common
            });
        }
        JobEvidenceKindV1::DisputeEvidence => {
            record.metadata["dispute"] = json!({
                "disputeId": evidence_id,
                "disputeRef": evidence_ref,
                "link": common
            });
        }
        JobEvidenceKindV1::SettlementEvent => {
            record.metadata["settlementEvent"] = json!({
                "eventId": evidence_id,
                "settlementRef": evidence_ref,
                "link": common.clone()
            });
            record.metadata["settlement"] = json!({
                "settlementId": request.evidence_id.clone(),
                "settlementRef": request.evidence_ref.clone(),
                "link": common
            });
        }
        JobEvidenceKindV1::SettlementResolution => {
            record.metadata["settlementResolution"] = json!({
                "resolutionId": evidence_id,
                "settlementRef": evidence_ref,
                "link": common
            });
        }
        JobEvidenceKindV1::Receipt => {
            if let Some(receipt_id) = &request.evidence_id {
                record.receipt_id = Some(receipt_id.clone());
            }
            record.receipt_ref = Some(request.evidence_ref.clone());
            record.metadata["linkedReceipt"] = common;
        }
        JobEvidenceKindV1::StreamEvents => {
            record.stream_ref = Some(request.evidence_ref.clone());
            record.metadata["streamEventStore"] = json!({
                "schemaVersion": "swarm-ai.stream-event-store.v1",
                "stored": true,
                "storageRefs": [request.evidence_ref],
                "link": common
            });
        }
        JobEvidenceKindV1::Other => {}
    }
}

fn append_metadata_array(metadata: &mut Value, key: &str, entry: Value) {
    if !metadata.is_object() {
        *metadata = json!({});
    }
    if !metadata.get(key).is_some_and(Value::is_array) {
        metadata[key] = json!([]);
    }
    if let Some(entries) = metadata.get_mut(key).and_then(Value::as_array_mut) {
        entries.push(entry);
    }
}

fn validation_warning(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn read_job_record(path: &Path) -> Result<JobRecordV1> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn job_lookup(record: JobRecordV1, path: PathBuf) -> JobLookupResultV1 {
    JobLookupResultV1 {
        schema_version: "swarm-ai.job-lookup.v1".to_string(),
        job_id: record.job_id.clone(),
        job_path: path.display().to_string(),
        record,
    }
}

fn job_entry(record: &JobRecordV1, job_path: String) -> JobStoreEntryV1 {
    JobStoreEntryV1 {
        job_id: record.job_id.clone(),
        request_id: record.request_id.clone(),
        status: record.status.clone(),
        package_id: record.job_order.package_id.clone(),
        package_ref: record.job_order.package_ref.clone(),
        task: record.job_order.task.clone(),
        runner_id: record.runner_id.clone(),
        receipt_id: record.receipt_id.clone(),
        created_at: record.created_at.clone(),
        updated_at: record.updated_at.clone(),
        completed_at: record.completed_at.clone(),
        job_path,
    }
}

fn job_path(job_dir: &Path, job_id: &str) -> PathBuf {
    job_dir.join(format!("{}.json", safe_file_component(job_id)))
}

fn job_status_from_execution(status: &ExecutionStatus) -> JobRecordStatusV1 {
    match status {
        ExecutionStatus::Succeeded => JobRecordStatusV1::Succeeded,
        ExecutionStatus::Failed => JobRecordStatusV1::Failed,
        ExecutionStatus::Cancelled => JobRecordStatusV1::Cancelled,
        ExecutionStatus::Partial => JobRecordStatusV1::Partial,
    }
}

fn status_key(status: &JobRecordStatusV1) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{status:?}"))
}

fn is_terminal_status(status: &JobRecordStatusV1) -> bool {
    matches!(
        status,
        JobRecordStatusV1::Succeeded | JobRecordStatusV1::Failed | JobRecordStatusV1::Cancelled
    )
}

fn execution_metadata_summary(metadata: &Value) -> Value {
    json!({
        "source": "execution-response",
        "routeDecisionStore": metadata.get("routeDecisionStore").cloned(),
        "routeExecution": metadata.get("routeExecution").cloned(),
        "routeTraceStore": metadata.get("routeTraceStore").cloned(),
        "routePlan": metadata.get("routePlan").cloned(),
        "marketplaceLifecycle": metadata.get("marketplaceLifecycle").cloned(),
        "jobQuotes": metadata.get("jobQuotes").cloned(),
        "executionLease": metadata.get("executionLease").cloned(),
        "marketplaceServiceQuote": metadata.get("marketplaceServiceQuote").cloned(),
        "serviceQuoteStore": metadata.get("serviceQuoteStore").cloned(),
        "paymentAuthorization": metadata.get("paymentAuthorization").cloned(),
        "paymentAuthorizationVerification": metadata.get("paymentAuthorizationVerification").cloned(),
        "paymentAuthorizationStore": metadata.get("paymentAuthorizationStore").cloned(),
        "settlement": metadata.get("settlement").cloned(),
        "settlementEvent": metadata.get("settlementEvent").cloned(),
        "settlementVerification": metadata.get("settlementVerification").cloned(),
        "settlementStore": metadata.get("settlementStore").cloned(),
        "marketplaceAuditStore": metadata.get("marketplaceAuditStore").cloned(),
        "receiptStore": metadata.get("receiptStore").cloned(),
        "streamEventStore": metadata.get("streamEventStore").cloned(),
        "streamEventSummary": metadata.get("streamEventSummary").cloned()
    })
}

fn response_job_quotes(metadata: &Value) -> Vec<JobQuoteV1> {
    metadata
        .get("jobQuotes")
        .and_then(|quotes| serde_json::from_value::<Vec<JobQuoteV1>>(quotes.clone()).ok())
        .or_else(|| {
            metadata
                .get("jobQuote")
                .and_then(|quote| serde_json::from_value::<JobQuoteV1>(quote.clone()).ok())
                .map(|quote| vec![quote])
        })
        .unwrap_or_default()
}

fn response_execution_lease(metadata: &Value) -> Option<ExecutionLeaseV1> {
    metadata
        .get("executionLease")
        .and_then(|lease| serde_json::from_value::<ExecutionLeaseV1>(lease.clone()).ok())
}

fn selected_runner_id(metadata: &Value) -> Option<String> {
    let selected_route_id = json_path_str(metadata, &["routeExecution", "selectedRouteId"])?;
    let attempts = metadata
        .get("routeExecution")
        .and_then(|trace| trace.get("attempts"))
        .and_then(Value::as_array)?;
    attempts
        .iter()
        .find(|attempt| json_path_str(attempt, &["routeId"]) == Some(selected_route_id))
        .and_then(|attempt| json_path_str(attempt, &["runnerId"]))
        .map(str::to_string)
        .or_else(|| json_path_str(metadata, &["receipt", "runnerId"]).map(str::to_string))
}

fn first_storage_ref(metadata: &Value) -> Option<String> {
    metadata
        .get("streamEventStore")
        .and_then(|store| store.get("storageRefs"))
        .and_then(Value::as_array)
        .and_then(|refs| refs.first())
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn json_path_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

fn json_path_u64(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_u64()
}

fn safe_file_component(value: &str) -> String {
    let component: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if component.is_empty() {
        "job".to_string()
    } else {
        component
    }
}

fn empty_metadata() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ApiSurface, ExecutionConstraintsV1, ExecutionMetrics, ExecutionOptions, IntegrityTier,
        JobPrivacyV1, OutputContractV1, PriceModel, PriceV1, RetryPolicyV1,
    };

    #[test]
    fn job_record_store_lists_and_gets_records() {
        let dir = test_temp_dir("hivemind-job-store");
        let order = job_order("job-store-1", "request-store-1");
        let quote = quote(&order);
        let record = job_record_with_quotes(order.clone(), vec![quote], "2026-06-02T00:00:00Z");

        upsert_job_record(&dir, record).unwrap();

        let lookup = get_job_record(&dir, &order.job_id).unwrap().unwrap();
        assert_eq!(lookup.record.status, JobRecordStatusV1::Quoted);
        assert_eq!(lookup.record.quotes.len(), 1);
        let summary = list_job_records(&dir).unwrap();
        assert_eq!(summary.job_count, 1);
        assert_eq!(summary.jobs[0].job_id, order.job_id);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expiration_sweep_fails_quoted_job_after_all_quotes_expire() {
        let dir = test_temp_dir("hivemind-job-expire-quotes");
        let order = job_order("job-expire-quotes-1", "request-expire-quotes-1");
        let mut stale_quote = quote(&order);
        stale_quote.expires_at = "2026-06-02T00:00:10Z".to_string();
        let record =
            job_record_with_quotes(order.clone(), vec![stale_quote], "2026-06-02T00:00:00Z");
        upsert_job_record(&dir, record).unwrap();

        let mut request = job_expiration_sweep_request();
        request.observed_at = Some("2026-06-02T00:00:11Z".to_string());
        let result = expire_stale_job_records(&dir, &request).unwrap();

        assert_eq!(result.scanned_job_count, 1);
        assert_eq!(result.expired_job_count, 1);
        assert_eq!(
            result.expired_jobs[0].expiration_kind,
            JobExpirationKindV1::QuoteExpired
        );
        assert_eq!(
            result.expired_jobs[0].previous_status,
            JobRecordStatusV1::Quoted
        );
        assert_eq!(
            result.expired_jobs[0].record.error.as_ref().unwrap().code,
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            result.expired_jobs[0].record.metadata["expiration"]["expirationKind"],
            "quote-expired"
        );
        let timeline = job_lifecycle_timeline(&result.expired_jobs[0].record);
        assert_eq!(
            timeline.events.last().unwrap().metadata["expiration"]["expiredAt"],
            "2026-06-02T00:00:10Z"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn job_store_audit_reports_coverage_warnings_and_stale_jobs() {
        let dir = test_temp_dir("hivemind-job-store-audit");
        let mut stale_order = job_order("job-audit-stale-1", "request-audit-stale-1");
        stale_order.validation_required = true;
        let mut stale_quote = quote(&stale_order);
        stale_quote.expires_at = "2026-06-02T00:00:10Z".to_string();
        let stale_record = job_record_with_quotes(
            stale_order.clone(),
            vec![stale_quote],
            "2026-06-02T00:00:00Z",
        );
        upsert_job_record(&dir, stale_record).unwrap();

        let done_order = job_order("job-audit-done-1", "request-audit-done-1");
        let mut response = ExecutionResponseV1::succeeded(
            "request-audit-done-1",
            json!({ "message": { "content": "done" } }),
            ExecutionMetrics::default(),
        );
        response.metadata = json!({
            "jobOrder": done_order,
            "receiptStore": {
                "receiptId": "receipt-audit-1",
                "receiptRef": "local://receipt/receipt-audit-1"
            },
            "streamEventSummary": {
                "eventCount": 2
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-audit-done-1"]
            }
        });
        let done_record =
            job_record_from_execution_response(&response, "2026-06-02T00:00:01Z").unwrap();
        upsert_job_record(&dir, done_record).unwrap();

        let mut request = job_store_audit_request();
        request.observed_at = Some("2026-06-02T00:00:11Z".to_string());
        let audit = audit_job_store(&dir, &request).unwrap();

        assert_eq!(audit.job_count, 2);
        assert_eq!(audit.active_job_count, 1);
        assert_eq!(audit.terminal_job_count, 1);
        assert_eq!(audit.status_counts.get("quoted"), Some(&1));
        assert_eq!(audit.status_counts.get("succeeded"), Some(&1));
        assert_eq!(audit.receipt_linked_job_count, 1);
        assert_eq!(audit.stream_linked_job_count, 1);
        assert_eq!(audit.jobs_requiring_validation_count, 1);
        assert_eq!(audit.jobs_missing_required_validation_count, 1);
        assert_eq!(audit.stale_job_count, 1);
        assert_eq!(audit.stale_quoted_job_count, 1);
        assert_eq!(
            audit.stale_jobs[0].expiration_kind,
            JobExpirationKindV1::QuoteExpired
        );
        assert!(audit.timeline_warning_count >= 1);
        assert!(
            audit
                .jobs_with_warnings
                .iter()
                .any(|job| job.job_id == stale_order.job_id)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expiration_sweep_preserves_job_with_active_quote() {
        let dir = test_temp_dir("hivemind-job-expire-active-quote");
        let order = job_order("job-expire-active-quote-1", "request-expire-active-quote-1");
        let mut active_quote = quote(&order);
        active_quote.expires_at = "2026-06-02T00:00:12Z".to_string();
        let record =
            job_record_with_quotes(order.clone(), vec![active_quote], "2026-06-02T00:00:00Z");
        upsert_job_record(&dir, record).unwrap();

        let mut request = job_expiration_sweep_request();
        request.observed_at = Some("2026-06-02T00:00:11Z".to_string());
        let result = expire_stale_job_records(&dir, &request).unwrap();
        let lookup = get_job_record(&dir, &order.job_id).unwrap().unwrap();

        assert_eq!(result.scanned_job_count, 1);
        assert_eq!(result.expired_job_count, 0);
        assert_eq!(lookup.record.status, JobRecordStatusV1::Quoted);
        assert!(lookup.record.error.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expiration_sweep_fails_leased_job_after_deadline() {
        let dir = test_temp_dir("hivemind-job-expire-lease");
        let order = job_order("job-expire-lease-1", "request-expire-lease-1");
        let record = job_record_with_lease(
            &ExecutionLeaseRequestV1 {
                schema_version: "swarm-ai.execution-lease-request.v1".to_string(),
                job_order: order.clone(),
                quote: quote(&order),
                requester: "local-dev".to_string(),
                settlement_ref: "local://settlement".to_string(),
                start_after: None,
                deadline: "2026-06-02T00:00:10Z".to_string(),
            },
            ExecutionLeaseV1 {
                schema_version: "swarm-ai.execution-lease.v1".to_string(),
                lease_id: "lease-expire-1".to_string(),
                job_id: order.job_id.clone(),
                quote_id: "quote-1".to_string(),
                runner_id: "local-dev".to_string(),
                requester: "local-dev".to_string(),
                allowed_input_refs: vec![format!("sha256://{}", order.input_hash)],
                allowed_input_hashes: vec![order.input_hash.clone()],
                allowed_package_refs: vec![order.package_ref.clone()],
                max_cost: PriceV1 {
                    amount: 0.0,
                    currency: "none".to_string(),
                },
                start_after: None,
                deadline: "2026-06-02T00:00:10Z".to_string(),
                cancellation_rules: json!({}),
                settlement_ref: "local://settlement".to_string(),
                signature: None,
            },
            "2026-06-02T00:00:00Z",
        );
        upsert_job_record(&dir, record).unwrap();

        let mut request = job_expiration_sweep_request();
        request.observed_at = Some("2026-06-02T00:00:11Z".to_string());
        let result = expire_stale_job_records(&dir, &request).unwrap();

        assert_eq!(result.expired_job_count, 1);
        assert_eq!(
            result.expired_jobs[0].expiration_kind,
            JobExpirationKindV1::LeaseExpired
        );
        assert_eq!(
            result.expired_jobs[0].previous_status,
            JobRecordStatusV1::Leased
        );
        assert_eq!(
            result.expired_jobs[0].record.metadata["expiration"]["evidenceRefs"][0]["ref"],
            "lease-expire-1"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn execution_response_record_extracts_audit_links() {
        let order = job_order("job-exec-1", "request-exec-1");
        let mut response = ExecutionResponseV1::succeeded(
            "request-exec-1",
            json!({ "message": { "content": "done" } }),
            ExecutionMetrics::default(),
        );
        response.receipt_ref = Some("local://receipt/receipt-1".to_string());
        response.metadata = json!({
            "jobOrder": order,
            "routeExecution": {
                "selectedRouteId": "local-route",
                "attempts": [
                    { "routeId": "local-route", "runnerId": "local-dev" }
                ]
            },
            "receiptStore": {
                "receiptId": "receipt-1",
                "receiptRef": "local://receipt/receipt-1"
            },
            "streamEventSummary": {
                "eventCount": 3
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-exec-1"]
            }
        });

        let record = job_record_from_execution_response(&response, "2026-06-02T00:00:01Z").unwrap();

        assert_eq!(record.status, JobRecordStatusV1::Succeeded);
        assert_eq!(record.runner_id.as_deref(), Some("local-dev"));
        assert_eq!(record.receipt_id.as_deref(), Some("receipt-1"));
        assert_eq!(record.stream_event_count, Some(3));
        assert_eq!(
            record.stream_ref.as_deref(),
            Some("local://stream-events/job-exec-1")
        );
        assert!(record.completed_at.is_some());
    }

    #[test]
    fn lifecycle_timeline_orders_execution_evidence() {
        let order = job_order("job-timeline-exec-1", "request-timeline-exec-1");
        let mut response = ExecutionResponseV1::succeeded(
            "request-timeline-exec-1",
            json!({ "message": { "content": "done" } }),
            ExecutionMetrics::default(),
        );
        response.metadata = json!({
            "jobOrder": order,
            "routeExecution": {
                "selectedRouteId": "local-route",
                "attempts": [
                    { "routeId": "local-route", "runnerId": "local-dev" }
                ]
            },
            "receiptStore": {
                "receiptId": "receipt-timeline-1",
                "receiptRef": "local://receipt/receipt-timeline-1"
            },
            "streamEventSummary": {
                "eventCount": 4
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-timeline-exec-1"]
            }
        });

        let record = job_record_from_execution_response(&response, "2026-06-02T00:00:01Z").unwrap();
        let timeline = job_lifecycle_timeline(&record);
        let phases = timeline
            .events
            .iter()
            .map(|event| event.phase.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            phases,
            vec![
                JobLifecyclePhaseV1::Created,
                JobLifecyclePhaseV1::Running,
                JobLifecyclePhaseV1::Streamed,
                JobLifecyclePhaseV1::ReceiptCaptured,
                JobLifecyclePhaseV1::Succeeded
            ]
        );
        assert_eq!(timeline.event_count, timeline.events.len());
        assert!(timeline.warnings.is_empty());
        assert_eq!(timeline.events[2].metadata["streamEventCount"], json!(4));
        assert_eq!(
            timeline.events[3].evidence_refs[0].reference,
            "receipt-timeline-1"
        );
    }

    #[test]
    fn production_lifecycle_summarizes_local_success_without_operator_action() {
        let order = job_order("job-production-local-1", "request-production-local-1");
        let mut response = ExecutionResponseV1::succeeded(
            "request-production-local-1",
            json!({ "message": { "content": "done" } }),
            ExecutionMetrics::default(),
        );
        response.metadata = json!({
            "jobOrder": order,
            "routeExecution": {
                "selectedRouteId": "local-route",
                "attempts": [
                    { "routeId": "local-route", "runnerId": "local-dev" }
                ]
            },
            "receiptStore": {
                "receiptId": "receipt-production-1",
                "receiptRef": "local://receipt/receipt-production-1"
            },
            "streamEventSummary": {
                "eventCount": 2
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-production-local-1"]
            }
        });

        let record = job_record_from_execution_response(&response, "2026-06-02T00:00:01Z").unwrap();
        let lifecycle = job_production_lifecycle(&record);

        assert_eq!(
            lifecycle.schema_version,
            "swarm-ai.job-production-lifecycle.v1"
        );
        assert_eq!(lifecycle.stages.len(), 15);
        assert!(!lifecycle.ready_for_settlement);
        assert!(!lifecycle.requires_operator_action);
        assert_eq!(
            stage_status(&lifecycle, JobProductionStageKindV1::RunnerDiscovery),
            JobProductionStageStatusV1::Complete
        );
        assert_eq!(
            stage_status(&lifecycle, JobProductionStageKindV1::QuoteRanking),
            JobProductionStageStatusV1::Skipped
        );
        assert_eq!(
            stage_status(&lifecycle, JobProductionStageKindV1::PaymentReserved),
            JobProductionStageStatusV1::Skipped
        );
        assert_eq!(
            stage_status(&lifecycle, JobProductionStageKindV1::ReceiptProduced),
            JobProductionStageStatusV1::Complete
        );
        assert_eq!(
            stage_status(&lifecycle, JobProductionStageKindV1::EvidenceStored),
            JobProductionStageStatusV1::Complete
        );
    }

    #[test]
    fn production_lifecycle_blocks_terminal_job_missing_required_validation() {
        let mut order = job_order(
            "job-production-validation-1",
            "request-production-validation-1",
        );
        order.validation_required = true;
        let mut response = ExecutionResponseV1::succeeded(
            "request-production-validation-1",
            json!({ "message": { "content": "done" } }),
            ExecutionMetrics::default(),
        );
        response.metadata = json!({
            "jobOrder": order,
            "routeExecution": {
                "selectedRouteId": "local-route",
                "attempts": [
                    { "routeId": "local-route", "runnerId": "local-dev" }
                ]
            },
            "receiptStore": {
                "receiptId": "receipt-validation-1",
                "receiptRef": "local://receipt/receipt-validation-1"
            },
            "streamEventSummary": {
                "eventCount": 2
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-production-validation-1"]
            }
        });

        let record = job_record_from_execution_response(&response, "2026-06-02T00:00:01Z").unwrap();
        let lifecycle = job_production_lifecycle(&record);

        assert!(lifecycle.requires_operator_action);
        assert!(lifecycle.blocked_stage_count >= 1);
        assert_eq!(
            stage_status(&lifecycle, JobProductionStageKindV1::ValidationPerformed),
            JobProductionStageStatusV1::Blocked
        );
        assert!(
            lifecycle
                .warnings
                .iter()
                .any(|warning| warning.path == "$.metadata.validation")
        );
    }

    #[test]
    fn production_lifecycle_store_summary_counts_stage_coverage() {
        let dir = test_temp_dir("hivemind-job-production-lifecycle-store");
        let done_order = job_order(
            "job-production-store-done-1",
            "request-production-store-done-1",
        );
        let mut done_response = ExecutionResponseV1::succeeded(
            "request-production-store-done-1",
            json!({ "message": { "content": "done" } }),
            ExecutionMetrics::default(),
        );
        done_response.metadata = json!({
            "jobOrder": done_order,
            "routeExecution": {
                "selectedRouteId": "local-route",
                "attempts": [
                    { "routeId": "local-route", "runnerId": "local-dev" }
                ]
            },
            "receiptStore": {
                "receiptId": "receipt-production-store-1",
                "receiptRef": "local://receipt/receipt-production-store-1"
            },
            "streamEventSummary": {
                "eventCount": 2
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-production-store-done-1"]
            }
        });
        upsert_job_record(
            &dir,
            job_record_from_execution_response(&done_response, "2026-06-02T00:00:01Z").unwrap(),
        )
        .unwrap();

        let mut blocked_order = job_order(
            "job-production-store-blocked-1",
            "request-production-store-blocked-1",
        );
        blocked_order.validation_required = true;
        let mut blocked_response = ExecutionResponseV1::succeeded(
            "request-production-store-blocked-1",
            json!({ "message": { "content": "done" } }),
            ExecutionMetrics::default(),
        );
        blocked_response.metadata = json!({
            "jobOrder": blocked_order,
            "routeExecution": {
                "selectedRouteId": "local-route",
                "attempts": [
                    { "routeId": "local-route", "runnerId": "local-dev" }
                ]
            },
            "receiptStore": {
                "receiptId": "receipt-production-store-blocked-1",
                "receiptRef": "local://receipt/receipt-production-store-blocked-1"
            },
            "streamEventSummary": {
                "eventCount": 2
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-production-store-blocked-1"]
            }
        });
        upsert_job_record(
            &dir,
            job_record_from_execution_response(&blocked_response, "2026-06-02T00:00:02Z").unwrap(),
        )
        .unwrap();

        let request = job_store_audit_request();
        let summary = audit_job_production_lifecycles(&dir, &request).unwrap();

        assert_eq!(summary.job_count, 2);
        assert_eq!(summary.blocked_job_count, 1);
        assert_eq!(summary.requires_operator_action_count, 1);
        assert!(summary.blocked_stage_count >= 1);
        assert_eq!(
            summary.stage_status_counts["validation-performed"]["blocked"],
            1
        );
        assert_eq!(summary.jobs[0].blocked_stage_count, 1);
        assert_eq!(
            summary.jobs[0].blocked_stages,
            vec![JobProductionStageKindV1::ValidationPerformed]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cancellation_transitions_active_job_and_preserves_audit_fields() {
        let dir = test_temp_dir("hivemind-job-cancel");
        let order = job_order("job-cancel-1", "request-cancel-1");
        let record = job_record_with_lease(
            &ExecutionLeaseRequestV1 {
                schema_version: "swarm-ai.execution-lease-request.v1".to_string(),
                job_order: order.clone(),
                quote: quote(&order),
                requester: "local-dev".to_string(),
                settlement_ref: "local://settlement".to_string(),
                start_after: None,
                deadline: "2026-06-02T00:05:00Z".to_string(),
            },
            ExecutionLeaseV1 {
                schema_version: "swarm-ai.execution-lease.v1".to_string(),
                lease_id: "lease-1".to_string(),
                job_id: order.job_id.clone(),
                quote_id: "quote-1".to_string(),
                runner_id: "local-dev".to_string(),
                requester: "local-dev".to_string(),
                allowed_input_refs: vec![format!("sha256://{}", order.input_hash)],
                allowed_input_hashes: vec![order.input_hash.clone()],
                allowed_package_refs: vec![order.package_ref.clone()],
                max_cost: PriceV1 {
                    amount: 0.0,
                    currency: "none".to_string(),
                },
                start_after: None,
                deadline: "2026-06-02T00:05:00Z".to_string(),
                cancellation_rules: json!({}),
                settlement_ref: "local://settlement".to_string(),
                signature: None,
            },
            "2026-06-02T00:00:00Z",
        );
        upsert_job_record(&dir, record).unwrap();

        let request = job_cancellation_request(&order.job_id, "local-dev", "user requested stop");
        let result = cancel_job_record(&dir, &request, "2026-06-02T00:00:01Z")
            .unwrap()
            .unwrap();

        assert!(result.transitioned);
        assert!(!result.terminal_already);
        assert_eq!(result.previous_status, JobRecordStatusV1::Leased);
        assert_eq!(result.current_status, JobRecordStatusV1::Cancelled);
        assert_eq!(
            result.record.execution_status,
            Some(ExecutionStatus::Cancelled)
        );
        assert_eq!(
            result.record.metadata["cancellation"]["reason"],
            "user requested stop"
        );
        assert_eq!(result.record.quotes.len(), 1);
        assert!(result.record.lease.is_some());

        let lookup = get_job_record(&dir, &order.job_id).unwrap().unwrap();
        assert_eq!(lookup.record.status, JobRecordStatusV1::Cancelled);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lifecycle_timeline_preserves_quote_lease_and_cancellation_evidence() {
        let dir = test_temp_dir("hivemind-job-cancel-timeline");
        let order = job_order("job-cancel-timeline-1", "request-cancel-timeline-1");
        let record = job_record_with_lease(
            &ExecutionLeaseRequestV1 {
                schema_version: "swarm-ai.execution-lease-request.v1".to_string(),
                job_order: order.clone(),
                quote: quote(&order),
                requester: "local-dev".to_string(),
                settlement_ref: "local://settlement".to_string(),
                start_after: None,
                deadline: "2026-06-02T00:05:00Z".to_string(),
            },
            ExecutionLeaseV1 {
                schema_version: "swarm-ai.execution-lease.v1".to_string(),
                lease_id: "lease-timeline-1".to_string(),
                job_id: order.job_id.clone(),
                quote_id: "quote-1".to_string(),
                runner_id: "local-dev".to_string(),
                requester: "local-dev".to_string(),
                allowed_input_refs: vec![format!("sha256://{}", order.input_hash)],
                allowed_input_hashes: vec![order.input_hash.clone()],
                allowed_package_refs: vec![order.package_ref.clone()],
                max_cost: PriceV1 {
                    amount: 0.0,
                    currency: "none".to_string(),
                },
                start_after: None,
                deadline: "2026-06-02T00:05:00Z".to_string(),
                cancellation_rules: json!({}),
                settlement_ref: "local://settlement".to_string(),
                signature: None,
            },
            "2026-06-02T00:00:00Z",
        );
        upsert_job_record(&dir, record).unwrap();

        let request = job_cancellation_request(&order.job_id, "local-dev", "user requested stop");
        let result = cancel_job_record(&dir, &request, "2026-06-02T00:00:01Z")
            .unwrap()
            .unwrap();
        let timeline = job_lifecycle_timeline(&result.record);
        let phases = timeline
            .events
            .iter()
            .map(|event| event.phase.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            phases,
            vec![
                JobLifecyclePhaseV1::Created,
                JobLifecyclePhaseV1::Quoted,
                JobLifecyclePhaseV1::Leased,
                JobLifecyclePhaseV1::Cancelled
            ]
        );
        assert!(timeline.warnings.is_empty());
        assert_eq!(timeline.events[1].evidence_refs[0].reference, "quote-1");
        assert_eq!(
            timeline.events[2].evidence_refs[0].reference,
            "lease-timeline-1"
        );
        assert_eq!(
            timeline.events[3].metadata["cancellation"]["reason"],
            "user requested stop"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evidence_link_adds_validation_phase_to_timeline() {
        let dir = test_temp_dir("hivemind-job-evidence-validation");
        let order = job_order("job-evidence-validation-1", "request-evidence-validation-1");
        let mut record = job_record_from_order(order.clone(), "2026-06-02T00:00:00Z");
        record.job_order.validation_required = true;
        upsert_job_record(&dir, record).unwrap();

        let mut request = job_evidence_link_request(
            &order.job_id,
            JobEvidenceKindV1::ValidationReport,
            "local://validation/report-1",
            "validator-1",
        );
        request.evidence_id = Some("report-1".to_string());
        request.summary = Some("validation passed".to_string());
        let result = link_job_evidence(&dir, &request, "2026-06-02T00:00:02Z")
            .unwrap()
            .unwrap();

        let phases = result
            .timeline
            .events
            .iter()
            .map(|event| event.phase.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                JobLifecyclePhaseV1::Created,
                JobLifecyclePhaseV1::ValidationLinked
            ]
        );
        assert!(result.timeline.warnings.is_empty());
        assert_eq!(
            result.record.metadata["validationReport"]["reportRef"],
            "local://validation/report-1"
        );
        assert_eq!(
            result.record.metadata["evidenceLinks"][0]["summary"],
            "validation passed"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evidence_links_add_dispute_and_settlement_phases() {
        let dir = test_temp_dir("hivemind-job-evidence-dispute-settlement");
        let order = job_order("job-evidence-settlement-1", "request-evidence-settlement-1");
        upsert_job_record(
            &dir,
            job_record_from_order(order.clone(), "2026-06-02T00:00:00Z"),
        )
        .unwrap();

        let mut dispute = job_evidence_link_request(
            &order.job_id,
            JobEvidenceKindV1::DisputeEvidence,
            "local://disputes/dispute-1",
            "claimant-1",
        );
        dispute.evidence_id = Some("dispute-1".to_string());
        link_job_evidence(&dir, &dispute, "2026-06-02T00:00:01Z").unwrap();

        let mut settlement = job_evidence_link_request(
            &order.job_id,
            JobEvidenceKindV1::SettlementEvent,
            "local://settlements/settlement-1",
            "market-1",
        );
        settlement.evidence_id = Some("settlement-1".to_string());
        let result = link_job_evidence(&dir, &settlement, "2026-06-02T00:00:02Z")
            .unwrap()
            .unwrap();
        let phases = result
            .timeline
            .events
            .iter()
            .map(|event| event.phase.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            phases,
            vec![
                JobLifecyclePhaseV1::Created,
                JobLifecyclePhaseV1::DisputeOpened,
                JobLifecyclePhaseV1::Settled
            ]
        );
        assert_eq!(
            result.record.metadata["settlementEvent"]["settlementRef"],
            "local://settlements/settlement-1"
        );
        assert_eq!(
            result.record.metadata["evidenceLinks"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cancellation_does_not_reopen_terminal_success() {
        let dir = test_temp_dir("hivemind-job-cancel-terminal");
        let order = job_order("job-done-1", "request-done-1");
        let mut response = ExecutionResponseV1::succeeded(
            "request-done-1",
            json!({ "ok": true }),
            ExecutionMetrics::default(),
        );
        response.metadata = json!({ "jobOrder": order.clone() });
        let record = job_record_from_execution_response(&response, "2026-06-02T00:00:01Z").unwrap();
        upsert_job_record(&dir, record).unwrap();

        let request = job_cancellation_request(&order.job_id, "local-dev", "too late");
        let result = cancel_job_record(&dir, &request, "2026-06-02T00:00:02Z")
            .unwrap()
            .unwrap();

        assert!(!result.transitioned);
        assert!(result.terminal_already);
        assert_eq!(result.previous_status, JobRecordStatusV1::Succeeded);
        assert_eq!(result.current_status, JobRecordStatusV1::Succeeded);
        assert!(result.record.metadata.get("cancellation").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    fn job_order(job_id: &str, request_id: &str) -> JobOrderV1 {
        JobOrderV1 {
            schema_version: "swarm-ai.job-order.v1".to_string(),
            job_id: job_id.to_string(),
            request_id: request_id.to_string(),
            requester: "local-dev".to_string(),
            package_ref: "bzz://job-package".to_string(),
            package_id: "hivemind/job-package".to_string(),
            package_version: "0.1.0".to_string(),
            api_surface: ApiSurface::HivemindNative,
            modalities: vec![],
            task: "chat".to_string(),
            input_hash: "0".repeat(64),
            preferred_artifact_group: None,
            output_contract: OutputContractV1 {
                task: "chat".to_string(),
                output_schema_ref: None,
            },
            constraints: ExecutionConstraintsV1::from(&ExecutionOptions::default()),
            privacy: JobPrivacyV1 {
                privacy_tier: hivemind_core::PrivacyTier::Standard,
                receipt_mode: hivemind_core::execution::ReceiptMode::HashOnly,
                data_retention_rule: None,
                logging_rule: None,
            },
            required_verification_tier: IntegrityTier::ReceiptOnly,
            access_grant_ref: None,
            max_price: None,
            validation_required: false,
            settlement_method: "free-local-dev".to_string(),
            retry_policy: RetryPolicyV1::default(),
            signature: None,
        }
    }

    fn quote(order: &JobOrderV1) -> JobQuoteV1 {
        JobQuoteV1 {
            schema_version: "swarm-ai.job-quote.v1".to_string(),
            quote_id: "quote-1".to_string(),
            job_id: order.job_id.clone(),
            runner_id: "local-dev".to_string(),
            route_id: Some("local-route".to_string()),
            price: PriceV1 {
                amount: 0.0,
                currency: "none".to_string(),
            },
            price_model: PriceModel::Fixed,
            privacy_mode: hivemind_core::PrivacyTier::Standard,
            verification_mode: IntegrityTier::ReceiptOnly,
            estimated_start_delay_ms: 0,
            estimated_time_to_first_output_ms: Some(1),
            estimated_completion_ms: Some(1),
            cache_hit_claim: false,
            validation_support: vec![],
            expires_at: "2026-06-02T00:05:00Z".to_string(),
            terms: json!({}),
            signature: None,
        }
    }

    fn stage_status(
        lifecycle: &JobProductionLifecycleV1,
        kind: JobProductionStageKindV1,
    ) -> JobProductionStageStatusV1 {
        lifecycle
            .stages
            .iter()
            .find(|stage| stage.stage == kind)
            .map(|stage| stage.status.clone())
            .unwrap()
    }

    fn test_temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn uuid_like() -> String {
        format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
}
