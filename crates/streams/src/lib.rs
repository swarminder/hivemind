use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{ExecutionResponseV1, StreamingEventType, StreamingEventV1, streaming_event};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StreamEventStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub stored: bool,
    #[serde(rename = "storedAt")]
    pub stored_at: String,
    pub keys: Vec<String>,
    #[serde(rename = "storageRefs")]
    pub storage_refs: Vec<String>,
    #[serde(rename = "eventCount")]
    pub event_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StreamEventAuditEntryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "streamKeys")]
    pub stream_keys: Vec<String>,
    #[serde(rename = "streamPaths")]
    pub stream_paths: Vec<String>,
    #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "eventCount")]
    pub event_count: usize,
    #[serde(
        rename = "firstEventAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub first_event_at: Option<String>,
    #[serde(
        rename = "firstOutputAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub first_output_at: Option<String>,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(
        rename = "timeToFirstOutputMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub time_to_first_output_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StreamEventAuditSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "streamCount")]
    pub stream_count: usize,
    #[serde(rename = "storedFileCount")]
    pub stored_file_count: usize,
    #[serde(rename = "eventCount")]
    pub event_count: usize,
    #[serde(rename = "withFirstOutputTimingCount")]
    pub with_first_output_timing_count: usize,
    #[serde(
        rename = "averageTimeToFirstOutputMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_time_to_first_output_ms: Option<f64>,
    #[serde(
        rename = "maxTimeToFirstOutputMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_time_to_first_output_ms: Option<u64>,
    pub streams: Vec<StreamEventAuditEntryV1>,
}

pub fn response_stream_events(
    response: &ExecutionResponseV1,
) -> Result<Option<Vec<StreamingEventV1>>> {
    let Some(events) = response.metadata.get("streamEvents") else {
        return Ok(None);
    };
    let events = serde_json::from_value(events.clone())
        .context("response streamEvents metadata is not a StreamingEventV1 array")?;
    Ok(Some(events))
}

pub fn stream_event_summary(events: &[StreamingEventV1], source: &str) -> Value {
    json!({
        "schemaVersion": "swarm-ai.stream-event-summary.v1",
        "requestId": events.first().map(|event| event.request_id.as_str()),
        "jobId": events.iter().find_map(|event| event.job_id.as_deref()),
        "eventCount": events.len(),
        "firstEventId": events.first().map(|event| event.event_id.clone()),
        "lastEventId": events.last().map(|event| event.event_id.clone()),
        "source": source
    })
}

pub fn stream_event_storage_keys(
    response: &ExecutionResponseV1,
    events: &[StreamingEventV1],
) -> Vec<String> {
    let mut keys = Vec::new();
    push_stream_event_key(
        &mut keys,
        json_path_str(&response.metadata, &["streamEventSummary", "jobId"]),
    );
    push_stream_event_key(
        &mut keys,
        json_path_str(&response.metadata, &["streamEventSummary", "requestId"]),
    );
    push_stream_event_key(&mut keys, Some(&response.request_id));
    for event in events {
        push_stream_event_key(&mut keys, event.job_id.as_deref());
        push_stream_event_key(&mut keys, Some(&event.request_id));
    }
    keys.sort();
    keys.dedup();
    keys
}

pub fn write_stream_events_for_keys(
    stream_event_dir: &Path,
    keys: &[String],
    events: &[StreamingEventV1],
) -> Result<StreamEventStoreSummaryV1> {
    fs::create_dir_all(stream_event_dir)
        .with_context(|| format!("failed to create {}", stream_event_dir.display()))?;
    let bytes = serde_json::to_vec_pretty(events)?;
    let mut storage_refs = Vec::with_capacity(keys.len());
    for key in keys {
        let path = stream_events_path(stream_event_dir, key);
        fs::write(&path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
        storage_refs.push(format!(
            "local://stream-events/{}",
            safe_record_component(key)
        ));
    }
    Ok(StreamEventStoreSummaryV1 {
        schema_version: "swarm-ai.stream-event-store.v1".to_string(),
        stored: true,
        stored_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        keys: keys.to_vec(),
        storage_refs,
        event_count: events.len(),
    })
}

pub fn read_stream_events(
    stream_event_dir: &Path,
    key: &str,
) -> Result<Option<Vec<StreamingEventV1>>> {
    let path = stream_events_path(stream_event_dir, key);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let events = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(events))
}

pub fn list_stream_event_audit(stream_event_dir: &Path) -> Result<StreamEventAuditSummaryV1> {
    let mut stored_file_count = 0;
    let mut streams = BTreeMap::<String, StreamEventAuditEntryV1>::new();
    if stream_event_dir.exists() {
        for entry in fs::read_dir(stream_event_dir)
            .with_context(|| format!("failed to list {}", stream_event_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                stored_file_count += 1;
                let bytes = fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let events: Vec<StreamingEventV1> = serde_json::from_slice(&bytes)
                    .with_context(|| format!("failed to parse {}", path.display()))?;
                let stream_key = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("stream")
                    .to_string();
                let fingerprint = stream_event_fingerprint(&events);
                streams
                    .entry(fingerprint)
                    .and_modify(|entry| {
                        push_unique(&mut entry.stream_keys, stream_key.clone());
                        push_unique(&mut entry.stream_paths, path.display().to_string());
                    })
                    .or_insert_with(|| {
                        stream_event_audit_entry(
                            vec![stream_key],
                            vec![path.display().to_string()],
                            &events,
                        )
                    });
            }
        }
    }

    let mut streams = streams.into_values().collect::<Vec<_>>();
    streams.sort_by(|left, right| {
        left.first_event_at
            .cmp(&right.first_event_at)
            .then(left.stream_keys.cmp(&right.stream_keys))
    });
    let first_output_values = streams
        .iter()
        .filter_map(|entry| entry.time_to_first_output_ms)
        .collect::<Vec<_>>();
    Ok(StreamEventAuditSummaryV1 {
        schema_version: "hivemind.stream-event-audit-summary.v1".to_string(),
        root: stream_event_dir.display().to_string(),
        stream_count: streams.len(),
        stored_file_count,
        event_count: streams.iter().map(|stream| stream.event_count).sum(),
        with_first_output_timing_count: first_output_values.len(),
        average_time_to_first_output_ms: average_u64(&first_output_values),
        max_time_to_first_output_ms: first_output_values.iter().copied().max(),
        streams,
    })
}

pub fn stream_events_path(stream_event_dir: &Path, key: &str) -> PathBuf {
    stream_event_dir.join(format!("{}.json", safe_record_component(key)))
}

pub fn append_job_cancellation_event(
    stream_event_dir: &Path,
    result: &mut hivemind_jobs::JobCancellationResultV1,
) -> Result<StreamEventStoreSummaryV1> {
    let record = &mut result.record;
    let mut events = read_stream_events(stream_event_dir, &record.job_id)?.unwrap_or_default();
    if events
        .iter()
        .any(|event| event.event_type == StreamingEventType::Cancelled)
    {
        return Ok(stream_store_summary_from_record(record, &events));
    }
    let cancellation = record
        .metadata
        .get("cancellation")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let timestamp = record
        .completed_at
        .clone()
        .unwrap_or_else(|| Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true));
    events.push(streaming_event(
        record.request_id.clone(),
        Some(record.job_id.clone()),
        events.len() as u64,
        StreamingEventType::Cancelled,
        timestamp,
        json!({
            "status": "cancelled",
            "source": "job-cancellation",
            "jobId": record.job_id,
            "requestId": record.request_id,
            "previousStatus": result.previous_status,
            "currentStatus": result.current_status,
            "cancellation": cancellation
        }),
    ));
    let keys = vec![record.job_id.clone(), record.request_id.clone()];
    let summary = write_stream_events_for_keys(stream_event_dir, &keys, &events)?;
    record.stream_event_count = Some(events.len() as u64);
    record.stream_ref = summary.storage_refs.first().cloned();
    if !record.metadata.is_object() {
        record.metadata = json!({});
    }
    record.metadata["streamEventStore"] = json!(&summary);
    Ok(summary)
}

pub fn streaming_events_sse_body(events: &[StreamingEventV1]) -> String {
    let mut body = String::new();
    for event in events {
        body.push_str("event: ");
        body.push_str(&streaming_event_sse_name(&event.event_type));
        body.push('\n');
        body.push_str("id: ");
        body.push_str(&event.event_id);
        body.push('\n');
        body.push_str("data: ");
        body.push_str(&serde_json::to_string(event).expect("streaming event should serialize"));
        body.push_str("\n\n");
    }
    body
}

pub fn streaming_event_sse_name(event_type: &StreamingEventType) -> String {
    serde_json::to_value(event_type)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "event".to_string())
}

fn stream_store_summary_from_record(
    record: &hivemind_jobs::JobRecordV1,
    events: &[StreamingEventV1],
) -> StreamEventStoreSummaryV1 {
    StreamEventStoreSummaryV1 {
        schema_version: "swarm-ai.stream-event-store.v1".to_string(),
        stored: true,
        stored_at: record.updated_at.clone(),
        keys: vec![record.job_id.clone(), record.request_id.clone()],
        storage_refs: record.stream_ref.clone().into_iter().collect(),
        event_count: events.len(),
    }
}

fn push_stream_event_key(keys: &mut Vec<String>, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };
    keys.push(value.to_string());
}

fn json_path_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

fn safe_record_component(value: &str) -> String {
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
        "record".to_string()
    } else {
        component
    }
}

fn stream_event_audit_entry(
    stream_keys: Vec<String>,
    stream_paths: Vec<String>,
    events: &[StreamingEventV1],
) -> StreamEventAuditEntryV1 {
    let ordered_events = ordered_events(events);
    let first_event = ordered_events.first().copied();
    let first_output = ordered_events
        .iter()
        .copied()
        .find(|event| is_first_output_event_type(&event.event_type));
    let completed = ordered_events
        .iter()
        .rev()
        .copied()
        .find(|event| is_terminal_event_type(&event.event_type));
    StreamEventAuditEntryV1 {
        schema_version: "hivemind.stream-event-audit-entry.v1".to_string(),
        stream_keys,
        stream_paths,
        request_id: first_event.map(|event| event.request_id.clone()),
        job_id: ordered_events
            .iter()
            .find_map(|event| event.job_id.as_ref().cloned()),
        event_count: events.len(),
        first_event_at: first_event.map(|event| event.timestamp.clone()),
        first_output_at: first_output.map(|event| event.timestamp.clone()),
        completed_at: completed.map(|event| event.timestamp.clone()),
        time_to_first_output_ms: first_event
            .zip(first_output)
            .and_then(|(start, output)| elapsed_ms(&start.timestamp, &output.timestamp)),
    }
}

fn ordered_events(events: &[StreamingEventV1]) -> Vec<&StreamingEventV1> {
    let mut events = events.iter().collect::<Vec<_>>();
    events.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then(left.timestamp.cmp(&right.timestamp))
            .then(left.event_id.cmp(&right.event_id))
    });
    events
}

fn is_first_output_event_type(event_type: &StreamingEventType) -> bool {
    matches!(
        event_type,
        StreamingEventType::TextDelta
            | StreamingEventType::TokenDelta
            | StreamingEventType::AudioChunk
            | StreamingEventType::ImageProgress
            | StreamingEventType::VideoFrame
            | StreamingEventType::EmbeddingProgress
            | StreamingEventType::ToolCallResult
    )
}

fn is_terminal_event_type(event_type: &StreamingEventType) -> bool {
    matches!(
        event_type,
        StreamingEventType::Completed | StreamingEventType::Error | StreamingEventType::Cancelled
    )
}

fn elapsed_ms(started_at: &str, completed_at: &str) -> Option<u64> {
    let started_at = DateTime::parse_from_rfc3339(started_at).ok()?;
    let completed_at = DateTime::parse_from_rfc3339(completed_at).ok()?;
    let elapsed_ms = completed_at
        .signed_duration_since(started_at)
        .num_milliseconds();
    u64::try_from(elapsed_ms).ok()
}

fn average_u64(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64)
    }
}

fn stream_event_fingerprint(events: &[StreamingEventV1]) -> String {
    let first_event_id = events
        .first()
        .map(|event| event.event_id.as_str())
        .unwrap_or("none");
    let last_event_id = events
        .last()
        .map(|event| event.event_id.as_str())
        .unwrap_or("none");
    format!("{}:{first_event_id}:{last_event_id}", events.len())
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
        values.sort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ApiSurface, ExecutionConstraintsV1, ExecutionOptions, IntegrityTier, JobOrderV1,
        JobPrivacyV1, OutputContractV1, RetryPolicyV1,
    };

    #[test]
    fn stream_store_round_trips_by_key() {
        let dir = test_temp_dir("hivemind-stream-store");
        let events = vec![streaming_event(
            "request-store-1",
            Some("job-store-1".to_string()),
            0,
            StreamingEventType::Started,
            "2026-06-02T00:00:00Z",
            json!({ "status": "started" }),
        )];

        let summary = write_stream_events_for_keys(
            &dir,
            &["job-store-1".to_string(), "request-store-1".to_string()],
            &events,
        )
        .unwrap();
        let by_job = read_stream_events(&dir, "job-store-1").unwrap().unwrap();
        let by_request = read_stream_events(&dir, "request-store-1")
            .unwrap()
            .unwrap();

        assert!(summary.stored);
        assert_eq!(summary.event_count, 1);
        assert_eq!(summary.storage_refs.len(), 2);
        assert_eq!(by_job[0].event_id, events[0].event_id);
        assert_eq!(by_request[0].event_id, events[0].event_id);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stream_event_audit_dedupes_keys_and_measures_first_output() {
        let dir = test_temp_dir("hivemind-stream-audit");
        let events = vec![
            streaming_event(
                "request-audit-1",
                Some("job-audit-1".to_string()),
                0,
                StreamingEventType::Started,
                "2026-06-05T00:00:00Z",
                json!({ "status": "started" }),
            ),
            streaming_event(
                "request-audit-1",
                Some("job-audit-1".to_string()),
                1,
                StreamingEventType::Heartbeat,
                "2026-06-05T00:00:00.004Z",
                json!({ "status": "running" }),
            ),
            streaming_event(
                "request-audit-1",
                Some("job-audit-1".to_string()),
                2,
                StreamingEventType::TokenDelta,
                "2026-06-05T00:00:00.024Z",
                json!({ "delta": "hello" }),
            ),
            streaming_event(
                "request-audit-1",
                Some("job-audit-1".to_string()),
                3,
                StreamingEventType::Completed,
                "2026-06-05T00:00:00.040Z",
                json!({ "status": "completed" }),
            ),
        ];
        write_stream_events_for_keys(
            &dir,
            &["job-audit-1".to_string(), "request-audit-1".to_string()],
            &events,
        )
        .unwrap();

        let summary = list_stream_event_audit(&dir).unwrap();

        assert_eq!(summary.stored_file_count, 2);
        assert_eq!(summary.stream_count, 1);
        assert_eq!(summary.event_count, 4);
        assert_eq!(summary.with_first_output_timing_count, 1);
        assert_eq!(summary.average_time_to_first_output_ms, Some(24.0));
        assert_eq!(summary.max_time_to_first_output_ms, Some(24));
        assert_eq!(
            summary.streams[0].stream_keys,
            vec!["job-audit-1".to_string(), "request-audit-1".to_string()]
        );
        assert_eq!(summary.streams[0].time_to_first_output_ms, Some(24));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cancellation_append_updates_record_and_store_metadata() {
        let dir = test_temp_dir("hivemind-stream-cancel");
        let order = job_order("job-cancel-stream-1", "request-cancel-stream-1");
        let record = hivemind_jobs::job_record_from_order(order.clone(), "2026-06-02T00:00:00Z");
        let request = hivemind_jobs::job_cancellation_request(&order.job_id, "local-dev", "stop");
        let job_dir = test_temp_dir("hivemind-stream-cancel-jobs");
        hivemind_jobs::upsert_job_record(&job_dir, record).unwrap();
        let mut result =
            hivemind_jobs::cancel_job_record(&job_dir, &request, "2026-06-02T00:00:01Z")
                .unwrap()
                .unwrap();

        let summary = append_job_cancellation_event(&dir, &mut result).unwrap();
        let events = read_stream_events(&dir, &order.job_id).unwrap().unwrap();

        assert!(summary.stored);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, StreamingEventType::Cancelled);
        assert_eq!(result.record.stream_event_count, Some(1));
        assert_eq!(result.record.metadata["streamEventStore"]["stored"], true);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&job_dir).ok();
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
