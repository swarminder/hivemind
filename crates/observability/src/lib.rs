use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{ValidationIssue, canonicalize_json, hash_canonical_json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_OPERATIONAL_SNAPSHOT_SIGNATURE_PREFIX: &str = "dev-operational-snapshot-signature-v1";
pub const OPERATIONAL_SNAPSHOT_SCHEMA_VERSION: &str = "hivemind.operational_metric_snapshot.v1";
pub const OPERATIONAL_SNAPSHOT_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.operational_metric_snapshot_request.v1";
pub const OPERATIONAL_SNAPSHOT_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.operational_metric_snapshot_verification.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalMetricSourceV1 {
    JobStore,
    ReceiptStore,
    PackageValidationAuditStore,
    RegistrySearchAuditStore,
    ValidationReportStore,
    StorageAuditStore,
    StreamStore,
    RouteAuditStore,
    MarketplaceAuditStore,
    MinerRecordStore,
    GovernanceStore,
    InstrumentationCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalMetricUnitV1 {
    Count,
    Ratio,
    Amount,
    Milliseconds,
    TokensPerSecond,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalMetricKindV1 {
    JobCount,
    ActiveJobCount,
    TerminalJobCount,
    FailedJobCount,
    CancelledJobCount,
    JobErrorRate,
    ReceiptLinkedJobCount,
    StreamLinkedJobCount,
    ValidationMissingJobCount,
    StaleJobCount,
    ReadyForSettlementJobCount,
    OperatorActionJobCount,
    BlockedLifecycleJobCount,
    ReceiptCount,
    ValidReceiptCount,
    InvalidReceiptCount,
    ReceiptInvalidRate,
    HashOnlyReceiptCount,
    EncryptedEvidenceReceiptCount,
    PublicEvidenceReceiptCount,
    ReceiptMissingJobContextCount,
    ReceiptReadyForSettlementCount,
    ReceiptDisputedCount,
    ReceiptRedactionRecommendedCount,
    ReceiptCurrencyTotal,
    ReceiptQueueTimeSampleCount,
    ReceiptQueueTimeAverageMs,
    ReceiptQueueTimeMaxMs,
    ReceiptPackageLoadTimeSampleCount,
    ReceiptPackageLoadTimeAverageMs,
    ReceiptPackageLoadTimeMaxMs,
    ReceiptCompletionLatencySampleCount,
    ReceiptCompletionLatencyAverageMs,
    ReceiptCompletionLatencyMaxMs,
    ReceiptThroughputSampleCount,
    ReceiptThroughputAverageOutputTokensPerSecond,
    ReceiptThroughputMaxOutputTokensPerSecond,
    PackageValidationCount,
    InvalidPackageValidationCount,
    ManifestParseLatencySampleCount,
    ManifestParseLatencyAverageMs,
    ManifestParseLatencyMaxMs,
    PackageValidationLatencySampleCount,
    PackageValidationLatencyAverageMs,
    PackageValidationLatencyMaxMs,
    RegistrySearchCount,
    RegistrySearchLatencySampleCount,
    RegistrySearchLatencyAverageMs,
    RegistrySearchLatencyMaxMs,
    RegistrySearchLocalCacheCount,
    RegistrySearchLocalCacheLatencyAverageMs,
    RegistrySearchLocalCacheLatencyMaxMs,
    RegistrySearchGatewayCount,
    RegistrySearchGatewayLatencyAverageMs,
    RegistrySearchGatewayLatencyMaxMs,
    RegistrySearchSwarmRetrievalCount,
    RegistrySearchSwarmRetrievalLatencyAverageMs,
    RegistrySearchSwarmRetrievalLatencyMaxMs,
    ValidationReportCount,
    InvalidValidationReportCount,
    ValidationLatencySampleCount,
    ValidationLatencyAverageMs,
    ValidationLatencyMaxMs,
    StorageTransferCount,
    StorageUploadCount,
    StorageDownloadCount,
    StorageTransferLatencySampleCount,
    StorageTransferLatencyAverageMs,
    StorageTransferLatencyMaxMs,
    StorageUploadLatencyAverageMs,
    StorageUploadLatencyMaxMs,
    StorageDownloadLatencyAverageMs,
    StorageDownloadLatencyMaxMs,
    StreamRecordCount,
    StreamStoredFileCount,
    StreamEventCount,
    TimeToFirstOutputSampleCount,
    TimeToFirstOutputAverageMs,
    TimeToFirstOutputMaxMs,
    RouteDecisionCount,
    RouteSelectedCount,
    RouteRejectedOnlyCount,
    RouteFallbackPlannedCount,
    RouteInvalidProofCount,
    RouteDecisionLatencySampleCount,
    RouteDecisionLatencyAverageMs,
    RouteDecisionLatencyMaxMs,
    RouteTraceCount,
    RouteFallbackTraceCount,
    RouteFailedTraceCount,
    QuoteCount,
    InvalidQuoteCount,
    QuoteResponseLatencySampleCount,
    QuoteResponseLatencyAverageMs,
    QuoteResponseLatencyMaxMs,
    QuoteCacheClaimSampleCount,
    QuoteCacheHitCount,
    QuoteCacheMissCount,
    QuoteCacheHitRate,
    SettlementLatencySampleCount,
    SettlementLatencyAverageMs,
    SettlementLatencyMaxMs,
    SettlementCount,
    InvalidSettlementCount,
    SettlementResolutionCount,
    InvalidSettlementResolutionCount,
    SettlementDisputedCount,
    SettlementRefundedCount,
    SettlementFailedCount,
    SettlementAmountTotal,
    MinerRecordCount,
    MinerHeartbeatCount,
    InvalidMinerRecordCount,
    MinerMemoryUsageSampleCount,
    MinerMemoryUsageAverageRatio,
    MinerMemoryUsageMaxRatio,
    MinerVramUsageSampleCount,
    MinerVramUsageAverageRatio,
    MinerVramUsageMaxRatio,
    GovernanceRecordCount,
    GovernancePolicyCount,
    SchemaReleaseCount,
    SecurityAdvisoryCount,
    CriticalSecurityAdvisoryCount,
    EmergencyActionGovernanceCount,
    ComponentReadinessCount,
    ProductionReadyComponentCount,
    BlockedComponentCount,
    RequiredMetricCoveredCount,
    RequiredMetricMissingCount,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricSampleV1 {
    pub kind: OperationalMetricKindV1,
    pub source: OperationalMetricSourceV1,
    pub value: f64,
    pub unit: OperationalMetricUnitV1,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricCoverageV1 {
    pub name: String,
    pub covered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<OperationalMetricSourceV1>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalSnapshotSourcesV1 {
    #[serde(rename = "jobRoot", default, skip_serializing_if = "Option::is_none")]
    pub job_root: Option<String>,
    #[serde(
        rename = "receiptRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receipt_root: Option<String>,
    #[serde(
        rename = "packageValidationAuditRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_validation_audit_root: Option<String>,
    #[serde(
        rename = "registrySearchAuditRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub registry_search_audit_root: Option<String>,
    #[serde(
        rename = "validationReportRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validation_report_root: Option<String>,
    #[serde(
        rename = "storageAuditRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub storage_audit_root: Option<String>,
    #[serde(
        rename = "streamRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_root: Option<String>,
    #[serde(
        rename = "routeAuditRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub route_audit_root: Option<String>,
    #[serde(
        rename = "marketplaceAuditRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub marketplace_audit_root: Option<String>,
    #[serde(rename = "minerRoot", default, skip_serializing_if = "Option::is_none")]
    pub miner_root: Option<String>,
    #[serde(
        rename = "governanceRoot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub governance_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricSnapshotRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(
        rename = "generatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub generated_at: Option<String>,
    #[serde(rename = "jobDir", default, skip_serializing_if = "Option::is_none")]
    pub job_dir: Option<PathBuf>,
    #[serde(
        rename = "receiptDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receipt_dir: Option<PathBuf>,
    #[serde(
        rename = "packageValidationAuditDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_validation_audit_dir: Option<PathBuf>,
    #[serde(
        rename = "registrySearchAuditDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub registry_search_audit_dir: Option<PathBuf>,
    #[serde(
        rename = "validationReportDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validation_report_dir: Option<PathBuf>,
    #[serde(
        rename = "storageAuditDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub storage_audit_dir: Option<PathBuf>,
    #[serde(rename = "streamDir", default, skip_serializing_if = "Option::is_none")]
    pub stream_dir: Option<PathBuf>,
    #[serde(
        rename = "routeAuditDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub route_audit_dir: Option<PathBuf>,
    #[serde(
        rename = "marketplaceAuditDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub marketplace_audit_dir: Option<PathBuf>,
    #[serde(rename = "minerDir", default, skip_serializing_if = "Option::is_none")]
    pub miner_dir: Option<PathBuf>,
    #[serde(
        rename = "governanceDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub governance_dir: Option<PathBuf>,
    #[serde(rename = "continueOnSourceError", default = "default_true")]
    pub continue_on_source_error: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricSnapshotV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "snapshotId")]
    pub snapshot_id: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    pub sources: OperationalSnapshotSourcesV1,
    pub samples: Vec<OperationalMetricSampleV1>,
    #[serde(rename = "requiredMetricCoverage")]
    pub required_metric_coverage: Vec<OperationalMetricCoverageV1>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricSnapshotVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "snapshotId")]
    pub snapshot_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "observedHash")]
    pub observed_hash: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricSnapshotIndexEntryV1 {
    #[serde(rename = "snapshotId")]
    pub snapshot_id: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(rename = "sampleCount")]
    pub sample_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    #[serde(rename = "coveredRequiredMetricCount")]
    pub covered_required_metric_count: usize,
    #[serde(rename = "missingRequiredMetricCount")]
    pub missing_required_metric_count: usize,
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
    #[serde(rename = "snapshotPath")]
    pub snapshot_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricSnapshotStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "snapshotCount")]
    pub snapshot_count: usize,
    #[serde(
        rename = "latestSnapshotId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub latest_snapshot_id: Option<String>,
    #[serde(rename = "validSignatureCount")]
    pub valid_signature_count: usize,
    #[serde(rename = "invalidSignatureCount")]
    pub invalid_signature_count: usize,
    pub snapshots: Vec<OperationalMetricSnapshotIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationalMetricSnapshotLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "snapshotId")]
    pub snapshot_id: String,
    #[serde(rename = "snapshotPath")]
    pub snapshot_path: String,
    pub snapshot: OperationalMetricSnapshotV1,
    pub verification: OperationalMetricSnapshotVerificationV1,
}

impl OperationalMetricSnapshotRequestV1 {
    pub fn local_stores(
        job_dir: impl Into<PathBuf>,
        receipt_dir: impl Into<PathBuf>,
        route_audit_dir: impl Into<PathBuf>,
        marketplace_audit_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            schema_version: OPERATIONAL_SNAPSHOT_REQUEST_SCHEMA_VERSION.to_string(),
            generated_at: None,
            job_dir: Some(job_dir.into()),
            receipt_dir: Some(receipt_dir.into()),
            package_validation_audit_dir: None,
            registry_search_audit_dir: None,
            validation_report_dir: None,
            storage_audit_dir: None,
            stream_dir: None,
            route_audit_dir: Some(route_audit_dir.into()),
            marketplace_audit_dir: Some(marketplace_audit_dir.into()),
            miner_dir: None,
            governance_dir: None,
            continue_on_source_error: true,
        }
    }
}

pub fn operational_snapshot_from_local_stores(
    request: &OperationalMetricSnapshotRequestV1,
) -> anyhow::Result<OperationalMetricSnapshotV1> {
    if request.schema_version != OPERATIONAL_SNAPSHOT_REQUEST_SCHEMA_VERSION {
        anyhow::bail!("operational snapshot request schemaVersion is not supported");
    }

    let generated_at = request.generated_at.clone().unwrap_or_else(now_timestamp);
    validate_timestamp_result(&generated_at, "$.generatedAt")?;
    let mut samples = Vec::new();
    let mut warnings = Vec::new();
    let sources = OperationalSnapshotSourcesV1 {
        job_root: request.job_dir.as_ref().map(path_string),
        receipt_root: request.receipt_dir.as_ref().map(path_string),
        package_validation_audit_root: request
            .package_validation_audit_dir
            .as_ref()
            .map(path_string),
        registry_search_audit_root: request.registry_search_audit_dir.as_ref().map(path_string),
        validation_report_root: request.validation_report_dir.as_ref().map(path_string),
        storage_audit_root: request.storage_audit_dir.as_ref().map(path_string),
        stream_root: request.stream_dir.as_ref().map(path_string),
        route_audit_root: request.route_audit_dir.as_ref().map(path_string),
        marketplace_audit_root: request.marketplace_audit_dir.as_ref().map(path_string),
        miner_root: request.miner_dir.as_ref().map(path_string),
        governance_root: request.governance_dir.as_ref().map(path_string),
    };

    if let Some(job_dir) = &request.job_dir {
        match job_metrics(job_dir, &generated_at) {
            Ok(mut job_samples) => samples.append(&mut job_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.jobRoot",
                format!("Could not read job store metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(receipt_dir) = &request.receipt_dir {
        match receipt_metrics(receipt_dir, &generated_at) {
            Ok(mut receipt_samples) => samples.append(&mut receipt_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.receiptRoot",
                format!("Could not read receipt audit metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(package_validation_audit_dir) = &request.package_validation_audit_dir {
        match package_validation_metrics(package_validation_audit_dir, &generated_at) {
            Ok(mut package_samples) => samples.append(&mut package_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.packageValidationAuditRoot",
                format!("Could not read package validation audit metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(registry_search_audit_dir) = &request.registry_search_audit_dir {
        match registry_search_metrics(registry_search_audit_dir, &generated_at) {
            Ok(mut registry_samples) => samples.append(&mut registry_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.registrySearchAuditRoot",
                format!("Could not read registry search audit metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(validation_report_dir) = &request.validation_report_dir {
        match validation_report_metrics(validation_report_dir, &generated_at) {
            Ok(mut validation_samples) => samples.append(&mut validation_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.validationReportRoot",
                format!("Could not read validation report metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(storage_audit_dir) = &request.storage_audit_dir {
        match storage_metrics(storage_audit_dir, &generated_at) {
            Ok(mut storage_samples) => samples.append(&mut storage_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.storageAuditRoot",
                format!("Could not read storage audit metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(stream_dir) = &request.stream_dir {
        match stream_metrics(stream_dir, &generated_at) {
            Ok(mut stream_samples) => samples.append(&mut stream_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.streamRoot",
                format!("Could not read stream event metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(route_audit_dir) = &request.route_audit_dir {
        match route_metrics(route_audit_dir, &generated_at) {
            Ok(mut route_samples) => samples.append(&mut route_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.routeAuditRoot",
                format!("Could not read route audit metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(marketplace_audit_dir) = &request.marketplace_audit_dir {
        match marketplace_metrics(marketplace_audit_dir, &generated_at) {
            Ok(mut marketplace_samples) => samples.append(&mut marketplace_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.marketplaceAuditRoot",
                format!("Could not read marketplace audit metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(miner_dir) = &request.miner_dir {
        match miner_metrics(miner_dir, &generated_at) {
            Ok(mut miner_samples) => samples.append(&mut miner_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.minerRoot",
                format!("Could not read miner record metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    if let Some(governance_dir) = &request.governance_dir {
        match governance_metrics(governance_dir, &generated_at) {
            Ok(mut governance_samples) => samples.append(&mut governance_samples),
            Err(error) if request.continue_on_source_error => warnings.push(issue(
                "$.sources.governanceRoot",
                format!("Could not read governance record metrics: {error}"),
            )),
            Err(error) => return Err(error),
        }
    }

    let coverage = required_metric_coverage(&samples);
    let covered = coverage.iter().filter(|metric| metric.covered).count();
    let missing = coverage.len().saturating_sub(covered);
    samples.push(sample(
        OperationalMetricKindV1::RequiredMetricCoveredCount,
        OperationalMetricSourceV1::InstrumentationCoverage,
        covered as f64,
        OperationalMetricUnitV1::Count,
        &generated_at,
        BTreeMap::new(),
    ));
    samples.push(sample(
        OperationalMetricKindV1::RequiredMetricMissingCount,
        OperationalMetricSourceV1::InstrumentationCoverage,
        missing as f64,
        OperationalMetricUnitV1::Count,
        &generated_at,
        BTreeMap::new(),
    ));
    warnings.extend(
        coverage
            .iter()
            .filter(|metric| !metric.covered)
            .map(|metric| {
                issue(
                    "$.requiredMetricCoverage",
                    format!("{} is not yet directly instrumented", metric.name),
                )
            }),
    );

    let mut snapshot = OperationalMetricSnapshotV1 {
        schema_version: OPERATIONAL_SNAPSHOT_SCHEMA_VERSION.to_string(),
        snapshot_id: String::new(),
        generated_at,
        sources,
        samples,
        required_metric_coverage: coverage,
        warnings,
        signature: None,
    };
    sign_operational_snapshot(&mut snapshot);
    Ok(snapshot)
}

pub fn sign_operational_snapshot(snapshot: &mut OperationalMetricSnapshotV1) {
    snapshot.snapshot_id = canonical_operational_snapshot_id(snapshot);
    snapshot.signature = Some(expected_operational_snapshot_signature(snapshot));
}

pub fn expected_operational_snapshot_signature(snapshot: &OperationalMetricSnapshotV1) -> String {
    format!(
        "{DEV_OPERATIONAL_SNAPSHOT_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&operational_snapshot_signing_value(
            snapshot
        )))
    )
}

pub fn canonical_operational_snapshot_id(snapshot: &OperationalMetricSnapshotV1) -> String {
    stable_id(
        "ops-snapshot",
        &operational_snapshot_signing_value(snapshot),
    )
}

pub fn verify_operational_snapshot(
    snapshot: &OperationalMetricSnapshotV1,
) -> OperationalMetricSnapshotVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if snapshot.schema_version != OPERATIONAL_SNAPSHOT_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {OPERATIONAL_SNAPSHOT_SCHEMA_VERSION}"),
        ));
    }
    if snapshot.snapshot_id.trim().is_empty() {
        issues.push(issue("$.snapshotId", "Snapshot id is required"));
    } else {
        let canonical_id = canonical_operational_snapshot_id(snapshot);
        if snapshot.snapshot_id != canonical_id {
            issues.push(issue(
                "$.snapshotId",
                "Snapshot id does not match canonical operational snapshot content",
            ));
        }
    }
    validate_timestamp(&snapshot.generated_at, "$.generatedAt", &mut issues);
    if snapshot.samples.is_empty() {
        warnings.push(issue(
            "$.samples",
            "Operational snapshot has no metric samples",
        ));
    }
    for (index, sample) in snapshot.samples.iter().enumerate() {
        if !sample.value.is_finite() {
            issues.push(issue(
                format!("$.samples[{index}].value"),
                "Metric sample value must be finite",
            ));
        }
        validate_timestamp(
            &sample.observed_at,
            &format!("$.samples[{index}].observedAt"),
            &mut issues,
        );
    }

    let expected_signature = Some(expected_operational_snapshot_signature(snapshot));
    if let Some(signature) = snapshot.signature.as_deref() {
        if Some(signature) != expected_signature.as_deref() {
            issues.push(issue(
                "$.signature",
                "Snapshot signature does not match canonical local-dev signature",
            ));
        }
    } else {
        warnings.push(issue(
            "$.signature",
            "Operational snapshot is unsigned; use only as local development evidence",
        ));
    }

    let observed_hash = hash_canonical_json(&canonicalize_json(
        &operational_snapshot_signing_value(snapshot),
    ));
    OperationalMetricSnapshotVerificationV1 {
        schema_version: OPERATIONAL_SNAPSHOT_VERIFICATION_SCHEMA_VERSION.to_string(),
        snapshot_id: snapshot.snapshot_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        observed_hash,
        verified_at: now_timestamp(),
    }
}

pub fn write_operational_snapshot(
    snapshot_dir: &Path,
    snapshot: &OperationalMetricSnapshotV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(snapshot_dir)?;
    let path = operational_snapshot_path(snapshot_dir, &snapshot.snapshot_id);
    fs::write(&path, serde_json::to_vec_pretty(snapshot)?)?;
    Ok(path)
}

pub fn list_operational_snapshots(
    snapshot_dir: &Path,
) -> anyhow::Result<OperationalMetricSnapshotStoreSummaryV1> {
    let mut snapshots = Vec::new();
    if snapshot_dir.exists() {
        for entry in fs::read_dir(snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let snapshot = read_operational_snapshot(&path)?;
                snapshots.push(operational_snapshot_index_entry(
                    &snapshot,
                    path.display().to_string(),
                ));
            }
        }
    }
    snapshots.sort_by(|left, right| {
        right
            .generated_at
            .cmp(&left.generated_at)
            .then(left.snapshot_id.cmp(&right.snapshot_id))
    });
    let valid_signature_count = snapshots
        .iter()
        .filter(|snapshot| snapshot.signature_verified)
        .count();
    Ok(OperationalMetricSnapshotStoreSummaryV1 {
        schema_version: "hivemind.operational_metric_snapshot_store_summary.v1".to_string(),
        root: snapshot_dir.display().to_string(),
        snapshot_count: snapshots.len(),
        latest_snapshot_id: snapshots
            .first()
            .map(|snapshot| snapshot.snapshot_id.clone()),
        valid_signature_count,
        invalid_signature_count: snapshots.len().saturating_sub(valid_signature_count),
        snapshots,
    })
}

pub fn get_operational_snapshot(
    snapshot_dir: &Path,
    snapshot_id: &str,
) -> anyhow::Result<Option<OperationalMetricSnapshotLookupV1>> {
    let direct_path = operational_snapshot_path(snapshot_dir, snapshot_id);
    if direct_path.exists() {
        let snapshot = read_operational_snapshot(&direct_path)?;
        return Ok(Some(operational_snapshot_lookup(snapshot, direct_path)));
    }
    if !snapshot_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let snapshot = read_operational_snapshot(&path)?;
            if snapshot.snapshot_id == snapshot_id {
                return Ok(Some(operational_snapshot_lookup(snapshot, path)));
            }
        }
    }
    Ok(None)
}

pub fn read_operational_snapshot(path: &Path) -> anyhow::Result<OperationalMetricSnapshotV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse operational snapshot JSON from {}: {error}",
            path.display()
        )
    })
}

fn job_metrics(
    job_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let request = hivemind_jobs::JobStoreAuditRequestV1 {
        schema_version: "swarm-ai.job-store-audit-request.v1".to_string(),
        observed_at: Some(observed_at.to_string()),
        metadata: Value::Object(Default::default()),
    };
    let audit = hivemind_jobs::audit_job_store(job_dir, &request)?;
    let lifecycle = hivemind_jobs::audit_job_production_lifecycles(job_dir, &request)?;
    let failed = audit.status_counts.get("failed").copied().unwrap_or(0);
    let cancelled = audit.status_counts.get("cancelled").copied().unwrap_or(0);
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::JobCount,
            OperationalMetricSourceV1::JobStore,
            audit.job_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ActiveJobCount,
            OperationalMetricSourceV1::JobStore,
            audit.active_job_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::TerminalJobCount,
            OperationalMetricSourceV1::JobStore,
            audit.terminal_job_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::FailedJobCount,
            OperationalMetricSourceV1::JobStore,
            failed,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::CancelledJobCount,
            OperationalMetricSourceV1::JobStore,
            cancelled,
            observed_at,
        ),
        ratio_sample(
            OperationalMetricKindV1::JobErrorRate,
            OperationalMetricSourceV1::JobStore,
            failed,
            audit.job_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptLinkedJobCount,
            OperationalMetricSourceV1::JobStore,
            audit.receipt_linked_job_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::StreamLinkedJobCount,
            OperationalMetricSourceV1::JobStore,
            audit.stream_linked_job_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ValidationMissingJobCount,
            OperationalMetricSourceV1::JobStore,
            audit.jobs_missing_required_validation_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::StaleJobCount,
            OperationalMetricSourceV1::JobStore,
            audit.stale_job_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReadyForSettlementJobCount,
            OperationalMetricSourceV1::JobStore,
            lifecycle.ready_for_settlement_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::OperatorActionJobCount,
            OperationalMetricSourceV1::JobStore,
            lifecycle.requires_operator_action_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::BlockedLifecycleJobCount,
            OperationalMetricSourceV1::JobStore,
            lifecycle.blocked_job_count,
            observed_at,
        ),
    ];
    append_status_samples(&mut samples, &audit.status_counts, observed_at);
    Ok(samples)
}

fn receipt_metrics(
    receipt_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let summary = hivemind_receipts::list_receipts(receipt_dir)?;
    let audit = hivemind_receipts::audit_receipt_store(&summary);
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::ReceiptCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.receipt_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ValidReceiptCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.valid_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::InvalidReceiptCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.invalid_count,
            observed_at,
        ),
        ratio_sample(
            OperationalMetricKindV1::ReceiptInvalidRate,
            OperationalMetricSourceV1::ReceiptStore,
            audit.invalid_count,
            audit.receipt_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::HashOnlyReceiptCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.hash_only_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::EncryptedEvidenceReceiptCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.encrypted_evidence_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::PublicEvidenceReceiptCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.public_evidence_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptMissingJobContextCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.missing_job_context_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptReadyForSettlementCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.ready_for_settlement_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptDisputedCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.disputed_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptRedactionRecommendedCount,
            OperationalMetricSourceV1::ReceiptStore,
            audit.redaction_recommended_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptQueueTimeSampleCount,
            OperationalMetricSourceV1::ReceiptStore,
            summary.with_timing_metric_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptPackageLoadTimeSampleCount,
            OperationalMetricSourceV1::ReceiptStore,
            summary.with_timing_metric_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptCompletionLatencySampleCount,
            OperationalMetricSourceV1::ReceiptStore,
            summary.with_timing_metric_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ReceiptThroughputSampleCount,
            OperationalMetricSourceV1::ReceiptStore,
            summary.throughput_sample_count,
            observed_at,
        ),
    ];
    if let Some(average) = summary.average_queue_ms {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptQueueTimeAverageMs,
            OperationalMetricSourceV1::ReceiptStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = summary.max_queue_ms {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptQueueTimeMaxMs,
            OperationalMetricSourceV1::ReceiptStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(average) = summary.average_load_ms {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptPackageLoadTimeAverageMs,
            OperationalMetricSourceV1::ReceiptStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = summary.max_load_ms {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptPackageLoadTimeMaxMs,
            OperationalMetricSourceV1::ReceiptStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(average) = summary.average_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptCompletionLatencyAverageMs,
            OperationalMetricSourceV1::ReceiptStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = summary.max_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptCompletionLatencyMaxMs,
            OperationalMetricSourceV1::ReceiptStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(average) = summary.average_output_tokens_per_second {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptThroughputAverageOutputTokensPerSecond,
            OperationalMetricSourceV1::ReceiptStore,
            average,
            OperationalMetricUnitV1::TokensPerSecond,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = summary.max_output_tokens_per_second {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptThroughputMaxOutputTokensPerSecond,
            OperationalMetricSourceV1::ReceiptStore,
            max,
            OperationalMetricUnitV1::TokensPerSecond,
            observed_at,
            BTreeMap::new(),
        ));
    }
    for total in audit.currency_totals {
        samples.push(sample(
            OperationalMetricKindV1::ReceiptCurrencyTotal,
            OperationalMetricSourceV1::ReceiptStore,
            total.estimated_cost,
            OperationalMetricUnitV1::Amount,
            observed_at,
            labels(&[("currency", total.currency)]),
        ));
    }
    Ok(samples)
}

fn package_validation_metrics(
    package_validation_audit_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let summary = hivemind_package::list_package_validation_audit(package_validation_audit_dir)?;
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::PackageValidationCount,
            OperationalMetricSourceV1::PackageValidationAuditStore,
            summary.validation_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::InvalidPackageValidationCount,
            OperationalMetricSourceV1::PackageValidationAuditStore,
            summary.invalid_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ManifestParseLatencySampleCount,
            OperationalMetricSourceV1::PackageValidationAuditStore,
            summary.manifest_parse_sample_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::PackageValidationLatencySampleCount,
            OperationalMetricSourceV1::PackageValidationAuditStore,
            summary.validation_sample_count,
            observed_at,
        ),
    ];
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::ManifestParseLatencyAverageMs,
        OperationalMetricSourceV1::PackageValidationAuditStore,
        summary.average_manifest_parse_elapsed_ms,
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::ManifestParseLatencyMaxMs,
        OperationalMetricSourceV1::PackageValidationAuditStore,
        summary
            .max_manifest_parse_elapsed_ms
            .map(|value| value as f64),
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::PackageValidationLatencyAverageMs,
        OperationalMetricSourceV1::PackageValidationAuditStore,
        summary.average_validation_elapsed_ms,
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::PackageValidationLatencyMaxMs,
        OperationalMetricSourceV1::PackageValidationAuditStore,
        summary.max_validation_elapsed_ms.map(|value| value as f64),
        observed_at,
    );
    Ok(samples)
}

fn registry_search_metrics(
    registry_search_audit_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let summary = hivemind_registry::list_registry_search_audit(registry_search_audit_dir)?;
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::RegistrySearchCount,
            OperationalMetricSourceV1::RegistrySearchAuditStore,
            summary.search_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RegistrySearchLatencySampleCount,
            OperationalMetricSourceV1::RegistrySearchAuditStore,
            summary.search_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RegistrySearchLocalCacheCount,
            OperationalMetricSourceV1::RegistrySearchAuditStore,
            summary.local_cache_search_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RegistrySearchGatewayCount,
            OperationalMetricSourceV1::RegistrySearchAuditStore,
            summary.gateway_search_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RegistrySearchSwarmRetrievalCount,
            OperationalMetricSourceV1::RegistrySearchAuditStore,
            summary.swarm_retrieval_search_count,
            observed_at,
        ),
    ];
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchLatencyAverageMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary.average_search_elapsed_ms,
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchLatencyMaxMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary.max_search_elapsed_ms.map(|value| value as f64),
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchLocalCacheLatencyAverageMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary.average_local_cache_search_elapsed_ms,
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchLocalCacheLatencyMaxMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary
            .max_local_cache_search_elapsed_ms
            .map(|value| value as f64),
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchGatewayLatencyAverageMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary.average_gateway_search_elapsed_ms,
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchGatewayLatencyMaxMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary
            .max_gateway_search_elapsed_ms
            .map(|value| value as f64),
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchSwarmRetrievalLatencyAverageMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary.average_swarm_retrieval_search_elapsed_ms,
        observed_at,
    );
    push_optional_ms(
        &mut samples,
        OperationalMetricKindV1::RegistrySearchSwarmRetrievalLatencyMaxMs,
        OperationalMetricSourceV1::RegistrySearchAuditStore,
        summary
            .max_swarm_retrieval_search_elapsed_ms
            .map(|value| value as f64),
        observed_at,
    );
    Ok(samples)
}

fn validation_report_metrics(
    validation_report_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let summary = hivemind_validator::list_validation_reports(validation_report_dir)?;
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::ValidationReportCount,
            OperationalMetricSourceV1::ValidationReportStore,
            summary.report_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::InvalidValidationReportCount,
            OperationalMetricSourceV1::ValidationReportStore,
            summary.invalid_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ValidationLatencySampleCount,
            OperationalMetricSourceV1::ValidationReportStore,
            summary.with_validation_elapsed_count,
            observed_at,
        ),
    ];
    if let Some(average) = summary.average_validation_elapsed_ms {
        samples.push(sample(
            OperationalMetricKindV1::ValidationLatencyAverageMs,
            OperationalMetricSourceV1::ValidationReportStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = summary.max_validation_elapsed_ms {
        samples.push(sample(
            OperationalMetricKindV1::ValidationLatencyMaxMs,
            OperationalMetricSourceV1::ValidationReportStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    Ok(samples)
}

fn storage_metrics(
    storage_audit_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let audit = hivemind_storage::list_storage_transfer_audit(storage_audit_dir)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::StorageTransferCount,
            OperationalMetricSourceV1::StorageAuditStore,
            audit.transfer_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::StorageUploadCount,
            OperationalMetricSourceV1::StorageAuditStore,
            audit.upload_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::StorageDownloadCount,
            OperationalMetricSourceV1::StorageAuditStore,
            audit.download_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::StorageTransferLatencySampleCount,
            OperationalMetricSourceV1::StorageAuditStore,
            audit.with_timing_metric_count,
            observed_at,
        ),
    ];
    if let Some(average) = audit.average_transfer_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::StorageTransferLatencyAverageMs,
            OperationalMetricSourceV1::StorageAuditStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = audit.max_transfer_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::StorageTransferLatencyMaxMs,
            OperationalMetricSourceV1::StorageAuditStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(average) = audit.average_upload_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::StorageUploadLatencyAverageMs,
            OperationalMetricSourceV1::StorageAuditStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = audit.max_upload_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::StorageUploadLatencyMaxMs,
            OperationalMetricSourceV1::StorageAuditStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(average) = audit.average_download_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::StorageDownloadLatencyAverageMs,
            OperationalMetricSourceV1::StorageAuditStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = audit.max_download_total_ms {
        samples.push(sample(
            OperationalMetricKindV1::StorageDownloadLatencyMaxMs,
            OperationalMetricSourceV1::StorageAuditStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    Ok(samples)
}

fn stream_metrics(
    stream_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let audit = hivemind_streams::list_stream_event_audit(stream_dir)?;
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::StreamRecordCount,
            OperationalMetricSourceV1::StreamStore,
            audit.stream_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::StreamStoredFileCount,
            OperationalMetricSourceV1::StreamStore,
            audit.stored_file_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::StreamEventCount,
            OperationalMetricSourceV1::StreamStore,
            audit.event_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::TimeToFirstOutputSampleCount,
            OperationalMetricSourceV1::StreamStore,
            audit.with_first_output_timing_count,
            observed_at,
        ),
    ];
    if let Some(average) = audit.average_time_to_first_output_ms {
        samples.push(sample(
            OperationalMetricKindV1::TimeToFirstOutputAverageMs,
            OperationalMetricSourceV1::StreamStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = audit.max_time_to_first_output_ms {
        samples.push(sample(
            OperationalMetricKindV1::TimeToFirstOutputMaxMs,
            OperationalMetricSourceV1::StreamStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    Ok(samples)
}

fn route_metrics(
    route_audit_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let decisions = hivemind_router::list_route_decisions(route_audit_dir)?;
    let traces = hivemind_router::list_route_execution_traces(route_audit_dir)?;
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::RouteDecisionCount,
            OperationalMetricSourceV1::RouteAuditStore,
            decisions.decision_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RouteSelectedCount,
            OperationalMetricSourceV1::RouteAuditStore,
            decisions.with_selected_route_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RouteRejectedOnlyCount,
            OperationalMetricSourceV1::RouteAuditStore,
            decisions.rejected_only_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RouteFallbackPlannedCount,
            OperationalMetricSourceV1::RouteAuditStore,
            decisions.fallback_planned_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RouteInvalidProofCount,
            OperationalMetricSourceV1::RouteAuditStore,
            decisions.invalid_proof_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RouteTraceCount,
            OperationalMetricSourceV1::RouteAuditStore,
            traces.trace_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RouteFallbackTraceCount,
            OperationalMetricSourceV1::RouteAuditStore,
            traces.fallback_trace_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::RouteFailedTraceCount,
            OperationalMetricSourceV1::RouteAuditStore,
            traces.failed_trace_count,
            observed_at,
        ),
    ];
    samples.push(count_sample(
        OperationalMetricKindV1::RouteDecisionLatencySampleCount,
        OperationalMetricSourceV1::RouteAuditStore,
        decisions.with_planning_timing_count,
        observed_at,
    ));
    if let Some(average) = decisions.average_planning_elapsed_ms {
        samples.push(sample(
            OperationalMetricKindV1::RouteDecisionLatencyAverageMs,
            OperationalMetricSourceV1::RouteAuditStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = decisions.max_planning_elapsed_ms {
        samples.push(sample(
            OperationalMetricKindV1::RouteDecisionLatencyMaxMs,
            OperationalMetricSourceV1::RouteAuditStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    Ok(samples)
}

fn marketplace_metrics(
    marketplace_audit_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let audit = hivemind_marketplace::list_marketplace_audit(marketplace_audit_dir)?;
    let disputed = audit
        .settlements
        .iter()
        .filter(|settlement| settlement.status == hivemind_marketplace::SettlementStatus::Disputed)
        .count();
    let refunded = audit
        .settlements
        .iter()
        .filter(|settlement| settlement.status == hivemind_marketplace::SettlementStatus::Refunded)
        .count();
    let failed = audit
        .settlements
        .iter()
        .filter(|settlement| settlement.status == hivemind_marketplace::SettlementStatus::Failed)
        .count();
    let quote_elapsed_values: Vec<u64> = audit
        .quotes
        .iter()
        .filter_map(|quote| quote.quote_elapsed_ms)
        .collect();
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::QuoteCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.quote_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::InvalidQuoteCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.invalid_quote_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::QuoteResponseLatencySampleCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            quote_elapsed_values.len(),
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::QuoteCacheClaimSampleCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.quote_cache_claim_sample_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::QuoteCacheHitCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.quote_cache_hit_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::QuoteCacheMissCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.quote_cache_miss_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::SettlementCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.settlement_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::InvalidSettlementCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.invalid_settlement_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::SettlementResolutionCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.resolution_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::InvalidSettlementResolutionCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            audit.invalid_resolution_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::SettlementDisputedCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            disputed,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::SettlementRefundedCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            refunded,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::SettlementFailedCount,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            failed,
            observed_at,
        ),
    ];
    if !quote_elapsed_values.is_empty() {
        let average = quote_elapsed_values
            .iter()
            .map(|value| *value as f64)
            .sum::<f64>()
            / quote_elapsed_values.len() as f64;
        samples.push(sample(
            OperationalMetricKindV1::QuoteResponseLatencyAverageMs,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = quote_elapsed_values.iter().copied().max() {
        samples.push(sample(
            OperationalMetricKindV1::QuoteResponseLatencyMaxMs,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(rate) = audit.quote_cache_hit_rate {
        samples.push(sample(
            OperationalMetricKindV1::QuoteCacheHitRate,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            rate,
            OperationalMetricUnitV1::Ratio,
            observed_at,
            BTreeMap::new(),
        ));
    }
    samples.push(count_sample(
        OperationalMetricKindV1::SettlementLatencySampleCount,
        OperationalMetricSourceV1::MarketplaceAuditStore,
        audit.settlement_latency_sample_count,
        observed_at,
    ));
    if let Some(average) = audit.average_quote_to_settlement_ms {
        samples.push(sample(
            OperationalMetricKindV1::SettlementLatencyAverageMs,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            average,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = audit.max_quote_to_settlement_ms {
        samples.push(sample(
            OperationalMetricKindV1::SettlementLatencyMaxMs,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            max as f64,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
    let mut totals = BTreeMap::<String, f64>::new();
    for settlement in &audit.settlements {
        *totals.entry(settlement.currency.clone()).or_default() += settlement.amount;
    }
    for (currency, amount) in totals {
        samples.push(sample(
            OperationalMetricKindV1::SettlementAmountTotal,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            amount,
            OperationalMetricUnitV1::Amount,
            observed_at,
            labels(&[("currency", currency)]),
        ));
    }
    Ok(samples)
}

fn miner_metrics(
    miner_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let summary = hivemind_miner::list_miner_records(miner_dir)?;
    let mut samples = vec![
        count_sample(
            OperationalMetricKindV1::MinerRecordCount,
            OperationalMetricSourceV1::MinerRecordStore,
            summary.record_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::MinerHeartbeatCount,
            OperationalMetricSourceV1::MinerRecordStore,
            summary.heartbeat_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::InvalidMinerRecordCount,
            OperationalMetricSourceV1::MinerRecordStore,
            summary.invalid_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::MinerMemoryUsageSampleCount,
            OperationalMetricSourceV1::MinerRecordStore,
            summary.memory_usage_sample_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::MinerVramUsageSampleCount,
            OperationalMetricSourceV1::MinerRecordStore,
            summary.vram_usage_sample_count,
            observed_at,
        ),
    ];
    if let Some(average) = summary.average_memory_usage_ratio {
        samples.push(sample(
            OperationalMetricKindV1::MinerMemoryUsageAverageRatio,
            OperationalMetricSourceV1::MinerRecordStore,
            average,
            OperationalMetricUnitV1::Ratio,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = summary.max_memory_usage_ratio {
        samples.push(sample(
            OperationalMetricKindV1::MinerMemoryUsageMaxRatio,
            OperationalMetricSourceV1::MinerRecordStore,
            max,
            OperationalMetricUnitV1::Ratio,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(average) = summary.average_vram_usage_ratio {
        samples.push(sample(
            OperationalMetricKindV1::MinerVramUsageAverageRatio,
            OperationalMetricSourceV1::MinerRecordStore,
            average,
            OperationalMetricUnitV1::Ratio,
            observed_at,
            BTreeMap::new(),
        ));
    }
    if let Some(max) = summary.max_vram_usage_ratio {
        samples.push(sample(
            OperationalMetricKindV1::MinerVramUsageMaxRatio,
            OperationalMetricSourceV1::MinerRecordStore,
            max,
            OperationalMetricUnitV1::Ratio,
            observed_at,
            BTreeMap::new(),
        ));
    }
    Ok(samples)
}

fn governance_metrics(
    governance_dir: &Path,
    observed_at: &str,
) -> anyhow::Result<Vec<OperationalMetricSampleV1>> {
    let summary = hivemind_governance::list_governance_records(governance_dir)?;
    Ok(vec![
        count_sample(
            OperationalMetricKindV1::GovernanceRecordCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.record_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::GovernancePolicyCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.policy_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::SchemaReleaseCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.schema_release_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::SecurityAdvisoryCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.security_advisory_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::CriticalSecurityAdvisoryCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.critical_advisory_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::EmergencyActionGovernanceCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.emergency_action_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ComponentReadinessCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.component_readiness_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::ProductionReadyComponentCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.production_ready_component_count,
            observed_at,
        ),
        count_sample(
            OperationalMetricKindV1::BlockedComponentCount,
            OperationalMetricSourceV1::GovernanceStore,
            summary.blocked_component_count,
            observed_at,
        ),
    ])
}

fn required_metric_coverage(
    samples: &[OperationalMetricSampleV1],
) -> Vec<OperationalMetricCoverageV1> {
    let has_error_rate = samples
        .iter()
        .any(|sample| sample.kind == OperationalMetricKindV1::JobErrorRate);
    let has_cost = samples.iter().any(|sample| {
        matches!(
            sample.kind,
            OperationalMetricKindV1::ReceiptCurrencyTotal
                | OperationalMetricKindV1::SettlementAmountTotal
        )
    });
    let has_storage_transfer_latency = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::StorageTransferLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::StorageTransferLatencyMaxMs
            || sample.kind == OperationalMetricKindV1::StorageUploadLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::StorageDownloadLatencyAverageMs
    });
    let has_manifest_parse_time = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::ManifestParseLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::ManifestParseLatencyMaxMs
    });
    let has_registry_search_latency = samples.iter().any(|sample| {
        matches!(
            sample.kind,
            OperationalMetricKindV1::RegistrySearchLatencyAverageMs
                | OperationalMetricKindV1::RegistrySearchLatencyMaxMs
                | OperationalMetricKindV1::RegistrySearchLocalCacheLatencyAverageMs
                | OperationalMetricKindV1::RegistrySearchGatewayLatencyAverageMs
                | OperationalMetricKindV1::RegistrySearchSwarmRetrievalLatencyAverageMs
        )
    });
    let has_route_decision_latency = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::RouteDecisionLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::RouteDecisionLatencyMaxMs
    });
    let has_quote_response_latency = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::QuoteResponseLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::QuoteResponseLatencyMaxMs
    });
    let has_settlement_latency = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::SettlementLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::SettlementLatencyMaxMs
    });
    let has_cache_hit_rate = samples
        .iter()
        .any(|sample| sample.kind == OperationalMetricKindV1::QuoteCacheHitRate);
    let has_queue_time = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::ReceiptQueueTimeAverageMs
            || sample.kind == OperationalMetricKindV1::ReceiptQueueTimeMaxMs
    });
    let has_time_to_first_output = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::TimeToFirstOutputAverageMs
            || sample.kind == OperationalMetricKindV1::TimeToFirstOutputMaxMs
    });
    let has_package_load_time = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::ReceiptPackageLoadTimeAverageMs
            || sample.kind == OperationalMetricKindV1::ReceiptPackageLoadTimeMaxMs
    });
    let has_completion_latency = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::ReceiptCompletionLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::ReceiptCompletionLatencyMaxMs
    });
    let has_validation_latency = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::ValidationLatencyAverageMs
            || sample.kind == OperationalMetricKindV1::ValidationLatencyMaxMs
    });
    let has_throughput = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::ReceiptThroughputAverageOutputTokensPerSecond
            || sample.kind == OperationalMetricKindV1::ReceiptThroughputMaxOutputTokensPerSecond
    });
    let has_memory_usage = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::MinerMemoryUsageAverageRatio
            || sample.kind == OperationalMetricKindV1::MinerMemoryUsageMaxRatio
    });
    let has_vram_usage = samples.iter().any(|sample| {
        sample.kind == OperationalMetricKindV1::MinerVramUsageAverageRatio
            || sample.kind == OperationalMetricKindV1::MinerVramUsageMaxRatio
    });
    let has_component_readiness_status = samples.iter().any(|sample| {
        matches!(
            sample.kind,
            OperationalMetricKindV1::ComponentReadinessCount
                | OperationalMetricKindV1::ProductionReadyComponentCount
                | OperationalMetricKindV1::BlockedComponentCount
        )
    });
    vec![
        coverage(
            "component-readiness-status",
            has_component_readiness_status,
            has_component_readiness_status.then_some(OperationalMetricSourceV1::GovernanceStore),
            "Derived from ComponentReadinessV1 records in the governance store.",
        ),
        coverage(
            "manifest-parse-time",
            has_manifest_parse_time,
            has_manifest_parse_time
                .then_some(OperationalMetricSourceV1::PackageValidationAuditStore),
            "Derived from manifestParseElapsedMs on package validation audit records.",
        ),
        coverage(
            "storage-upload-download-time",
            has_storage_transfer_latency,
            has_storage_transfer_latency.then_some(OperationalMetricSourceV1::StorageAuditStore),
            "Derived from totalMs on stored upload and download transfer audit records.",
        ),
        coverage(
            "registry-search-latency",
            has_registry_search_latency,
            has_registry_search_latency
                .then_some(OperationalMetricSourceV1::RegistrySearchAuditStore),
            "Derived from elapsedMs on registry search audit records, grouped by retrievalMode.",
        ),
        coverage(
            "route-decision-latency",
            has_route_decision_latency,
            has_route_decision_latency.then_some(OperationalMetricSourceV1::RouteAuditStore),
            "Derived from planningTiming.elapsedMs on stored route decision reports.",
        ),
        coverage(
            "quote-response-latency",
            has_quote_response_latency,
            has_quote_response_latency.then_some(OperationalMetricSourceV1::MarketplaceAuditStore),
            "Derived from quoteTiming.elapsedMs on stored marketplace service quotes.",
        ),
        coverage(
            "queue-time",
            has_queue_time,
            has_queue_time.then_some(OperationalMetricSourceV1::ReceiptStore),
            "Derived from metrics.queueMs on stored execution receipts.",
        ),
        coverage(
            "package-load-time",
            has_package_load_time,
            has_package_load_time.then_some(OperationalMetricSourceV1::ReceiptStore),
            "Derived from metrics.loadMs on stored execution receipts.",
        ),
        coverage(
            "time-to-first-output",
            has_time_to_first_output,
            has_time_to_first_output.then_some(OperationalMetricSourceV1::StreamStore),
            "Derived from the first persisted output streaming event relative to the first stream event.",
        ),
        coverage(
            "completion-latency",
            has_completion_latency,
            has_completion_latency.then_some(OperationalMetricSourceV1::ReceiptStore),
            "Derived from metrics.totalMs on stored execution receipts.",
        ),
        coverage(
            "throughput",
            has_throughput,
            has_throughput.then_some(OperationalMetricSourceV1::ReceiptStore),
            "Derived from metrics.outputTokens divided by metrics.totalMs on stored execution receipts.",
        ),
        coverage(
            "memory-usage",
            has_memory_usage,
            has_memory_usage.then_some(OperationalMetricSourceV1::MinerRecordStore),
            "Derived from latest valid miner heartbeats compared with signed miner profile RAM capacity.",
        ),
        coverage(
            "vram-usage",
            has_vram_usage,
            has_vram_usage.then_some(OperationalMetricSourceV1::MinerRecordStore),
            "Derived from latest valid miner heartbeats compared with signed miner profile VRAM capacity.",
        ),
        coverage(
            "cache-hit-rate",
            has_cache_hit_rate,
            has_cache_hit_rate.then_some(OperationalMetricSourceV1::MarketplaceAuditStore),
            "Derived from cacheHitClaim on valid stored marketplace service quotes.",
        ),
        coverage(
            "receipt-creation-latency",
            false,
            None,
            "Receipt creation is audited for validity, but creation latency is not emitted yet.",
        ),
        coverage(
            "validation-latency",
            has_validation_latency,
            has_validation_latency.then_some(OperationalMetricSourceV1::ValidationReportStore),
            "Derived from validationElapsedMs on stored validation reports.",
        ),
        coverage(
            "settlement-latency",
            has_settlement_latency,
            has_settlement_latency.then_some(OperationalMetricSourceV1::MarketplaceAuditStore),
            "Derived from quoteTiming.completedAt and occurredAt on stored marketplace settlement events.",
        ),
        coverage(
            "error-rate",
            has_error_rate,
            has_error_rate.then_some(OperationalMetricSourceV1::JobStore),
            "Derived from failed jobs divided by total jobs in the job audit store.",
        ),
        coverage(
            "cost-total",
            has_cost,
            has_cost.then_some(OperationalMetricSourceV1::ReceiptStore),
            "Derived from receipt and settlement currency totals when those audit stores contain cost data.",
        ),
    ]
}

fn operational_snapshot_index_entry(
    snapshot: &OperationalMetricSnapshotV1,
    snapshot_path: String,
) -> OperationalMetricSnapshotIndexEntryV1 {
    let verification = verify_operational_snapshot(snapshot);
    let covered_required_metric_count = snapshot
        .required_metric_coverage
        .iter()
        .filter(|metric| metric.covered)
        .count();
    OperationalMetricSnapshotIndexEntryV1 {
        snapshot_id: snapshot.snapshot_id.clone(),
        generated_at: snapshot.generated_at.clone(),
        sample_count: snapshot.samples.len(),
        warning_count: snapshot.warnings.len(),
        covered_required_metric_count,
        missing_required_metric_count: snapshot
            .required_metric_coverage
            .len()
            .saturating_sub(covered_required_metric_count),
        signature_verified: verification.valid,
        snapshot_path,
    }
}

fn operational_snapshot_lookup(
    snapshot: OperationalMetricSnapshotV1,
    path: PathBuf,
) -> OperationalMetricSnapshotLookupV1 {
    let verification = verify_operational_snapshot(&snapshot);
    OperationalMetricSnapshotLookupV1 {
        schema_version: "hivemind.operational_metric_snapshot_lookup.v1".to_string(),
        snapshot_id: snapshot.snapshot_id.clone(),
        snapshot_path: path.display().to_string(),
        snapshot,
        verification,
    }
}

fn operational_snapshot_path(snapshot_dir: &Path, snapshot_id: &str) -> PathBuf {
    snapshot_dir.join(format!("{snapshot_id}.json"))
}

fn append_status_samples(
    samples: &mut Vec<OperationalMetricSampleV1>,
    status_counts: &BTreeMap<String, usize>,
    observed_at: &str,
) {
    for (status, count) in status_counts {
        samples.push(sample(
            OperationalMetricKindV1::JobCount,
            OperationalMetricSourceV1::JobStore,
            *count as f64,
            OperationalMetricUnitV1::Count,
            observed_at,
            labels(&[("status", status.clone())]),
        ));
    }
}

fn count_sample(
    kind: OperationalMetricKindV1,
    source: OperationalMetricSourceV1,
    value: usize,
    observed_at: &str,
) -> OperationalMetricSampleV1 {
    sample(
        kind,
        source,
        value as f64,
        OperationalMetricUnitV1::Count,
        observed_at,
        BTreeMap::new(),
    )
}

fn push_optional_ms(
    samples: &mut Vec<OperationalMetricSampleV1>,
    kind: OperationalMetricKindV1,
    source: OperationalMetricSourceV1,
    value: Option<f64>,
    observed_at: &str,
) {
    if let Some(value) = value {
        samples.push(sample(
            kind,
            source,
            value,
            OperationalMetricUnitV1::Milliseconds,
            observed_at,
            BTreeMap::new(),
        ));
    }
}

fn ratio_sample(
    kind: OperationalMetricKindV1,
    source: OperationalMetricSourceV1,
    numerator: usize,
    denominator: usize,
    observed_at: &str,
) -> OperationalMetricSampleV1 {
    let value = if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    };
    sample(
        kind,
        source,
        value,
        OperationalMetricUnitV1::Ratio,
        observed_at,
        BTreeMap::new(),
    )
}

fn sample(
    kind: OperationalMetricKindV1,
    source: OperationalMetricSourceV1,
    value: f64,
    unit: OperationalMetricUnitV1,
    observed_at: &str,
    labels: BTreeMap<String, String>,
) -> OperationalMetricSampleV1 {
    OperationalMetricSampleV1 {
        kind,
        source,
        value,
        unit,
        observed_at: observed_at.to_string(),
        labels,
    }
}

fn coverage(
    name: impl Into<String>,
    covered: bool,
    source: Option<OperationalMetricSourceV1>,
    notes: impl Into<String>,
) -> OperationalMetricCoverageV1 {
    OperationalMetricCoverageV1 {
        name: name.into(),
        covered,
        source,
        notes: notes.into(),
    }
}

fn labels(values: &[(&str, String)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

fn operational_snapshot_signing_value(snapshot: &OperationalMetricSnapshotV1) -> Value {
    let mut value = serde_json::to_value(snapshot).expect("operational snapshot should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("snapshotId");
        object.remove("signature");
    }
    value
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("operational snapshot should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn validate_timestamp_result(timestamp: &str, path: &str) -> anyhow::Result<()> {
    if DateTime::parse_from_rfc3339(timestamp).is_err() {
        anyhow::bail!("{path} timestamp must be RFC3339");
    }
    Ok(())
}

fn validate_timestamp(timestamp: &str, path: &str, issues: &mut Vec<ValidationIssue>) {
    if DateTime::parse_from_rfc3339(timestamp).is_err() {
        issues.push(issue(path, "Timestamp must be RFC3339"));
    }
}

fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn path_string(path: &PathBuf) -> String {
    path.display().to_string()
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::receipt::AccessInfo;
    use hivemind_core::{
        ApiSurface, BillingInfo, CandidateRoute, ExecutionConstraintsV1, ExecutionMetrics,
        ExecutionReceiptV1, IntegrityTier, JobOrderV1, JobPrivacyV1, Modality, OutputContractV1,
        PolicyMode, PriceModel, PriceV1, PrivacyTier, ReceiptMode, RetryPolicyV1, RouteDecision,
        RouteEstimate, RoutePlanV1, RunnerType, StreamingEventType, StreamingEventV1,
        streaming_event,
    };

    #[test]
    fn operational_snapshot_derives_store_metrics_and_round_trips() {
        let root = unique_temp_dir("hivemind-observability-test");
        let job_dir = root.join("jobs");
        let receipt_dir = root.join("receipts");
        let package_validation_audit_dir = root.join("package-audit");
        let registry_search_audit_dir = root.join("registry-audit");
        let validation_report_dir = root.join("validations");
        let storage_audit_dir = root.join("storage-audit");
        let stream_dir = root.join("streams");
        let route_dir = root.join("routes");
        let marketplace_dir = root.join("marketplace");
        let miner_dir = root.join("miner");
        let governance_dir = root.join("governance");
        let snapshot_dir = root.join("snapshots");

        let order = sample_job_order("job-1", "request-1");
        let mut record =
            hivemind_jobs::job_record_from_order(order, "2026-06-05T00:00:00Z".to_string());
        record.status = hivemind_jobs::JobRecordStatusV1::Failed;
        hivemind_jobs::write_job_record(&job_dir, &record).unwrap();
        let receipt = sample_receipt();
        hivemind_receipts::write_receipt(&receipt_dir, &receipt).unwrap();
        write_sample_package_validation_audit(&package_validation_audit_dir);
        let validation_report = sample_validation_report();
        hivemind_validator::write_validation_report(&validation_report_dir, &validation_report)
            .unwrap();
        write_sample_registry_search_audit(&registry_search_audit_dir);
        for record in sample_storage_transfer_records() {
            hivemind_storage::write_storage_transfer_audit_record(&storage_audit_dir, &record)
                .unwrap();
        }
        let stream_events = sample_stream_events();
        hivemind_streams::write_stream_events_for_keys(
            &stream_dir,
            &["job-stream-1".to_string(), "request-stream-1".to_string()],
            &stream_events,
        )
        .unwrap();
        let route_report = sample_route_report();
        hivemind_router::write_route_decision(&route_dir, &route_report).unwrap();
        let service_quote = sample_service_quote();
        let settlement = sample_settlement(&service_quote);
        hivemind_marketplace::write_service_quote(&marketplace_dir, &service_quote).unwrap();
        hivemind_marketplace::write_settlement_event(&marketplace_dir, &settlement).unwrap();
        write_sample_miner_records(&miner_dir);
        write_sample_governance_records(&governance_dir);

        let request = OperationalMetricSnapshotRequestV1 {
            schema_version: OPERATIONAL_SNAPSHOT_REQUEST_SCHEMA_VERSION.to_string(),
            generated_at: Some("2026-06-05T00:01:00Z".to_string()),
            job_dir: Some(job_dir),
            receipt_dir: Some(receipt_dir),
            package_validation_audit_dir: Some(package_validation_audit_dir),
            registry_search_audit_dir: Some(registry_search_audit_dir),
            validation_report_dir: Some(validation_report_dir),
            storage_audit_dir: Some(storage_audit_dir),
            stream_dir: Some(stream_dir),
            route_audit_dir: Some(route_dir),
            marketplace_audit_dir: Some(marketplace_dir),
            miner_dir: Some(miner_dir),
            governance_dir: Some(governance_dir),
            continue_on_source_error: true,
        };
        let snapshot = operational_snapshot_from_local_stores(&request).unwrap();
        assert_eq!(snapshot.schema_version, OPERATIONAL_SNAPSHOT_SCHEMA_VERSION);
        assert!(snapshot.snapshot_id.starts_with("ops-snapshot-"));
        assert!(verify_operational_snapshot(&snapshot).valid);
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::JobCount,
            OperationalMetricSourceV1::JobStore,
            1.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::FailedJobCount,
            OperationalMetricSourceV1::JobStore,
            1.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::JobErrorRate,
            OperationalMetricSourceV1::JobStore,
            1.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ReceiptQueueTimeAverageMs,
            OperationalMetricSourceV1::ReceiptStore,
            2.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ReceiptPackageLoadTimeAverageMs,
            OperationalMetricSourceV1::ReceiptStore,
            3.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ReceiptCompletionLatencyAverageMs,
            OperationalMetricSourceV1::ReceiptStore,
            20.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ReceiptThroughputAverageOutputTokensPerSecond,
            OperationalMetricSourceV1::ReceiptStore,
            300.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ValidationLatencyAverageMs,
            OperationalMetricSourceV1::ValidationReportStore,
            17.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ManifestParseLatencyAverageMs,
            OperationalMetricSourceV1::PackageValidationAuditStore,
            5.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::PackageValidationLatencyAverageMs,
            OperationalMetricSourceV1::PackageValidationAuditStore,
            8.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::RegistrySearchLatencyAverageMs,
            OperationalMetricSourceV1::RegistrySearchAuditStore,
            9.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::RegistrySearchLocalCacheLatencyAverageMs,
            OperationalMetricSourceV1::RegistrySearchAuditStore,
            9.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::StorageTransferLatencyAverageMs,
            OperationalMetricSourceV1::StorageAuditStore,
            15.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::TimeToFirstOutputAverageMs,
            OperationalMetricSourceV1::StreamStore,
            15.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::RouteDecisionCount,
            OperationalMetricSourceV1::RouteAuditStore,
            1.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::RouteDecisionLatencyAverageMs,
            OperationalMetricSourceV1::RouteAuditStore,
            7.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::QuoteResponseLatencyAverageMs,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            11.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::QuoteCacheHitRate,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            0.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::SettlementLatencyAverageMs,
            OperationalMetricSourceV1::MarketplaceAuditStore,
            20.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::MinerMemoryUsageAverageRatio,
            OperationalMetricSourceV1::MinerRecordStore,
            0.5,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::MinerVramUsageAverageRatio,
            OperationalMetricSourceV1::MinerRecordStore,
            0.75,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ComponentReadinessCount,
            OperationalMetricSourceV1::GovernanceStore,
            1.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::ProductionReadyComponentCount,
            OperationalMetricSourceV1::GovernanceStore,
            1.0,
        );
        assert_metric(
            &snapshot,
            OperationalMetricKindV1::BlockedComponentCount,
            OperationalMetricSourceV1::GovernanceStore,
            0.0,
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "component-readiness-status" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "error-rate" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "storage-upload-download-time" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "manifest-parse-time" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "registry-search-latency" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "route-decision-latency" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "quote-response-latency" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "cache-hit-rate" && coverage.covered)
        );
        assert!(
            snapshot
                .required_metric_coverage
                .iter()
                .any(|coverage| coverage.name == "settlement-latency" && coverage.covered)
        );
        for metric_name in [
            "queue-time",
            "time-to-first-output",
            "package-load-time",
            "completion-latency",
            "validation-latency",
            "throughput",
            "memory-usage",
            "vram-usage",
        ] {
            assert!(
                snapshot
                    .required_metric_coverage
                    .iter()
                    .any(|coverage| coverage.name == metric_name && coverage.covered),
                "{metric_name} should be covered"
            );
        }

        let path = write_operational_snapshot(&snapshot_dir, &snapshot).unwrap();
        assert!(path.exists());
        let summary = list_operational_snapshots(&snapshot_dir).unwrap();
        assert_eq!(summary.snapshot_count, 1);
        assert_eq!(
            summary.latest_snapshot_id.as_deref(),
            Some(snapshot.snapshot_id.as_str())
        );
        assert_eq!(summary.valid_signature_count, 1);
        let lookup = get_operational_snapshot(&snapshot_dir, &snapshot.snapshot_id)
            .unwrap()
            .unwrap();
        assert!(lookup.verification.valid);
        assert_eq!(lookup.snapshot.snapshot_id, snapshot.snapshot_id);

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn operational_snapshot_verification_detects_tampering() {
        let request = OperationalMetricSnapshotRequestV1 {
            schema_version: OPERATIONAL_SNAPSHOT_REQUEST_SCHEMA_VERSION.to_string(),
            generated_at: Some("2026-06-05T00:01:00Z".to_string()),
            job_dir: None,
            receipt_dir: None,
            package_validation_audit_dir: None,
            registry_search_audit_dir: None,
            validation_report_dir: None,
            storage_audit_dir: None,
            route_audit_dir: None,
            marketplace_audit_dir: None,
            stream_dir: None,
            miner_dir: None,
            governance_dir: None,
            continue_on_source_error: true,
        };
        let mut snapshot = operational_snapshot_from_local_stores(&request).unwrap();
        assert!(verify_operational_snapshot(&snapshot).valid);
        snapshot.samples[0].value += 1.0;
        let verification = verify_operational_snapshot(&snapshot);
        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.snapshotId" || issue.path == "$.signature")
        );
    }

    fn assert_metric(
        snapshot: &OperationalMetricSnapshotV1,
        kind: OperationalMetricKindV1,
        source: OperationalMetricSourceV1,
        expected: f64,
    ) {
        let metric = snapshot
            .samples
            .iter()
            .find(|sample| sample.kind == kind && sample.source == source)
            .expect("metric should exist");
        assert!((metric.value - expected).abs() < f64::EPSILON);
    }

    fn sample_job_order(job_id: &str, request_id: &str) -> JobOrderV1 {
        JobOrderV1 {
            schema_version: "hivemind.job_order.v1".to_string(),
            job_id: job_id.to_string(),
            request_id: request_id.to_string(),
            requester: "tester".to_string(),
            package_ref: "bzz://package".to_string(),
            package_id: "package".to_string(),
            package_version: "0.1.0".to_string(),
            api_surface: hivemind_core::ApiSurface::HivemindNative,
            modalities: vec![Modality::Text],
            task: "chat".to_string(),
            input_hash: "input-hash".to_string(),
            preferred_artifact_group: None,
            output_contract: OutputContractV1 {
                task: "chat".to_string(),
                output_schema_ref: None,
            },
            constraints: ExecutionConstraintsV1 {
                stream: false,
                deadline_ms: Some(1_000),
                max_latency_ms: Some(1_000),
                deterministic: Some(true),
            },
            privacy: JobPrivacyV1 {
                privacy_tier: PrivacyTier::LocalOnly,
                receipt_mode: ReceiptMode::HashOnly,
                data_retention_rule: None,
                logging_rule: None,
            },
            required_verification_tier: IntegrityTier::ReceiptOnly,
            access_grant_ref: None,
            max_price: Some(PriceV1 {
                amount: 0.0,
                currency: "none".to_string(),
            }),
            validation_required: false,
            settlement_method: "local-dev".to_string(),
            retry_policy: RetryPolicyV1 {
                max_attempts: 1,
                retryable_error_codes: Vec::new(),
            },
            signature: None,
        }
    }

    fn sample_route_report() -> hivemind_router::RoutePlannerReportV1 {
        hivemind_router::RoutePlannerReportV1 {
            schema_version: "swarm-ai.route-planner-report.v1".to_string(),
            job_order: None,
            plan: RoutePlanV1 {
                schema_version: "swarm-ai.route-plan.v1".to_string(),
                request_id: "request-route-1".to_string(),
                package_ref: "bzz://package".to_string(),
                task: "chat".to_string(),
                candidate_routes: vec![CandidateRoute {
                    route_id: "local-local-dev".to_string(),
                    runner_type: RunnerType::Local,
                    runner_id: Some("local-dev".to_string()),
                    artifact_group: None,
                    estimated: RouteEstimate {
                        cost: 0.0,
                        currency: "none".to_string(),
                        queue_ms: 0,
                        first_token_ms: 1,
                        privacy: "local".to_string(),
                    },
                    quality_score: Some(1.0),
                    policy_decision: None,
                    decision: RouteDecision::Eligible,
                    reason: Some("eligible test route".to_string()),
                }],
                selected_route_id: Some("local-local-dev".to_string()),
                fallback_route_ids: Vec::new(),
                reason: "test route report".to_string(),
            },
            quotes: Vec::new(),
            marketplace_shortlist: None,
            runner_reputation: Vec::new(),
            miner_capacity: Vec::new(),
            trust_policy: None,
            policy_mode: PolicyMode::Balanced,
            planning_timing: Some(hivemind_router::RoutePlannerTimingV1 {
                schema_version: "swarm-ai.route-planner-timing.v1".to_string(),
                started_at: "2026-06-05T00:00:00Z".to_string(),
                completed_at: "2026-06-05T00:00:00.007Z".to_string(),
                elapsed_ms: 7,
                candidate_count: 1,
                eligible_candidate_count: 1,
            }),
        }
    }

    fn sample_receipt() -> ExecutionReceiptV1 {
        let mut receipt = ExecutionReceiptV1 {
            schema_version: "swarm-ai.receipt.v1".to_string(),
            receipt_id: String::new(),
            request_id: "request-receipt-1".to_string(),
            package_id: "hivemind/test".to_string(),
            package_ref: "bzz://package".to_string(),
            artifact_group: "local".to_string(),
            package_manifest_hash: "0".repeat(64),
            runner_id: "runner-receipt-1".to_string(),
            route_id: Some("local-local-dev".to_string()),
            input_hash: "a".repeat(64),
            output_hash: "b".repeat(64),
            privacy_mode: "hash-only".to_string(),
            started_at: "2026-06-05T00:00:00Z".to_string(),
            finished_at: "2026-06-05T00:00:00.020Z".to_string(),
            metrics: ExecutionMetrics {
                queue_ms: 2,
                load_ms: 3,
                compute_ms: 10,
                total_ms: 20,
                input_tokens: Some(4),
                output_tokens: Some(6),
            },
            billing: BillingInfo {
                estimated_cost: 0.01,
                currency: "xDAI".to_string(),
            },
            access: AccessInfo {
                license_grant_id: None,
            },
            policy: None,
            signature: String::new(),
        };
        hivemind_receipts::sign_receipt(&mut receipt);
        receipt.receipt_id = hivemind_receipts::canonical_receipt_id(&receipt).unwrap();
        receipt
    }

    fn sample_validation_report() -> hivemind_validator::ValidationReportV1 {
        let mut report = hivemind_validator::ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-observability-1".to_string(),
            runner_id: "runner-receipt-1".to_string(),
            package_ref: "bzz://package".to_string(),
            challenge_id: "challenge-observability-1".to_string(),
            receipt_id: "receipt-observability-1".to_string(),
            scores: hivemind_validator::ValidationScoresV1 {
                quality: 0.9,
                latency: 0.95,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.95,
            },
            evidence_refs: vec!["local://receipt/receipt-observability-1".to_string()],
            validation_elapsed_ms: Some(17),
            created_at: "2026-06-05T00:00:00Z".to_string(),
            signature: String::new(),
        };
        hivemind_validator::sign_validation_report(&mut report);
        report.report_id = hivemind_validator::canonical_validation_report_id(&report).unwrap();
        report
    }

    fn write_sample_package_validation_audit(package_validation_audit_dir: &Path) {
        let manifest = serde_json::json!({
            "schemaVersion": "swarm-ai.package.v1",
            "packageId": "hivemind/observability-package",
            "kind": "model",
            "name": "Observability Package",
            "version": "0.1.0",
            "publisher": {
                "address": "0x0000000000000000000000000000000000000000",
                "displayName": "Hivemind"
            },
            "capabilities": ["embedding"],
            "artifactGroups": [{
                "id": "local",
                "target": "local-mock",
                "engine": "rust-mock",
                "format": "json",
                "paths": ["model/config.json"],
                "totalBytes": 1,
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "minimum": {
                    "memoryMb": 1,
                    "webgpu": false
                }
            }],
            "inputSchema": { "type": "object" },
            "outputSchema": { "type": "object" },
            "permissions": [],
            "license": {
                "type": "open",
                "name": "Apache-2.0"
            }
        });
        let (report, mut record) =
            hivemind_package::validate_manifest_value_with_audit(&manifest, "test-inline");
        assert!(report.valid, "{:?}", report.issues);
        record.source_kind = hivemind_package::PackageValidationSourceKindV1::LocalDirectory;
        record.source = "examples/packages/observability".to_string();
        record.manifest_parse_elapsed_ms = Some(5);
        record.validation_elapsed_ms = 8;
        record.total_elapsed_ms = 13;
        record.recorded_at = "2026-06-05T00:00:00.000Z".to_string();
        record.validation_id =
            hivemind_package::canonical_package_validation_audit_record_id(&record);
        hivemind_package::write_package_validation_audit_record(
            package_validation_audit_dir,
            &record,
        )
        .unwrap();
    }

    fn write_sample_registry_search_audit(registry_search_audit_dir: &Path) {
        let query = hivemind_core::RegistryQueryV1 {
            schema_version: "swarm-ai.registry.query.v1".to_string(),
            kind: None,
            capability: Some("embedding".to_string()),
            modality: None,
            api_surface: None,
            publisher: None,
            target: None,
            engine: None,
            license_type: None,
            privacy_tier: None,
            verification_tier: None,
            max_artifact_bytes: None,
            min_artifact_bytes: None,
            browser_runnable: Some(true),
            gpu_required: None,
            min_validator_score: None,
            min_benchmark_score: None,
            max_price: None,
            page_size: 20,
            cursor: None,
            requester: None,
            requested_use: None,
            runner_id: None,
            access_grant: None,
            access_revocation_list: None,
        };
        let response = hivemind_core::RegistrySearchResponse {
            schema_version: "swarm-ai.registry.search.response.v1".to_string(),
            entries: Vec::new(),
            next_cursor: None,
            total_approx: 0,
        };
        let record = hivemind_registry::registry_search_audit_record(
            &query,
            &response,
            hivemind_registry::RegistrySearchRetrievalModeV1::LocalCache,
            3,
            9,
            "2026-06-05T00:00:00.000Z",
            "2026-06-05T00:00:00.009Z",
        );
        hivemind_registry::write_registry_search_audit_record(registry_search_audit_dir, &record)
            .unwrap();
    }

    fn write_sample_miner_records(miner_dir: &Path) {
        std::fs::create_dir_all(miner_dir).unwrap();
        let mut profile = hivemind_miner::MinerProfileV1 {
            schema_version: "swarm-ai.miner-profile.v1".to_string(),
            miner_id: String::new(),
            operator: "operator-observability-1".to_string(),
            runner_id: "runner-miner-1".to_string(),
            daemon_version: "0.1.0-test".to_string(),
            hardware: hivemind_marketplace::HardwareResourceV1 {
                gpu_vendor: Some("test".to_string()),
                gpu_model: Some("test-gpu".to_string()),
                gpu_count: 1,
                vram_gb: Some(16.0),
                cpu_cores: Some(8),
                ram_gb: 32.0,
                disk_gb: Some(256.0),
                network_mbps: Some(1000.0),
                driver_version: Some("test-driver".to_string()),
                runtime_versions: vec!["test-runtime".to_string()],
            },
            supported_execution_modes: vec![
                hivemind_marketplace::HardwareExecutionModeV1::PackageInference,
            ],
            supported_engines: vec!["test-engine".to_string()],
            supported_apis: vec![ApiSurface::HivemindNative],
            supported_modalities: vec![Modality::Chat],
            privacy_tiers: vec![PrivacyTier::Standard],
            verification_tiers: vec![IntegrityTier::ReceiptOnly],
            trust_tier: hivemind_marketplace::MinerTrustTierV1::Open,
            hardware_offer_id: "hardware-offer-observability-1".to_string(),
            terms_ref: "local://terms/miner-observability-1".to_string(),
            created_at: "2026-06-05T00:00:00Z".to_string(),
            signature: None,
        };
        hivemind_miner::sign_miner_profile(&mut profile);
        let mut heartbeat = hivemind_miner::miner_heartbeat_from_profile(
            &profile,
            hivemind_miner::MinerDaemonStatus::Busy,
            2,
            1,
            vec!["job-miner-1".to_string()],
            0.5,
        );
        heartbeat.observed_at = "2026-06-05T00:00:10Z".to_string();
        heartbeat.available_ram_gb = 16.0;
        heartbeat.available_vram_gb = Some(4.0);
        hivemind_miner::sign_miner_heartbeat(&mut heartbeat);

        std::fs::write(
            miner_dir.join("profile.json"),
            serde_json::to_vec_pretty(&profile).unwrap(),
        )
        .unwrap();
        std::fs::write(
            miner_dir.join("heartbeat.json"),
            serde_json::to_vec_pretty(&heartbeat).unwrap(),
        )
        .unwrap();
    }

    fn write_sample_governance_records(governance_dir: &Path) {
        std::fs::create_dir_all(governance_dir).unwrap();
        let readiness = hivemind_governance::create_component_readiness(
            hivemind_governance::ComponentReadinessInitOptionsV1 {
                schema_version:
                    hivemind_governance::COMPONENT_READINESS_INIT_OPTIONS_SCHEMA_VERSION.to_string(),
                component_name: "hivemind-observability".to_string(),
                component_type: "crate".to_string(),
                owner: "core-maintainers".to_string(),
                status: hivemind_governance::ComponentReadinessLevelV1::Production,
                implementation_ref: Some("local://crates/observability".to_string()),
                version: Some("0.1.0".to_string()),
                schema_refs: vec!["urn:schema:hivemind.operational_metric_snapshot.v1".to_string()],
                api_surfaces: vec!["operational-snapshot".to_string()],
                supported_environments: vec!["local-dev".to_string()],
                compatibility_certification_refs: vec!["local://compat/observability".to_string()],
                evidence_refs: vec!["local://tests/observability".to_string()],
                blockers: Vec::new(),
                limitations: vec!["local governance store only".to_string()],
                expires_at: None,
                metadata: serde_json::json!({}),
            },
        );
        std::fs::write(
            governance_dir.join("readiness.json"),
            serde_json::to_vec_pretty(&readiness).unwrap(),
        )
        .unwrap();
    }

    fn sample_storage_transfer_records() -> Vec<hivemind_storage::StorageTransferAuditRecordV1> {
        vec![
            hivemind_storage::storage_transfer_audit_record(
                "local",
                hivemind_storage::StorageTransferDirectionV1::Upload,
                "bzz://storage-upload",
                None,
                None,
                10,
                sample_storage_metrics(12, 10),
            ),
            hivemind_storage::storage_transfer_audit_record(
                "local",
                hivemind_storage::StorageTransferDirectionV1::Download,
                "bzz://storage-download",
                Some("receipt.json".to_string()),
                Some("application/json".to_string()),
                30,
                sample_storage_metrics(18, 30),
            ),
        ]
    }

    fn sample_storage_metrics(
        total_ms: u64,
        size_bytes: usize,
    ) -> hivemind_storage::StorageTransferMetricsV1 {
        hivemind_storage::StorageTransferMetricsV1 {
            schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
            resolve_ms: total_ms / 2,
            first_byte_ms: total_ms / 2,
            total_ms,
            size_bytes,
            retry_count: 0,
        }
    }

    fn sample_stream_events() -> Vec<StreamingEventV1> {
        vec![
            streaming_event(
                "request-stream-1",
                Some("job-stream-1".to_string()),
                0,
                StreamingEventType::Started,
                "2026-06-05T00:00:00Z",
                Value::Object(Default::default()),
            ),
            streaming_event(
                "request-stream-1",
                Some("job-stream-1".to_string()),
                1,
                StreamingEventType::Heartbeat,
                "2026-06-05T00:00:00.005Z",
                Value::Object(Default::default()),
            ),
            streaming_event(
                "request-stream-1",
                Some("job-stream-1".to_string()),
                2,
                StreamingEventType::TextDelta,
                "2026-06-05T00:00:00.015Z",
                serde_json::json!({ "delta": "hello" }),
            ),
            streaming_event(
                "request-stream-1",
                Some("job-stream-1".to_string()),
                3,
                StreamingEventType::Completed,
                "2026-06-05T00:00:00.022Z",
                Value::Object(Default::default()),
            ),
        ]
    }

    fn sample_service_quote() -> hivemind_marketplace::ServiceQuoteV1 {
        let mut quote = hivemind_marketplace::ServiceQuoteV1 {
            schema_version: hivemind_marketplace::SERVICE_QUOTE_SCHEMA_VERSION.to_string(),
            quote_id: String::new(),
            job_id: Some("job-quote-1".to_string()),
            request_id: "request-quote-1".to_string(),
            offer_id: "offer-quote-1".to_string(),
            listing_id: Some("offer-quote-1".to_string()),
            runner_id: "runner-quote-1".to_string(),
            package_ref: "bzz://package".to_string(),
            estimated_input_tokens: 1,
            estimated_output_tokens: 1,
            estimated_cost: 0.01,
            currency: "xDAI".to_string(),
            price: Some(PriceV1 {
                amount: 0.01,
                currency: "xDAI".to_string(),
            }),
            price_model: Some(PriceModel::PerToken),
            privacy_mode: Some(PrivacyTier::NoLog),
            verification_mode: Some(IntegrityTier::ReceiptOnly),
            estimated_start_delay_ms: Some(0),
            estimated_time_to_first_output_ms: Some(100),
            estimated_completion_ms: Some(111),
            cache_hit_claim: Some(false),
            validation_support: vec!["receipt".to_string()],
            settlement_model: hivemind_marketplace::SettlementModel::DirectPayPerCall,
            expires_at: (Utc::now() + chrono::Duration::minutes(5))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            terms: Value::Object(Default::default()),
            details: Value::Object(Default::default()),
            quote_timing: Some(hivemind_marketplace::ServiceQuoteTimingV1 {
                schema_version: "hivemind.quote_timing.v1".to_string(),
                started_at: "2026-06-05T00:00:00Z".to_string(),
                completed_at: "2026-06-05T00:00:00.011Z".to_string(),
                elapsed_ms: 11,
                offer_matched: true,
                privacy_matched: true,
                verification_matched: true,
            }),
            signature: None,
        };
        hivemind_marketplace::sign_service_quote(&mut quote);
        quote
    }

    fn sample_settlement(
        quote: &hivemind_marketplace::ServiceQuoteV1,
    ) -> hivemind_marketplace::SettlementEventV1 {
        let mut settlement = hivemind_marketplace::SettlementEventV1 {
            schema_version: hivemind_marketplace::SETTLEMENT_EVENT_SCHEMA_VERSION.to_string(),
            settlement_id: String::new(),
            job_id: quote.job_id.clone(),
            request_id: quote.request_id.clone(),
            receipt_id: "receipt-quote-1".to_string(),
            quote_id: Some(quote.quote_id.clone()),
            payment_authorization_id: None,
            payment_ref: None,
            package_ref: quote.package_ref.clone(),
            runner_id: quote.runner_id.clone(),
            payer: "0xUser".to_string(),
            payee: quote.runner_id.clone(),
            amount: quote.estimated_cost,
            currency: quote.currency.clone(),
            asset: Some(quote.currency.clone()),
            status: hivemind_marketplace::SettlementStatus::Settled,
            reason: Some("settled for observability fixture".to_string()),
            evidence_refs: vec!["bzz://receipt".to_string()],
            created_at: Some("2026-06-05T00:00:00.031Z".to_string()),
            occurred_at: "2026-06-05T00:00:00.031Z".to_string(),
            receipt_ref: Some("bzz://receipt".to_string()),
            signature: None,
        };
        hivemind_marketplace::sign_settlement_event(&mut settlement);
        settlement
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{}-{}",
            name,
            Utc::now()
                .timestamp_nanos_opt()
                .expect("timestamp should be representable")
        ))
    }
}
