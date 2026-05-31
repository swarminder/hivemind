use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use hivemind_benchmarks::{EvaluationResultV1, verify_evaluation_result};
use hivemind_core::{
    AccessControlV1, AccessDecision, AccessGrantV1, AccessRevocationListV1, LicensePolicyV1,
    LicenseType, RegistryBenchmarkScoreV1, RegistryEntryV1, RegistryQueryV1,
    RegistrySearchResponse, default_access_control_mode, default_allowed_uses, hash_canonical_json,
    license_requires_access_grant, registry::RegistryPackageRef,
};
use hivemind_package::{LocalPackage, load_package_from_dir};
use hivemind_publisher::{
    FeedPointerV1, FeedResolutionV1, PublicationRecordV1, PublicationVerificationV1,
    feed_ref as publisher_feed_ref, verify_feed_pointer, verify_publication_record,
};
use hivemind_validator::{ValidationReportV1, verify_validation_report};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const DEFAULT_REGISTRY_REQUESTED_USE: &str = "runner-service";
pub const REGISTRY_SHARD_MANIFEST_FILE: &str = "manifest.json";
pub const REGISTRY_LOCAL_PUBLISHED_AT: &str = "1970-01-01T00:00:00Z";

#[derive(Debug, Clone)]
pub struct IndexedPackage {
    pub package: LocalPackage,
    pub entry: RegistryEntryV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistrySnapshotV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub entries: Vec<RegistryEntryV1>,
    #[serde(rename = "publicationRecords")]
    pub publication_records: Vec<PublicationRecordV1>,
    #[serde(rename = "publicationStatuses", default)]
    pub publication_statuses: Vec<RegistryPublicationStatusV1>,
    #[serde(rename = "feedStatuses", default)]
    pub feed_statuses: Vec<RegistryFeedStatusV1>,
    #[serde(rename = "validationReports", default)]
    pub validation_reports: Vec<ValidationReportV1>,
    #[serde(rename = "evaluationResults", default)]
    pub evaluation_results: Vec<EvaluationResultV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryPackageLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRoot")]
    pub package_root: String,
    #[serde(rename = "localPackageRef")]
    pub local_package_ref: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    pub entry: RegistryEntryV1,
    pub manifest: hivemind_core::PackageManifestV1,
    #[serde(rename = "publicationRecords")]
    pub publication_records: Vec<PublicationRecordV1>,
    #[serde(rename = "publicationStatuses")]
    pub publication_statuses: Vec<RegistryPublicationStatusV1>,
    #[serde(rename = "feedStatuses")]
    pub feed_statuses: Vec<RegistryFeedStatusV1>,
    #[serde(rename = "validationReports")]
    pub validation_reports: Vec<ValidationReportV1>,
    #[serde(rename = "evaluationResults")]
    pub evaluation_results: Vec<EvaluationResultV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryPackageLookupRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId", default)]
    pub package_id: Option<String>,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(rename = "requestedUse", default)]
    pub requested_use: Option<String>,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "accessGrant", default)]
    pub access_grant: Option<AccessGrantV1>,
    #[serde(rename = "accessRevocationList", default)]
    pub access_revocation_list: Option<AccessRevocationListV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryPublicationStatusV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub valid: bool,
    pub verification: PublicationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryFeedStatusV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub channel: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub valid: bool,
    pub resolution: FeedResolutionV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "shardId")]
    pub shard_id: String,
    #[serde(rename = "shardKind")]
    pub shard_kind: String,
    #[serde(rename = "shardKey")]
    pub shard_key: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(rename = "entryCount")]
    pub entry_count: usize,
    pub entries: Vec<RegistryEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardFileV1 {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    #[serde(rename = "shardPath")]
    pub shard_path: String,
    #[serde(rename = "entryCount")]
    pub entry_count: usize,
    #[serde(rename = "shardHash")]
    pub shard_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(rename = "snapshotHash")]
    pub snapshot_hash: String,
    #[serde(rename = "entryCount")]
    pub entry_count: usize,
    #[serde(rename = "shardCount")]
    pub shard_count: usize,
    pub shards: Vec<RegistryShardFileV1>,
    #[serde(rename = "manifestHash", default)]
    pub manifest_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardWriteResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "shardDir")]
    pub shard_dir: String,
    #[serde(rename = "manifestPath")]
    pub manifest_path: String,
    #[serde(rename = "shardCount")]
    pub shard_count: usize,
    pub shards: Vec<RegistryShardFileV1>,
    pub manifest: RegistryShardManifestV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardVerificationIssueV1 {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardHashV1 {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    #[serde(rename = "shardHash")]
    pub shard_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    #[serde(rename = "shardSource")]
    pub shard_source: String,
    #[serde(rename = "expectedShardCount")]
    pub expected_shard_count: usize,
    #[serde(rename = "actualShardCount")]
    pub actual_shard_count: usize,
    #[serde(rename = "missingShardIds")]
    pub missing_shard_ids: Vec<String>,
    #[serde(rename = "unexpectedShardIds")]
    pub unexpected_shard_ids: Vec<String>,
    #[serde(rename = "mismatchedShardIds")]
    pub mismatched_shard_ids: Vec<String>,
    #[serde(rename = "expectedShardHashes")]
    pub expected_shard_hashes: Vec<RegistryShardHashV1>,
    #[serde(rename = "actualShardHashes")]
    pub actual_shard_hashes: Vec<RegistryShardHashV1>,
    pub issues: Vec<RegistryShardVerificationIssueV1>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardVerificationRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub shards: Vec<RegistryShardV1>,
    #[serde(rename = "shardSource", default)]
    pub shard_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardManifestVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    #[serde(rename = "shardSource")]
    pub shard_source: String,
    #[serde(rename = "expectedSnapshotHash")]
    pub expected_snapshot_hash: String,
    #[serde(rename = "actualSnapshotHash")]
    pub actual_snapshot_hash: String,
    #[serde(rename = "snapshotHashMatches")]
    pub snapshot_hash_matches: bool,
    #[serde(rename = "expectedManifestHash")]
    pub expected_manifest_hash: String,
    #[serde(rename = "actualManifestHash")]
    pub actual_manifest_hash: String,
    #[serde(rename = "declaredManifestHash")]
    pub declared_manifest_hash: String,
    #[serde(rename = "manifestHashMatches")]
    pub manifest_hash_matches: bool,
    #[serde(rename = "expectedEntryCount")]
    pub expected_entry_count: usize,
    #[serde(rename = "manifestEntryCount")]
    pub manifest_entry_count: usize,
    #[serde(rename = "expectedShardCount")]
    pub expected_shard_count: usize,
    #[serde(rename = "manifestShardCount")]
    pub manifest_shard_count: usize,
    #[serde(rename = "actualShardCount")]
    pub actual_shard_count: usize,
    #[serde(rename = "missingManifestShardIds")]
    pub missing_manifest_shard_ids: Vec<String>,
    #[serde(rename = "unexpectedManifestShardIds")]
    pub unexpected_manifest_shard_ids: Vec<String>,
    #[serde(rename = "missingShardIds")]
    pub missing_shard_ids: Vec<String>,
    #[serde(rename = "unexpectedShardIds")]
    pub unexpected_shard_ids: Vec<String>,
    #[serde(rename = "mismatchedShardIds")]
    pub mismatched_shard_ids: Vec<String>,
    pub issues: Vec<RegistryShardVerificationIssueV1>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardManifestVerificationRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub manifest: RegistryShardManifestV1,
    pub shards: Vec<RegistryShardV1>,
    #[serde(rename = "shardSource", default)]
    pub shard_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardManifestComparisonV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub matches: bool,
    #[serde(rename = "shardSource")]
    pub shard_source: String,
    #[serde(rename = "expectedSnapshotHash")]
    pub expected_snapshot_hash: String,
    #[serde(rename = "actualSnapshotHash")]
    pub actual_snapshot_hash: String,
    #[serde(rename = "snapshotHashMatches")]
    pub snapshot_hash_matches: bool,
    #[serde(rename = "expectedManifestHash")]
    pub expected_manifest_hash: String,
    #[serde(rename = "actualManifestHash")]
    pub actual_manifest_hash: String,
    #[serde(rename = "declaredManifestHash")]
    pub declared_manifest_hash: String,
    #[serde(rename = "manifestHashMatches")]
    pub manifest_hash_matches: bool,
    #[serde(rename = "expectedEntryCount")]
    pub expected_entry_count: usize,
    #[serde(rename = "manifestEntryCount")]
    pub manifest_entry_count: usize,
    #[serde(rename = "expectedShardCount")]
    pub expected_shard_count: usize,
    #[serde(rename = "manifestShardCount")]
    pub manifest_shard_count: usize,
    #[serde(rename = "missingShardIds")]
    pub missing_shard_ids: Vec<String>,
    #[serde(rename = "unexpectedShardIds")]
    pub unexpected_shard_ids: Vec<String>,
    #[serde(rename = "changedShardIds")]
    pub changed_shard_ids: Vec<String>,
    pub issues: Vec<RegistryShardVerificationIssueV1>,
    #[serde(rename = "comparedAt")]
    pub compared_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryShardManifestComparisonRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub manifest: RegistryShardManifestV1,
    #[serde(rename = "shardSource", default)]
    pub shard_source: Option<String>,
}

pub fn load_packages_from_dir(package_dir: &Path) -> Result<Vec<IndexedPackage>> {
    if !package_dir.exists() {
        return Ok(Vec::new());
    }

    let mut packages = Vec::new();
    for entry in fs::read_dir(package_dir)
        .with_context(|| format!("failed to read {}", package_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let candidate = entry.path();
            if candidate.join("swarm-ai.json").exists() {
                packages.push(index_package(load_package_from_dir(&candidate)?));
            }
        }
    }
    packages.sort_by(|left, right| {
        left.package
            .manifest
            .package_id
            .cmp(&right.package.manifest.package_id)
    });
    Ok(packages)
}

pub fn load_packages_with_publications(
    package_dir: &Path,
    record_dir: Option<&Path>,
) -> Result<Vec<IndexedPackage>> {
    load_packages_with_metadata(package_dir, record_dir, None)
}

pub fn load_packages_with_metadata(
    package_dir: &Path,
    record_dir: Option<&Path>,
    validation_dir: Option<&Path>,
) -> Result<Vec<IndexedPackage>> {
    load_packages_with_all_metadata(package_dir, record_dir, validation_dir, None)
}

pub fn load_packages_with_all_metadata(
    package_dir: &Path,
    record_dir: Option<&Path>,
    validation_dir: Option<&Path>,
    evaluation_dir: Option<&Path>,
) -> Result<Vec<IndexedPackage>> {
    load_packages_with_all_metadata_and_feeds(
        package_dir,
        record_dir,
        None,
        validation_dir,
        evaluation_dir,
    )
}

pub fn load_packages_with_all_metadata_and_feeds(
    package_dir: &Path,
    record_dir: Option<&Path>,
    feed_dir: Option<&Path>,
    validation_dir: Option<&Path>,
    evaluation_dir: Option<&Path>,
) -> Result<Vec<IndexedPackage>> {
    let records = if let Some(record_dir) = record_dir {
        load_publication_records(record_dir)?
    } else {
        Vec::new()
    };
    let feed_resolutions = if let Some(feed_dir) = feed_dir {
        load_feed_resolutions(feed_dir)?
    } else {
        Vec::new()
    };
    let publication_records = merge_publication_records(records, &feed_resolutions);
    let validation_reports = if let Some(validation_dir) = validation_dir {
        load_validation_reports(validation_dir)?
    } else {
        Vec::new()
    };
    let evaluation_results = if let Some(evaluation_dir) = evaluation_dir {
        load_evaluation_results(evaluation_dir)?
    } else {
        Vec::new()
    };
    let mut packages = load_packages_from_dir(package_dir)?;
    apply_publication_records(&mut packages, &publication_records);
    apply_validation_reports(&mut packages, &validation_reports);
    apply_evaluation_results(&mut packages, &evaluation_results);
    Ok(packages)
}

pub fn index_package(package: LocalPackage) -> IndexedPackage {
    let entry = RegistryEntryV1::from_manifest(
        &package.manifest,
        package.package_ref.clone(),
        package.manifest_hash.clone(),
        REGISTRY_LOCAL_PUBLISHED_AT,
    );
    IndexedPackage { package, entry }
}

pub fn load_publication_records(record_dir: &Path) -> Result<Vec<PublicationRecordV1>> {
    if !record_dir.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    for entry in fs::read_dir(record_dir)
        .with_context(|| format!("failed to read {}", record_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("json")
        {
            let bytes = fs::read(entry.path())?;
            let record = serde_json::from_slice::<PublicationRecordV1>(&bytes)?;
            records.push(record);
        }
    }
    records.sort_by(|left, right| {
        left.package_id
            .cmp(&right.package_id)
            .then(left.version.cmp(&right.version))
    });
    Ok(records)
}

pub fn load_feed_resolutions(feed_dir: &Path) -> Result<Vec<FeedResolutionV1>> {
    if !feed_dir.exists() {
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    collect_json_files(feed_dir, &mut paths)?;
    let mut resolutions = Vec::new();
    for path in paths {
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let pointer = serde_json::from_slice::<FeedPointerV1>(&bytes)
            .with_context(|| format!("failed to parse feed pointer {}", path.display()))?;
        resolutions.push(feed_resolution_from_pointer(pointer));
    }
    resolutions.sort_by(|left, right| {
        left.pointer
            .package_id
            .cmp(&right.pointer.package_id)
            .then(left.pointer.channel.cmp(&right.pointer.channel))
            .then(left.pointer.version.cmp(&right.pointer.version))
    });
    Ok(resolutions)
}

pub fn load_validation_reports(report_dir: &Path) -> Result<Vec<ValidationReportV1>> {
    if !report_dir.exists() {
        return Ok(Vec::new());
    }

    let mut reports = Vec::new();
    for entry in fs::read_dir(report_dir)
        .with_context(|| format!("failed to read {}", report_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("json")
        {
            let bytes = fs::read(entry.path())?;
            let report = serde_json::from_slice::<ValidationReportV1>(&bytes)?;
            reports.push(report);
        }
    }
    reports.sort_by(|left, right| {
        left.package_ref
            .cmp(&right.package_ref)
            .then(left.created_at.cmp(&right.created_at))
            .then(left.report_id.cmp(&right.report_id))
    });
    Ok(reports)
}

pub fn load_evaluation_results(result_dir: &Path) -> Result<Vec<EvaluationResultV1>> {
    if !result_dir.exists() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    for entry in fs::read_dir(result_dir)
        .with_context(|| format!("failed to read {}", result_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("json")
        {
            let bytes = fs::read(entry.path())?;
            let result = serde_json::from_slice::<EvaluationResultV1>(&bytes)?;
            results.push(result);
        }
    }
    results.sort_by(|left, right| {
        left.package_ref
            .cmp(&right.package_ref)
            .then(left.benchmark_id.cmp(&right.benchmark_id))
            .then(left.created_at.cmp(&right.created_at))
            .then(left.evaluation_id.cmp(&right.evaluation_id))
    });
    Ok(results)
}

pub fn apply_publication_records(packages: &mut [IndexedPackage], records: &[PublicationRecordV1]) {
    for package in packages {
        let matching: Vec<_> = records
            .iter()
            .filter(|record| {
                record.package_id == package.package.manifest.package_id
                    && record.version == package.package.manifest.version
                    && record.manifest_hash == package.package.manifest_hash
            })
            .collect();

        if matching.is_empty() {
            continue;
        }

        let mut package_refs = BTreeMap::<(String, String, String), RegistryPackageRef>::new();
        let mut signature_verified = false;
        for record in matching {
            let verification = verify_publication_record(record);
            signature_verified = signature_verified || verification.valid;
            for update in &record.channels_updated {
                match update.channel.as_str() {
                    "latest" => package.entry.latest_version = record.version.clone(),
                    "stable" => package.entry.stable_version = record.version.clone(),
                    _ => {}
                }
            }
            let key = (
                record.version.clone(),
                record.package_ref.clone(),
                record.manifest_hash.clone(),
            );
            let reference = RegistryPackageRef {
                version: record.version.clone(),
                package_ref: record.package_ref.clone(),
                manifest_hash: record.manifest_hash.clone(),
                published_at: record.published_at.clone(),
            };
            package_refs
                .entry(key)
                .and_modify(|existing| {
                    if existing.published_at < reference.published_at {
                        *existing = reference.clone();
                    }
                })
                .or_insert(reference);
        }
        package.entry.package_refs = package_refs.into_values().collect();
        package.entry.trust.signature_verified = signature_verified;
    }
}

pub fn apply_validation_reports(packages: &mut [IndexedPackage], reports: &[ValidationReportV1]) {
    for package in packages {
        let package_refs: Vec<_> = package
            .entry
            .package_refs
            .iter()
            .map(|reference| reference.package_ref.as_str())
            .chain(std::iter::once(package.package.package_ref.as_str()))
            .collect();
        let matching: Vec<_> = reports
            .iter()
            .filter(|report| verify_validation_report(report).valid)
            .filter(|report| {
                package_refs
                    .iter()
                    .any(|package_ref| *package_ref == report.package_ref)
            })
            .collect();

        if matching.is_empty() {
            continue;
        }

        let average = matching
            .iter()
            .map(|report| report.scores.overall)
            .sum::<f64>()
            / matching.len() as f64;
        package.entry.trust.validator_score = Some(round_score(average));
    }
}

pub fn apply_evaluation_results(packages: &mut [IndexedPackage], results: &[EvaluationResultV1]) {
    for package in packages {
        let package_refs: Vec<_> = package
            .entry
            .package_refs
            .iter()
            .map(|reference| reference.package_ref.as_str())
            .chain(std::iter::once(package.package.package_ref.as_str()))
            .collect();
        let mut matching: Vec<_> = results
            .iter()
            .filter(|result| verify_evaluation_result(result).valid)
            .filter(|result| {
                package_refs
                    .iter()
                    .any(|package_ref| *package_ref == result.package_ref)
            })
            .collect();

        if matching.is_empty() {
            continue;
        }

        matching.sort_by(|left, right| {
            left.benchmark_id
                .cmp(&right.benchmark_id)
                .then(left.created_at.cmp(&right.created_at))
                .then(left.evaluation_id.cmp(&right.evaluation_id))
        });

        let mut summaries = Vec::new();
        for result in matching {
            if let Some(position) =
                summaries
                    .iter()
                    .position(|summary: &RegistryBenchmarkScoreV1| {
                        summary.benchmark_id == result.benchmark_id
                    })
            {
                summaries[position] = benchmark_summary(result);
            } else {
                summaries.push(benchmark_summary(result));
            }
        }
        package.entry.benchmark_scores = summaries;
    }
}

pub fn rebuild_registry_snapshot(
    package_dir: &Path,
    record_dir: Option<&Path>,
) -> Result<RegistrySnapshotV1> {
    rebuild_registry_snapshot_with_validations(package_dir, record_dir, None)
}

pub fn rebuild_registry_snapshot_with_validations(
    package_dir: &Path,
    record_dir: Option<&Path>,
    validation_dir: Option<&Path>,
) -> Result<RegistrySnapshotV1> {
    rebuild_registry_snapshot_with_metadata(package_dir, record_dir, validation_dir, None)
}

pub fn rebuild_registry_snapshot_with_metadata(
    package_dir: &Path,
    record_dir: Option<&Path>,
    validation_dir: Option<&Path>,
    evaluation_dir: Option<&Path>,
) -> Result<RegistrySnapshotV1> {
    rebuild_registry_snapshot_with_all_sources(
        package_dir,
        record_dir,
        None,
        validation_dir,
        evaluation_dir,
    )
}

pub fn rebuild_registry_snapshot_with_all_sources(
    package_dir: &Path,
    record_dir: Option<&Path>,
    feed_dir: Option<&Path>,
    validation_dir: Option<&Path>,
    evaluation_dir: Option<&Path>,
) -> Result<RegistrySnapshotV1> {
    let records = if let Some(record_dir) = record_dir {
        load_publication_records(record_dir)?
    } else {
        Vec::new()
    };
    let feed_resolutions = if let Some(feed_dir) = feed_dir {
        load_feed_resolutions(feed_dir)?
    } else {
        Vec::new()
    };
    let publication_records = merge_publication_records(records, &feed_resolutions);
    let publication_statuses = publication_statuses(&publication_records);
    let feed_statuses = feed_statuses(&feed_resolutions);
    let validation_reports = if let Some(validation_dir) = validation_dir {
        load_validation_reports(validation_dir)?
    } else {
        Vec::new()
    };
    let evaluation_results = if let Some(evaluation_dir) = evaluation_dir {
        load_evaluation_results(evaluation_dir)?
    } else {
        Vec::new()
    };
    let mut packages = load_packages_from_dir(package_dir)?;
    apply_publication_records(&mut packages, &publication_records);
    apply_validation_reports(&mut packages, &validation_reports);
    apply_evaluation_results(&mut packages, &evaluation_results);
    let entries = packages.into_iter().map(|package| package.entry).collect();
    Ok(RegistrySnapshotV1 {
        schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
        entries,
        publication_records,
        publication_statuses,
        feed_statuses,
        validation_reports,
        evaluation_results,
    })
}

pub fn write_registry_snapshot(snapshot: &RegistrySnapshotV1, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serde_json::to_vec_pretty(snapshot)?)?;
    Ok(())
}

pub fn build_registry_shards(snapshot: &RegistrySnapshotV1) -> Vec<RegistryShardV1> {
    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut groups = BTreeMap::<(String, String), Vec<RegistryEntryV1>>::new();
    groups.insert(
        ("all".to_string(), "all".to_string()),
        snapshot.entries.clone(),
    );
    for entry in &snapshot.entries {
        push_shard_entry(
            &mut groups,
            "kind",
            &format!("{:?}", entry.kind).to_ascii_lowercase(),
            entry,
        );
        push_shard_entry(&mut groups, "publisher", &entry.publisher.address, entry);
        for capability in &entry.capabilities {
            push_shard_entry(&mut groups, "capability", capability, entry);
        }
        for target in &entry.targets {
            push_shard_entry(&mut groups, "target", target, entry);
        }
    }

    groups
        .into_iter()
        .map(|((shard_kind, shard_key), mut entries)| {
            entries.sort_by(|left, right| left.package_id.cmp(&right.package_id));
            entries.dedup_by(|left, right| left.package_id == right.package_id);
            RegistryShardV1 {
                schema_version: "swarm-ai.registry.shard.v1".to_string(),
                shard_id: shard_id(&shard_kind, &shard_key),
                shard_kind,
                shard_key,
                generated_at: generated_at.clone(),
                entry_count: entries.len(),
                entries,
            }
        })
        .collect()
}

pub fn write_registry_shards(
    snapshot: &RegistrySnapshotV1,
    shard_dir: &Path,
) -> Result<RegistryShardWriteResultV1> {
    fs::create_dir_all(shard_dir)?;
    let mut files = Vec::new();
    let shards = build_registry_shards(snapshot);
    for shard in &shards {
        let shard_hash = registry_shard_hash(&shard);
        let shard_filename = format!("{}.json", safe_file_component(&shard.shard_id));
        let path = shard_dir.join(&shard_filename);
        fs::write(&path, serde_json::to_vec_pretty(&shard)?)?;
        files.push(RegistryShardFileV1 {
            shard_id: shard.shard_id.clone(),
            shard_path: path.display().to_string(),
            entry_count: shard.entry_count,
            shard_hash: shard_hash.clone(),
        });
    }
    files.sort_by(|left, right| left.shard_id.cmp(&right.shard_id));
    let manifest = registry_shard_manifest_for_shards(snapshot, &shards);
    let manifest_path = shard_dir.join(REGISTRY_SHARD_MANIFEST_FILE);
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(RegistryShardWriteResultV1 {
        schema_version: "swarm-ai.registry.shard-write-result.v1".to_string(),
        shard_dir: shard_dir.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        shard_count: files.len(),
        shards: files,
        manifest,
    })
}

pub fn registry_shard_manifest_for_shards(
    snapshot: &RegistrySnapshotV1,
    shards: &[RegistryShardV1],
) -> RegistryShardManifestV1 {
    let files = registry_shard_file_entries(shards);
    registry_shard_manifest(snapshot, &files)
}

pub fn registry_shard_file_entries(shards: &[RegistryShardV1]) -> Vec<RegistryShardFileV1> {
    let mut files: Vec<_> = shards
        .iter()
        .map(|shard| RegistryShardFileV1 {
            shard_id: shard.shard_id.clone(),
            shard_path: format!("{}.json", safe_file_component(&shard.shard_id)),
            entry_count: shard.entry_count,
            shard_hash: registry_shard_hash(shard),
        })
        .collect();
    files.sort_by(|left, right| left.shard_id.cmp(&right.shard_id));
    files
}

pub fn registry_shard_manifest(
    snapshot: &RegistrySnapshotV1,
    shards: &[RegistryShardFileV1],
) -> RegistryShardManifestV1 {
    let mut shards = shards.to_vec();
    shards.sort_by(|left, right| left.shard_id.cmp(&right.shard_id));
    let mut manifest = RegistryShardManifestV1 {
        schema_version: "swarm-ai.registry.shard-manifest.v1".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        snapshot_hash: registry_snapshot_hash(snapshot),
        entry_count: snapshot.entries.len(),
        shard_count: shards.len(),
        shards,
        manifest_hash: String::new(),
    };
    manifest.manifest_hash = registry_shard_manifest_hash(&manifest);
    manifest
}

pub fn registry_snapshot_hash(snapshot: &RegistrySnapshotV1) -> String {
    let mut value = serde_json::to_value(snapshot).expect("registry snapshot should serialize");
    remove_volatile_registry_hash_fields(&mut value, &["verifiedAt"]);
    hash_canonical_json(&value)
}

pub fn read_registry_shard_manifest(path: &Path) -> Result<RegistryShardManifestV1> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse registry shard manifest {}", path.display()))
}

pub fn registry_shard_hash(shard: &RegistryShardV1) -> String {
    let mut value = serde_json::to_value(shard).expect("registry shard should serialize");
    if let Value::Object(map) = &mut value {
        map.remove("generatedAt");
    }
    hash_canonical_json(&value)
}

pub fn registry_shard_manifest_hash(manifest: &RegistryShardManifestV1) -> String {
    let mut value =
        serde_json::to_value(manifest).expect("registry shard manifest should serialize");
    if let Value::Object(map) = &mut value {
        map.remove("generatedAt");
        map.remove("manifestHash");
    }
    hash_canonical_json(&value)
}

fn remove_volatile_registry_hash_fields(value: &mut Value, field_names: &[&str]) {
    match value {
        Value::Object(map) => {
            for field_name in field_names {
                map.remove(*field_name);
            }
            for nested in map.values_mut() {
                remove_volatile_registry_hash_fields(nested, field_names);
            }
        }
        Value::Array(items) => {
            for item in items {
                remove_volatile_registry_hash_fields(item, field_names);
            }
        }
        _ => {}
    }
}

pub fn verify_registry_shards(
    snapshot: &RegistrySnapshotV1,
    shard_dir: &Path,
) -> Result<RegistryShardVerificationV1> {
    let actual = load_registry_shard_files(shard_dir)?;
    Ok(verify_registry_shard_map(
        snapshot,
        actual,
        shard_dir.display().to_string(),
    ))
}

pub fn verify_registry_shard_set(
    snapshot: &RegistrySnapshotV1,
    shards: Vec<RegistryShardV1>,
    shard_source: impl Into<String>,
) -> RegistryShardVerificationV1 {
    let actual = shards
        .into_iter()
        .map(|shard| (shard.shard_id.clone(), shard))
        .collect();
    verify_registry_shard_map(snapshot, actual, shard_source.into())
}

pub fn verify_registry_shard_manifest_dir(
    snapshot: &RegistrySnapshotV1,
    shard_dir: &Path,
) -> Result<RegistryShardManifestVerificationV1> {
    let manifest_path = shard_dir.join(REGISTRY_SHARD_MANIFEST_FILE);
    let manifest = read_registry_shard_manifest(&manifest_path)?;
    let actual = load_registry_shard_files(shard_dir)?;
    Ok(verify_registry_shard_manifest_map(
        snapshot,
        &manifest,
        actual,
        shard_dir.display().to_string(),
        Some(shard_dir),
    ))
}

pub fn verify_registry_shard_manifest_set(
    snapshot: &RegistrySnapshotV1,
    manifest: &RegistryShardManifestV1,
    shards: Vec<RegistryShardV1>,
    shard_source: impl Into<String>,
) -> RegistryShardManifestVerificationV1 {
    let actual = shards
        .into_iter()
        .map(|shard| (shard.shard_id.clone(), shard))
        .collect();
    verify_registry_shard_manifest_map(snapshot, manifest, actual, shard_source.into(), None)
}

pub fn compare_registry_shard_manifest_file(
    snapshot: &RegistrySnapshotV1,
    manifest_path: &Path,
) -> Result<RegistryShardManifestComparisonV1> {
    let manifest = read_registry_shard_manifest(manifest_path)?;
    Ok(compare_registry_shard_manifest(
        snapshot,
        &manifest,
        manifest_path.display().to_string(),
    ))
}

pub fn compare_registry_shard_manifest(
    snapshot: &RegistrySnapshotV1,
    manifest: &RegistryShardManifestV1,
    shard_source: impl Into<String>,
) -> RegistryShardManifestComparisonV1 {
    let expected_shards = build_registry_shards(snapshot);
    let expected_manifest = registry_shard_manifest_for_shards(snapshot, &expected_shards);
    compare_registry_shard_manifests(snapshot, &expected_manifest, manifest, shard_source.into())
}

fn compare_registry_shard_manifests(
    snapshot: &RegistrySnapshotV1,
    expected_manifest: &RegistryShardManifestV1,
    manifest: &RegistryShardManifestV1,
    shard_source: String,
) -> RegistryShardManifestComparisonV1 {
    let expected_snapshot_hash = registry_snapshot_hash(snapshot);
    let actual_snapshot_hash = manifest.snapshot_hash.clone();
    let snapshot_hash_matches = actual_snapshot_hash == expected_snapshot_hash;
    let expected_manifest_hash = expected_manifest.manifest_hash.clone();
    let actual_manifest_hash = registry_shard_manifest_hash(manifest);
    let declared_manifest_hash = manifest.manifest_hash.clone();
    let manifest_hash_matches = declared_manifest_hash == expected_manifest_hash
        && declared_manifest_hash == actual_manifest_hash;
    let expected_entries: BTreeMap<_, _> = expected_manifest
        .shards
        .iter()
        .map(|entry| (entry.shard_id.clone(), entry))
        .collect();
    let manifest_entries: BTreeMap<_, _> = manifest
        .shards
        .iter()
        .map(|entry| (entry.shard_id.clone(), entry))
        .collect();
    let mut missing_shard_ids: Vec<_> = expected_entries
        .keys()
        .filter(|shard_id| !manifest_entries.contains_key(*shard_id))
        .cloned()
        .collect();
    let mut unexpected_shard_ids: Vec<_> = manifest_entries
        .keys()
        .filter(|shard_id| !expected_entries.contains_key(*shard_id))
        .cloned()
        .collect();
    let mut changed_shard_ids = Vec::new();
    let mut issues = Vec::new();

    if manifest.schema_version != "swarm-ai.registry.shard-manifest.v1" {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest schemaVersion {} is not swarm-ai.registry.shard-manifest.v1",
                manifest.schema_version
            ),
        ));
    }
    if !snapshot_hash_matches {
        issues.push(shard_verification_issue(
            "manifest",
            "Manifest snapshotHash does not match the registry snapshot",
        ));
    }
    if declared_manifest_hash != actual_manifest_hash {
        issues.push(shard_verification_issue(
            "manifest",
            "Manifest manifestHash does not match the manifest content",
        ));
    }
    if actual_manifest_hash != expected_manifest_hash {
        issues.push(shard_verification_issue(
            "manifest",
            "Manifest content hash does not match the expected snapshot-derived manifest",
        ));
    }
    if manifest.entry_count != snapshot.entries.len() {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest entryCount {} does not match {} snapshot entries",
                manifest.entry_count,
                snapshot.entries.len()
            ),
        ));
    }
    if manifest.shard_count != manifest.shards.len() {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest shardCount {} does not match {} manifest shard entries",
                manifest.shard_count,
                manifest.shards.len()
            ),
        ));
    }
    if manifest.shard_count != expected_manifest.shard_count {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest shardCount {} does not match {} expected shards",
                manifest.shard_count, expected_manifest.shard_count
            ),
        ));
    }

    for shard_id in &missing_shard_ids {
        issues.push(shard_verification_issue(
            shard_id,
            "Manifest is missing the expected shard entry",
        ));
    }
    for shard_id in &unexpected_shard_ids {
        issues.push(shard_verification_issue(
            shard_id,
            "Manifest includes a shard entry that is not expected for the snapshot",
        ));
    }
    for (shard_id, manifest_entry) in &manifest_entries {
        if !registry_manifest_shard_path_is_portable(&manifest_entry.shard_path) {
            issues.push(shard_verification_issue(
                shard_id,
                format!(
                    "Manifest shardPath {} is not a portable relative path",
                    manifest_entry.shard_path
                ),
            ));
            changed_shard_ids.push(shard_id.clone());
        }
        if manifest_entry.shard_hash.len() != 64
            || !manifest_entry
                .shard_hash
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            issues.push(shard_verification_issue(
                shard_id,
                "Manifest shardHash is not a 64-character hex hash",
            ));
            changed_shard_ids.push(shard_id.clone());
        }
        if let Some(expected_entry) = expected_entries.get(shard_id)
            && *manifest_entry != *expected_entry
        {
            changed_shard_ids.push(shard_id.clone());
            issues.push(shard_verification_issue(
                shard_id,
                "Manifest shard entry differs from the expected snapshot-derived manifest",
            ));
        }
    }

    missing_shard_ids.sort();
    unexpected_shard_ids.sort();
    changed_shard_ids.sort();
    changed_shard_ids.dedup();
    issues.sort_by(|left, right| {
        left.shard_id
            .cmp(&right.shard_id)
            .then(left.message.cmp(&right.message))
    });
    issues.dedup();
    let matches = missing_shard_ids.is_empty()
        && unexpected_shard_ids.is_empty()
        && changed_shard_ids.is_empty()
        && issues.is_empty();

    RegistryShardManifestComparisonV1 {
        schema_version: "swarm-ai.registry.shard-manifest-comparison.v1".to_string(),
        matches,
        shard_source,
        expected_snapshot_hash,
        actual_snapshot_hash,
        snapshot_hash_matches,
        expected_manifest_hash,
        actual_manifest_hash,
        declared_manifest_hash,
        manifest_hash_matches,
        expected_entry_count: snapshot.entries.len(),
        manifest_entry_count: manifest.entry_count,
        expected_shard_count: expected_manifest.shard_count,
        manifest_shard_count: manifest.shard_count,
        missing_shard_ids,
        unexpected_shard_ids,
        changed_shard_ids,
        issues,
        compared_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn verify_registry_shard_manifest_map(
    snapshot: &RegistrySnapshotV1,
    manifest: &RegistryShardManifestV1,
    actual: BTreeMap<String, RegistryShardV1>,
    shard_source: String,
    shard_dir: Option<&Path>,
) -> RegistryShardManifestVerificationV1 {
    let expected_shards = build_registry_shards(snapshot);
    let expected_manifest = registry_shard_manifest_for_shards(snapshot, &expected_shards);
    let expected_manifest_hash = expected_manifest.manifest_hash.clone();
    let actual_manifest_hash = registry_shard_manifest_hash(manifest);
    let manifest_hash_matches = manifest.manifest_hash == expected_manifest_hash
        && manifest.manifest_hash == actual_manifest_hash;
    let expected: BTreeMap<_, _> = expected_shards
        .into_iter()
        .map(|shard| (shard.shard_id.clone(), shard))
        .collect();
    let mut manifest_entries = BTreeMap::<String, RegistryShardFileV1>::new();
    let mut missing_shard_ids = BTreeSet::<String>::new();
    let mut mismatched_shard_ids = BTreeSet::<String>::new();
    let mut issues = Vec::new();

    if manifest.schema_version != "swarm-ai.registry.shard-manifest.v1" {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest schemaVersion {} is not swarm-ai.registry.shard-manifest.v1",
                manifest.schema_version
            ),
        ));
    }
    if manifest.manifest_hash != actual_manifest_hash {
        issues.push(shard_verification_issue(
            "manifest",
            "Manifest manifestHash does not match the manifest content",
        ));
    }
    if actual_manifest_hash != expected_manifest_hash {
        issues.push(shard_verification_issue(
            "manifest",
            "Manifest content hash does not match the expected snapshot-derived manifest",
        ));
    }

    let expected_snapshot_hash = registry_snapshot_hash(snapshot);
    let snapshot_hash_matches = manifest.snapshot_hash == expected_snapshot_hash;
    if !snapshot_hash_matches {
        issues.push(shard_verification_issue(
            "manifest",
            "Manifest snapshotHash does not match the registry snapshot",
        ));
    }
    if manifest.entry_count != snapshot.entries.len() {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest entryCount {} does not match {} snapshot entries",
                manifest.entry_count,
                snapshot.entries.len()
            ),
        ));
    }
    if manifest.shard_count != manifest.shards.len() {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest shardCount {} does not match {} manifest shard entries",
                manifest.shard_count,
                manifest.shards.len()
            ),
        ));
    }
    if manifest.shard_count != expected.len() {
        issues.push(shard_verification_issue(
            "manifest",
            format!(
                "Manifest shardCount {} does not match {} expected shards",
                manifest.shard_count,
                expected.len()
            ),
        ));
    }

    for entry in &manifest.shards {
        if manifest_entries
            .insert(entry.shard_id.clone(), entry.clone())
            .is_some()
        {
            mismatched_shard_ids.insert(entry.shard_id.clone());
            issues.push(shard_verification_issue(
                &entry.shard_id,
                "Manifest contains duplicate shard entries",
            ));
        }
        if !registry_manifest_shard_path_is_portable(&entry.shard_path) {
            mismatched_shard_ids.insert(entry.shard_id.clone());
            issues.push(shard_verification_issue(
                &entry.shard_id,
                format!(
                    "Manifest shardPath {} is not a portable relative path",
                    entry.shard_path
                ),
            ));
        } else if let Some(shard_dir) = shard_dir
            && !shard_dir.join(&entry.shard_path).is_file()
        {
            missing_shard_ids.insert(entry.shard_id.clone());
            issues.push(shard_verification_issue(
                &entry.shard_id,
                format!("Manifest shardPath {} does not exist", entry.shard_path),
            ));
        }
        if entry.shard_hash.len() != 64
            || !entry
                .shard_hash
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            mismatched_shard_ids.insert(entry.shard_id.clone());
            issues.push(shard_verification_issue(
                &entry.shard_id,
                "Manifest shardHash is not a 64-character hex hash",
            ));
        }
    }

    let missing_manifest_shard_ids: BTreeSet<_> = expected
        .keys()
        .filter(|shard_id| !manifest_entries.contains_key(*shard_id))
        .cloned()
        .collect();
    let unexpected_manifest_shard_ids: BTreeSet<_> = manifest_entries
        .keys()
        .filter(|shard_id| !expected.contains_key(*shard_id))
        .cloned()
        .collect();
    let unexpected_shard_ids: BTreeSet<_> = actual
        .keys()
        .filter(|shard_id| !manifest_entries.contains_key(*shard_id))
        .cloned()
        .collect();

    for shard_id in manifest_entries.keys() {
        if !actual.contains_key(shard_id) {
            missing_shard_ids.insert(shard_id.clone());
        }
    }
    for shard_id in &missing_manifest_shard_ids {
        issues.push(shard_verification_issue(
            shard_id,
            "Manifest is missing the expected shard entry",
        ));
    }
    for shard_id in &unexpected_manifest_shard_ids {
        issues.push(shard_verification_issue(
            shard_id,
            "Manifest includes a shard entry that is not expected for the snapshot",
        ));
    }
    for shard_id in &missing_shard_ids {
        issues.push(shard_verification_issue(
            shard_id,
            "Manifest references a shard that is not present in the supplied shard set",
        ));
    }
    for shard_id in &unexpected_shard_ids {
        issues.push(shard_verification_issue(
            shard_id,
            "Supplied shard is not listed in the manifest",
        ));
    }

    for (shard_id, manifest_entry) in &manifest_entries {
        if let Some(expected_shard) = expected.get(shard_id) {
            let expected_hash = registry_shard_hash(expected_shard);
            if manifest_entry.entry_count != expected_shard.entry_count {
                mismatched_shard_ids.insert(shard_id.clone());
                issues.push(shard_verification_issue(
                    shard_id,
                    format!(
                        "Manifest entryCount {} does not match {} expected shard entries",
                        manifest_entry.entry_count, expected_shard.entry_count
                    ),
                ));
            }
            if manifest_entry.shard_hash != expected_hash {
                mismatched_shard_ids.insert(shard_id.clone());
                issues.push(shard_verification_issue(
                    shard_id,
                    "Manifest shardHash does not match the expected snapshot-derived shard",
                ));
            }
        }
        if let Some(actual_shard) = actual.get(shard_id) {
            let actual_hash = registry_shard_hash(actual_shard);
            if actual_shard.shard_id != *shard_id {
                mismatched_shard_ids.insert(shard_id.clone());
                issues.push(shard_verification_issue(
                    shard_id,
                    format!(
                        "Actual shard payload id {} does not match manifest shard id {}",
                        actual_shard.shard_id, shard_id
                    ),
                ));
            }
            if manifest_entry.entry_count != actual_shard.entry_count {
                mismatched_shard_ids.insert(shard_id.clone());
                issues.push(shard_verification_issue(
                    shard_id,
                    format!(
                        "Manifest entryCount {} does not match {} actual shard entries",
                        manifest_entry.entry_count, actual_shard.entry_count
                    ),
                ));
            }
            if manifest_entry.shard_hash != actual_hash {
                mismatched_shard_ids.insert(shard_id.clone());
                issues.push(shard_verification_issue(
                    shard_id,
                    "Manifest shardHash does not match the actual shard file",
                ));
            }
        }
    }

    issues.sort_by(|left, right| {
        left.shard_id
            .cmp(&right.shard_id)
            .then(left.message.cmp(&right.message))
    });
    issues.dedup();
    let missing_manifest_shard_ids: Vec<_> = missing_manifest_shard_ids.into_iter().collect();
    let unexpected_manifest_shard_ids: Vec<_> = unexpected_manifest_shard_ids.into_iter().collect();
    let missing_shard_ids: Vec<_> = missing_shard_ids.into_iter().collect();
    let unexpected_shard_ids: Vec<_> = unexpected_shard_ids.into_iter().collect();
    let mismatched_shard_ids: Vec<_> = mismatched_shard_ids.into_iter().collect();
    let valid = missing_manifest_shard_ids.is_empty()
        && unexpected_manifest_shard_ids.is_empty()
        && missing_shard_ids.is_empty()
        && unexpected_shard_ids.is_empty()
        && mismatched_shard_ids.is_empty()
        && issues.is_empty();

    RegistryShardManifestVerificationV1 {
        schema_version: "swarm-ai.registry.shard-manifest-verification.v1".to_string(),
        valid,
        shard_source,
        expected_snapshot_hash,
        actual_snapshot_hash: manifest.snapshot_hash.clone(),
        snapshot_hash_matches,
        expected_manifest_hash,
        actual_manifest_hash,
        declared_manifest_hash: manifest.manifest_hash.clone(),
        manifest_hash_matches,
        expected_entry_count: snapshot.entries.len(),
        manifest_entry_count: manifest.entry_count,
        expected_shard_count: expected.len(),
        manifest_shard_count: manifest.shard_count,
        actual_shard_count: actual.len(),
        missing_manifest_shard_ids,
        unexpected_manifest_shard_ids,
        missing_shard_ids,
        unexpected_shard_ids,
        mismatched_shard_ids,
        issues,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn verify_registry_shard_map(
    snapshot: &RegistrySnapshotV1,
    actual: BTreeMap<String, RegistryShardV1>,
    shard_source: String,
) -> RegistryShardVerificationV1 {
    let expected: BTreeMap<_, _> = build_registry_shards(snapshot)
        .into_iter()
        .map(|shard| (shard.shard_id.clone(), shard))
        .collect();

    let mut missing_shard_ids: Vec<_> = expected
        .keys()
        .filter(|shard_id| !actual.contains_key(*shard_id))
        .cloned()
        .collect();
    let mut unexpected_shard_ids: Vec<_> = actual
        .keys()
        .filter(|shard_id| !expected.contains_key(*shard_id))
        .cloned()
        .collect();
    let mut mismatched_shard_ids = Vec::new();
    let mut issues = Vec::new();

    for (shard_id, actual_shard) in &actual {
        if actual_shard.shard_id != *shard_id {
            issues.push(shard_verification_issue(
                shard_id,
                format!(
                    "Shard payload id {} does not match file-derived id {}",
                    actual_shard.shard_id, shard_id
                ),
            ));
        }
        let expected_id = shard_id_from_shard(actual_shard);
        if actual_shard.shard_id != expected_id {
            issues.push(shard_verification_issue(
                shard_id,
                format!(
                    "Shard id should be {} for kind {} and key {}",
                    expected_id, actual_shard.shard_kind, actual_shard.shard_key
                ),
            ));
        }
        if actual_shard.entry_count != actual_shard.entries.len() {
            issues.push(shard_verification_issue(
                shard_id,
                format!(
                    "Shard entryCount {} does not match {} embedded entries",
                    actual_shard.entry_count,
                    actual_shard.entries.len()
                ),
            ));
        }
    }

    for (shard_id, expected_shard) in &expected {
        if let Some(actual_shard) = actual.get(shard_id)
            && !registry_shards_equivalent(expected_shard, actual_shard)
        {
            mismatched_shard_ids.push(shard_id.clone());
            issues.push(shard_verification_issue(
                shard_id,
                "Shard content differs from the expected snapshot-derived shard",
            ));
        }
    }

    missing_shard_ids.sort();
    unexpected_shard_ids.sort();
    mismatched_shard_ids.sort();
    issues.sort_by(|left, right| {
        left.shard_id
            .cmp(&right.shard_id)
            .then(left.message.cmp(&right.message))
    });
    let valid = missing_shard_ids.is_empty()
        && unexpected_shard_ids.is_empty()
        && mismatched_shard_ids.is_empty()
        && issues.is_empty();
    let expected_shard_hashes = shard_hashes(&expected);
    let actual_shard_hashes = shard_hashes(&actual);

    RegistryShardVerificationV1 {
        schema_version: "swarm-ai.registry.shard-verification.v1".to_string(),
        valid,
        shard_source,
        expected_shard_count: expected.len(),
        actual_shard_count: actual.len(),
        missing_shard_ids,
        unexpected_shard_ids,
        mismatched_shard_ids,
        expected_shard_hashes,
        actual_shard_hashes,
        issues,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn round_score(score: f64) -> f64 {
    (score * 10_000.0).round() / 10_000.0
}

pub fn public_registry_snapshot(snapshot: &RegistrySnapshotV1) -> RegistrySnapshotV1 {
    let hidden_ids: BTreeSet<_> = snapshot
        .entries
        .iter()
        .filter(|entry| registry_entry_is_private(entry))
        .map(|entry| entry.package_id.clone())
        .collect();
    let hidden_refs: BTreeSet<_> = snapshot
        .entries
        .iter()
        .filter(|entry| registry_entry_is_private(entry))
        .flat_map(|entry| {
            entry
                .package_refs
                .iter()
                .map(|reference| reference.package_ref.clone())
        })
        .collect();

    let mut public = snapshot.clone();
    public
        .entries
        .retain(|entry| !registry_entry_is_private(entry));
    public.publication_records.retain(|record| {
        !hidden_ids.contains(&record.package_id) && !hidden_refs.contains(&record.package_ref)
    });
    public.publication_statuses.retain(|status| {
        !hidden_ids.contains(&status.package_id) && !hidden_refs.contains(&status.package_ref)
    });
    public
        .feed_statuses
        .retain(|status| !hidden_ids.contains(&status.package_id));
    public
        .validation_reports
        .retain(|report| !hidden_refs.contains(&report.package_ref));
    public
        .evaluation_results
        .retain(|result| !hidden_refs.contains(&result.package_ref));
    public
}

pub fn registry_entry_visible_to_query(entry: &RegistryEntryV1, query: &RegistryQueryV1) -> bool {
    if !registry_entry_is_private(entry) {
        return true;
    }
    private_entry_authorized_by_query(entry, query)
}

pub fn search_registry(
    packages: &[IndexedPackage],
    query: &RegistryQueryV1,
) -> RegistrySearchResponse {
    let mut entries: Vec<_> = packages
        .iter()
        .map(|package| package.entry.clone())
        .filter(|entry| registry_entry_visible_to_query(entry, query))
        .filter(|entry| {
            query
                .kind
                .as_ref()
                .map(|kind| &entry.kind == kind)
                .unwrap_or(true)
        })
        .filter(|entry| {
            query
                .capability
                .as_ref()
                .map(|capability| entry.capabilities.iter().any(|item| item == capability))
                .unwrap_or(true)
        })
        .filter(|entry| {
            query
                .target
                .as_ref()
                .map(|target| entry.targets.iter().any(|item| item == target))
                .unwrap_or(true)
        })
        .filter(|entry| {
            query
                .engine
                .as_ref()
                .map(|engine| entry.engines.iter().any(|item| item == engine))
                .unwrap_or(true)
        })
        .filter(|entry| {
            query
                .license_type
                .as_ref()
                .map(|license_type| {
                    format!("{:?}", entry.license.license_type).eq_ignore_ascii_case(license_type)
                })
                .unwrap_or(true)
        })
        .filter(|entry| {
            query
                .min_validator_score
                .map(|score| entry.trust.validator_score.unwrap_or(0.0) >= score)
                .unwrap_or(true)
        })
        .filter(|entry| {
            query
                .min_benchmark_score
                .map(|score| {
                    entry
                        .benchmark_scores
                        .iter()
                        .any(|summary| summary.overall >= score)
                })
                .unwrap_or(true)
        })
        .collect();

    let start = query
        .cursor
        .as_deref()
        .and_then(|cursor| cursor.parse::<usize>().ok())
        .unwrap_or(0);
    let page_size = query.page_size.clamp(1, 100);
    let total = entries.len();
    entries = entries.into_iter().skip(start).take(page_size).collect();
    let next = (start + entries.len() < total).then(|| (start + entries.len()).to_string());

    RegistrySearchResponse {
        schema_version: "swarm-ai.registry.search.response.v1".to_string(),
        entries,
        next_cursor: next,
        total_approx: total,
    }
}

pub fn registry_package_lookup(
    packages: &[IndexedPackage],
    snapshot: &RegistrySnapshotV1,
    package_ref: &str,
    package_id: &str,
) -> Option<RegistryPackageLookupV1> {
    let package = find_package(packages, package_ref, package_id)?;
    Some(registry_package_lookup_from_indexed(package, snapshot))
}

pub fn registry_package_lookup_for_request(
    packages: &[IndexedPackage],
    snapshot: &RegistrySnapshotV1,
    request: &RegistryPackageLookupRequestV1,
) -> Option<RegistryPackageLookupV1> {
    let package = find_package(
        packages,
        request.package_ref.as_deref().unwrap_or_default(),
        request.package_id.as_deref().unwrap_or_default(),
    )?;
    registry_package_visible_to_lookup_request(&package.entry, request)
        .then(|| registry_package_lookup_from_indexed(package, snapshot))
}

pub fn registry_package_lookup_from_indexed(
    package: &IndexedPackage,
    snapshot: &RegistrySnapshotV1,
) -> RegistryPackageLookupV1 {
    let package_id = package.entry.package_id.clone();
    let package_refs = package_reference_set(package);

    let publication_records = snapshot
        .publication_records
        .iter()
        .filter(|record| {
            record.package_id == package_id || package_refs.contains(record.package_ref.as_str())
        })
        .cloned()
        .collect();
    let publication_statuses = snapshot
        .publication_statuses
        .iter()
        .filter(|status| {
            status.package_id == package_id || package_refs.contains(status.package_ref.as_str())
        })
        .cloned()
        .collect();
    let feed_statuses = snapshot
        .feed_statuses
        .iter()
        .filter(|status| status.package_id == package_id)
        .cloned()
        .collect();
    let validation_reports = snapshot
        .validation_reports
        .iter()
        .filter(|report| package_refs.contains(report.package_ref.as_str()))
        .cloned()
        .collect();
    let evaluation_results = snapshot
        .evaluation_results
        .iter()
        .filter(|result| package_refs.contains(result.package_ref.as_str()))
        .cloned()
        .collect();

    RegistryPackageLookupV1 {
        schema_version: "swarm-ai.registry.package-lookup.v1".to_string(),
        package_id,
        package_root: package.package.root.display().to_string(),
        local_package_ref: package.package.package_ref.clone(),
        manifest_hash: package.package.manifest_hash.clone(),
        entry: package.entry.clone(),
        manifest: package.package.manifest.clone(),
        publication_records,
        publication_statuses,
        feed_statuses,
        validation_reports,
        evaluation_results,
    }
}

pub fn registry_package_visible_to_lookup_request(
    entry: &RegistryEntryV1,
    request: &RegistryPackageLookupRequestV1,
) -> bool {
    if !registry_entry_is_private(entry) {
        return true;
    }
    private_entry_authorized_by_query(entry, &lookup_request_query(request))
}

fn registry_entry_is_private(entry: &RegistryEntryV1) -> bool {
    entry.license.license_type == LicenseType::Private
}

fn lookup_request_query(request: &RegistryPackageLookupRequestV1) -> RegistryQueryV1 {
    RegistryQueryV1 {
        schema_version: "swarm-ai.registry.query.v1".to_string(),
        kind: None,
        capability: None,
        target: None,
        engine: None,
        license_type: None,
        min_validator_score: None,
        min_benchmark_score: None,
        page_size: 1,
        cursor: None,
        requester: request.requester.clone(),
        requested_use: request.requested_use.clone(),
        runner_id: request.runner_id.clone(),
        access_grant: request.access_grant.clone(),
        access_revocation_list: request.access_revocation_list.clone(),
    }
}

fn private_entry_authorized_by_query(entry: &RegistryEntryV1, query: &RegistryQueryV1) -> bool {
    let Some(grant) = query.access_grant.as_ref() else {
        return false;
    };
    if grant.package_id != entry.package_id {
        return false;
    }
    if !entry
        .package_refs
        .iter()
        .any(|reference| reference.package_ref == grant.package_ref)
    {
        return false;
    }

    let requester = query.requester.as_deref().unwrap_or(grant.grantee.as_str());
    let requested_use = query
        .requested_use
        .as_deref()
        .unwrap_or(DEFAULT_REGISTRY_REQUESTED_USE);
    let policy = registry_entry_license_policy(entry, grant.package_ref.clone());
    let request = hivemind_access::access_request(
        "registry-search",
        entry.package_id.clone(),
        grant.package_ref.clone(),
        requester.to_string(),
        requested_use.to_string(),
        query.runner_id.clone(),
        Vec::new(),
    );
    let evaluation = hivemind_access::evaluate_access_request_with_revocations(
        &policy,
        &request,
        Some(grant),
        query.access_revocation_list.as_ref(),
        Utc::now(),
    );
    evaluation.decision == AccessDecision::Granted
}

fn registry_entry_license_policy(
    entry: &RegistryEntryV1,
    package_ref: impl Into<String>,
) -> LicensePolicyV1 {
    let license_type = entry.license.license_type.clone();
    LicensePolicyV1 {
        schema_version: "swarm-ai.license-policy.v1".to_string(),
        package_id: entry.package_id.clone(),
        package_ref: package_ref.into(),
        license_type: license_type.clone(),
        allowed_uses: default_allowed_uses(&license_type),
        restricted_uses: vec![
            "training-competitor-model".to_string(),
            "redistribution".to_string(),
        ],
        requires_access_grant: license_requires_access_grant(&license_type),
        terms_ref: entry.license.url.clone(),
        access_control: AccessControlV1 {
            mode: default_access_control_mode(&license_type),
            act_ref: None,
        },
    }
}

fn package_reference_set(package: &IndexedPackage) -> BTreeSet<&str> {
    package
        .entry
        .package_refs
        .iter()
        .map(|reference| reference.package_ref.as_str())
        .chain(std::iter::once(package.package.package_ref.as_str()))
        .collect()
}

fn benchmark_summary(result: &EvaluationResultV1) -> RegistryBenchmarkScoreV1 {
    RegistryBenchmarkScoreV1 {
        benchmark_id: result.benchmark_id.clone(),
        benchmark_version: result.benchmark_version.clone(),
        evaluation_id: result.evaluation_id.clone(),
        quality: round_score(result.scores.quality),
        latency: round_score(result.scores.latency),
        overall: round_score(result.scores.overall),
        created_at: result.created_at.clone(),
    }
}

fn merge_publication_records(
    records: Vec<PublicationRecordV1>,
    feed_resolutions: &[FeedResolutionV1],
) -> Vec<PublicationRecordV1> {
    let mut merged = BTreeMap::<(String, String, String, String), PublicationRecordV1>::new();
    for record in records.into_iter().chain(
        feed_resolutions
            .iter()
            .map(|resolution| resolution.pointer.publication_record.clone()),
    ) {
        let key = (
            record.package_id.clone(),
            record.version.clone(),
            record.package_ref.clone(),
            record.manifest_hash.clone(),
        );
        merged
            .entry(key)
            .and_modify(|existing| {
                if prefer_publication_record(&record, existing) {
                    *existing = record.clone();
                }
            })
            .or_insert(record);
    }
    merged.into_values().collect()
}

fn prefer_publication_record(
    candidate: &PublicationRecordV1,
    current: &PublicationRecordV1,
) -> bool {
    let candidate_verified = verify_publication_record(candidate).valid;
    let current_verified = verify_publication_record(current).valid;
    candidate_verified && !current_verified
        || candidate_verified == current_verified && candidate.published_at > current.published_at
}

fn publication_statuses(records: &[PublicationRecordV1]) -> Vec<RegistryPublicationStatusV1> {
    records
        .iter()
        .map(|record| {
            let verification = verify_publication_record(record);
            RegistryPublicationStatusV1 {
                schema_version: "swarm-ai.registry.publication-status.v1".to_string(),
                package_id: record.package_id.clone(),
                version: record.version.clone(),
                package_ref: record.package_ref.clone(),
                valid: verification.valid,
                verification,
            }
        })
        .collect()
}

fn feed_statuses(resolutions: &[FeedResolutionV1]) -> Vec<RegistryFeedStatusV1> {
    resolutions
        .iter()
        .map(|resolution| RegistryFeedStatusV1 {
            schema_version: "swarm-ai.registry.feed-status.v1".to_string(),
            package_id: resolution.pointer.package_id.clone(),
            channel: resolution.pointer.channel.clone(),
            feed_ref: resolution.feed_ref.clone(),
            valid: resolution.valid,
            resolution: resolution.clone(),
        })
        .collect()
}

fn load_registry_shard_files(shard_dir: &Path) -> Result<BTreeMap<String, RegistryShardV1>> {
    let mut shards = BTreeMap::new();
    if !shard_dir.exists() {
        return Ok(shards);
    }
    for entry in fs::read_dir(shard_dir)
        .with_context(|| format!("failed to read {}", shard_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if is_registry_shard_manifest_file(&path) {
            continue;
        }
        if !entry.file_type()?.is_file()
            || path.extension().and_then(|extension| extension.to_str()) != Some("json")
        {
            continue;
        }
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let shard = serde_json::from_slice::<RegistryShardV1>(&bytes)
            .with_context(|| format!("failed to parse registry shard {}", path.display()))?;
        let shard_id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(shard.shard_id.as_str())
            .to_string();
        shards.insert(shard_id, shard);
    }
    Ok(shards)
}

fn is_registry_shard_manifest_file(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some(REGISTRY_SHARD_MANIFEST_FILE)
}

fn registry_manifest_shard_path_is_portable(path: &str) -> bool {
    let path = Path::new(path);
    if path.is_absolute() {
        return false;
    }
    let mut has_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => has_component = true,
            _ => return false,
        }
    }
    has_component
}

fn registry_shards_equivalent(expected: &RegistryShardV1, actual: &RegistryShardV1) -> bool {
    expected.schema_version == actual.schema_version
        && expected.shard_id == actual.shard_id
        && expected.shard_kind == actual.shard_kind
        && expected.shard_key == actual.shard_key
        && expected.entry_count == actual.entry_count
        && expected.entries == actual.entries
}

fn shard_hashes(shards: &BTreeMap<String, RegistryShardV1>) -> Vec<RegistryShardHashV1> {
    shards
        .iter()
        .map(|(shard_id, shard)| RegistryShardHashV1 {
            shard_id: shard_id.clone(),
            shard_hash: registry_shard_hash(shard),
        })
        .collect()
}

fn shard_id_from_shard(shard: &RegistryShardV1) -> String {
    shard_id(&shard.shard_kind, &shard.shard_key)
}

fn shard_verification_issue(
    shard_id: impl Into<String>,
    message: impl Into<String>,
) -> RegistryShardVerificationIssueV1 {
    RegistryShardVerificationIssueV1 {
        shard_id: shard_id.into(),
        message: message.into(),
    }
}

fn feed_resolution_from_pointer(pointer: FeedPointerV1) -> FeedResolutionV1 {
    let record = pointer.publication_record.clone();
    let feed_verification = verify_feed_pointer(&pointer);
    let publication_verification = verify_publication_record(&record);
    let valid = feed_verification.valid && publication_verification.valid;
    FeedResolutionV1 {
        schema_version: "swarm-ai.feed-resolution.v1".to_string(),
        valid,
        feed_ref: publisher_feed_ref(&pointer.package_id, &pointer.channel),
        pointer,
        feed_verification,
        verification: publication_verification,
    }
}

fn collect_json_files(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_json_files(&path, paths)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(())
}

fn push_shard_entry(
    groups: &mut BTreeMap<(String, String), Vec<RegistryEntryV1>>,
    shard_kind: &str,
    shard_key: &str,
    entry: &RegistryEntryV1,
) {
    groups
        .entry((shard_kind.to_string(), shard_key.to_string()))
        .or_default()
        .push(entry.clone());
}

fn shard_id(shard_kind: &str, shard_key: &str) -> String {
    format!(
        "{}-{}",
        safe_file_component(shard_kind),
        safe_file_component(shard_key)
    )
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

pub fn find_package<'a>(
    packages: &'a [IndexedPackage],
    package_ref: &str,
    package_id: &str,
) -> Option<&'a IndexedPackage> {
    let package_ref = package_ref.trim();
    let package_id = package_id.trim();
    packages.iter().find(|package| {
        if !package_ref.is_empty() {
            return package.package.package_ref == package_ref
                || package
                    .entry
                    .package_refs
                    .iter()
                    .any(|reference| reference.package_ref == package_ref);
        }

        !package_id.is_empty() && package.package.manifest.package_id == package_id
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, Publisher,
    };
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn finds_published_refs_without_falling_back_to_id() {
        let mut indexed = index_package(package("bzz://local-manifest"));
        indexed.entry.package_refs[0].package_ref = "bzz://published".to_string();
        let packages = vec![indexed];

        assert!(find_package(&packages, "bzz://published", "hivemind/test").is_some());
        assert!(find_package(&packages, "bzz://missing", "hivemind/test").is_none());
        assert!(find_package(&packages, "", "hivemind/test").is_some());
    }

    #[test]
    fn local_indexing_uses_stable_published_at_for_mirror_hashes() {
        let first = index_package(package("bzz://local-manifest"));
        let second = index_package(package("bzz://local-manifest"));
        assert_eq!(
            first.entry.package_refs[0].published_at,
            REGISTRY_LOCAL_PUBLISHED_AT
        );
        assert_eq!(
            first.entry.package_refs[0].published_at,
            second.entry.package_refs[0].published_at
        );

        let first_snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![first.entry],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };
        let second_snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![second.entry],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };
        assert_eq!(
            registry_snapshot_hash(&first_snapshot),
            registry_snapshot_hash(&second_snapshot)
        );
    }

    #[test]
    fn registry_snapshot_hash_ignores_verification_observation_time() {
        let package = package("bzz://local-manifest");
        let record = signed_publication(&package, "bzz://published", &["latest"]);
        let mut first_statuses = publication_statuses(std::slice::from_ref(&record));
        let mut second_statuses = first_statuses.clone();
        first_statuses[0].verification.verified_at = "2026-05-28T00:00:01Z".to_string();
        second_statuses[0].verification.verified_at = "2026-05-28T00:00:02Z".to_string();
        assert_ne!(first_statuses, second_statuses);

        let first_snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![index_package(package.clone()).entry],
            publication_records: vec![record.clone()],
            publication_statuses: first_statuses,
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };
        let second_snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![index_package(package).entry],
            publication_records: vec![record],
            publication_statuses: second_statuses,
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };
        assert_eq!(
            registry_snapshot_hash(&first_snapshot),
            registry_snapshot_hash(&second_snapshot)
        );
    }

    #[test]
    fn package_lookup_collects_entry_manifest_and_trust_evidence() {
        let package = package("bzz://local-manifest");
        let record = signed_publication(&package, "bzz://published", &["latest"]);
        let pointer = hivemind_publisher::feed_pointer_from_record(&record, "latest");
        let resolution = feed_resolution_from_pointer(pointer);
        let mut indexed = index_package(package.clone());
        indexed.entry.package_refs[0].package_ref = "bzz://published".to_string();
        let report = validation_report("report-lookup", "bzz://published", 0.91);
        let result = evaluation_result(
            "evaluation-lookup",
            "commons/embedding-basic-v1",
            "bzz://published",
            0.93,
        );
        let packages = vec![indexed.clone()];
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![indexed.entry.clone()],
            publication_records: vec![record.clone()],
            publication_statuses: publication_statuses(std::slice::from_ref(&record)),
            feed_statuses: feed_statuses(std::slice::from_ref(&resolution)),
            validation_reports: vec![report],
            evaluation_results: vec![result],
        };

        let lookup = registry_package_lookup(&packages, &snapshot, "", "hivemind/test")
            .expect("package lookup");

        assert_eq!(lookup.schema_version, "swarm-ai.registry.package-lookup.v1");
        assert_eq!(lookup.package_id, "hivemind/test");
        assert_eq!(lookup.manifest.package_id, "hivemind/test");
        assert_eq!(lookup.entry.package_refs[0].package_ref, "bzz://published");
        assert_eq!(lookup.publication_records.len(), 1);
        assert_eq!(lookup.publication_statuses.len(), 1);
        assert_eq!(lookup.feed_statuses.len(), 1);
        assert_eq!(lookup.validation_reports.len(), 1);
        assert_eq!(lookup.evaluation_results.len(), 1);
        assert!(registry_package_lookup(&packages, &snapshot, "", "missing").is_none());
    }

    #[test]
    fn private_package_lookup_requires_matching_access_grant() {
        let private = index_package(package_with_license(
            "hivemind/private-test",
            "Private Test",
            "bzz://private",
            LicenseType::Private,
        ));
        let packages = vec![private.clone()];
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![private.entry.clone()],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };
        let mut request = lookup_request("hivemind/private-test");

        assert!(registry_package_lookup_for_request(&packages, &snapshot, &request).is_none());

        let policy = registry_entry_license_policy(&private.entry, "bzz://private");
        let grant = hivemind_access::dev_access_grant(
            &policy,
            "local-dev",
            "runner-service",
            Some("local-dev-runner".to_string()),
            None,
        );
        request.access_grant = Some(grant.clone());
        request.requester = Some("local-dev".to_string());

        assert!(registry_package_lookup_for_request(&packages, &snapshot, &request).is_none());

        request.runner_id = Some("local-dev-runner".to_string());
        assert!(
            registry_package_lookup_for_request(&packages, &snapshot, &request)
                .is_some_and(|lookup| lookup.package_id == "hivemind/private-test")
        );

        let revocation = hivemind_access::revoke_access_grant(&grant, "local-dev", "grant revoked");
        request.access_revocation_list =
            Some(hivemind_access::access_revocation_list(vec![revocation]));
        assert!(registry_package_lookup_for_request(&packages, &snapshot, &request).is_none());
    }

    #[test]
    fn applies_validation_scores_to_matching_package_refs() {
        let mut indexed = index_package(package("bzz://local-manifest"));
        indexed.entry.package_refs[0].package_ref = "bzz://published".to_string();
        let mut packages = vec![indexed];
        let reports = vec![
            validation_report("report-1", "bzz://published", 0.9),
            validation_report("report-2", "bzz://published", 0.7),
        ];

        apply_validation_reports(&mut packages, &reports);

        assert_eq!(packages[0].entry.trust.validator_score, Some(0.8));
    }

    #[test]
    fn applies_evaluation_summaries_to_matching_package_refs() {
        let mut indexed = index_package(package("bzz://local-manifest"));
        indexed.entry.package_refs[0].package_ref = "bzz://published".to_string();
        let mut packages = vec![indexed];
        let results = vec![evaluation_result(
            "evaluation-1",
            "commons/embedding-basic-v1",
            "bzz://published",
            0.92,
        )];

        apply_evaluation_results(&mut packages, &results);

        assert_eq!(packages[0].entry.benchmark_scores.len(), 1);
        assert_eq!(
            packages[0].entry.benchmark_scores[0].benchmark_id,
            "commons/embedding-basic-v1"
        );
        assert_eq!(packages[0].entry.benchmark_scores[0].overall, 0.92);
    }

    #[test]
    fn applies_publication_signature_status() {
        let package = package("bzz://local-manifest");
        let signed = signed_publication(&package, "bzz://published", &["latest"]);
        let mut packages = vec![index_package(package.clone())];

        apply_publication_records(&mut packages, &[signed.clone()]);

        assert!(packages[0].entry.trust.signature_verified);
        assert_eq!(
            packages[0].entry.package_refs[0].package_ref,
            "bzz://published"
        );

        let mut tampered = signed;
        tampered.package_ref = "bzz://tampered".to_string();
        let mut packages = vec![index_package(package)];

        apply_publication_records(&mut packages, &[tampered]);

        assert!(!packages[0].entry.trust.signature_verified);
        assert_eq!(
            packages[0].entry.package_refs[0].package_ref,
            "bzz://tampered"
        );
    }

    #[test]
    fn loads_feed_resolutions_as_registry_publications() {
        let root = std::env::temp_dir().join(format!(
            "hivemind-registry-feed-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let package = package("bzz://local-manifest");
        let record = signed_publication(&package, "bzz://published-feed", &["latest", "stable"]);

        hivemind_publisher::write_feed_updates(&root, &record).unwrap();
        let resolutions = load_feed_resolutions(&root).unwrap();
        let records = merge_publication_records(Vec::new(), &resolutions);
        let mut packages = vec![index_package(package)];
        apply_publication_records(&mut packages, &records);

        assert_eq!(resolutions.len(), 2);
        assert!(resolutions.iter().all(|resolution| resolution.valid));
        assert!(packages[0].entry.trust.signature_verified);
        assert_eq!(packages[0].entry.latest_version, "0.1.0");
        assert_eq!(packages[0].entry.stable_version, "0.1.0");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn builds_registry_shards_for_common_facets() {
        let entry = index_package(package("bzz://local-manifest")).entry;
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![entry],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };

        let shards = build_registry_shards(&snapshot);

        assert!(shards.iter().any(|shard| shard.shard_id == "all-all"));
        assert!(
            shards
                .iter()
                .any(|shard| shard.shard_id == "capability-embedding")
        );
        assert!(shards.iter().all(|shard| shard.entry_count > 0));
    }

    #[test]
    fn verifies_registry_shard_directory_against_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "hivemind-registry-shard-verify-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let entry = index_package(package("bzz://local-manifest")).entry;
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![entry],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };

        let write = write_registry_shards(&snapshot, &root).unwrap();
        assert!(write.shards.iter().all(|file| file.shard_hash.len() == 64));
        assert_eq!(
            write.manifest_path,
            root.join(REGISTRY_SHARD_MANIFEST_FILE)
                .display()
                .to_string()
        );
        assert!(root.join(REGISTRY_SHARD_MANIFEST_FILE).exists());
        assert_eq!(
            write.manifest.schema_version,
            "swarm-ai.registry.shard-manifest.v1"
        );
        assert_eq!(write.manifest.entry_count, snapshot.entries.len());
        assert_eq!(write.manifest.shard_count, write.shard_count);
        assert_eq!(
            write.manifest.snapshot_hash,
            registry_snapshot_hash(&snapshot)
        );
        assert_eq!(
            write.manifest.manifest_hash,
            registry_shard_manifest_hash(&write.manifest)
        );
        assert_eq!(write.manifest.manifest_hash.len(), 64);
        assert!(write.manifest.shards.iter().all(|file| {
            file.shard_hash.len() == 64 && !Path::new(&file.shard_path).is_absolute()
        }));
        assert_eq!(
            read_registry_shard_manifest(&root.join(REGISTRY_SHARD_MANIFEST_FILE)).unwrap(),
            write.manifest
        );
        let all_manifest_file = write
            .manifest
            .shards
            .iter()
            .find(|file| file.shard_id == "all-all")
            .unwrap();
        assert_eq!(all_manifest_file.shard_path, "all-all.json");
        let verification = verify_registry_shards(&snapshot, &root).unwrap();
        assert!(verification.valid);
        assert!(verification.issues.is_empty());
        assert_eq!(verification.expected_shard_hashes.len(), write.shard_count);
        assert_eq!(
            verification.expected_shard_hashes,
            verification.actual_shard_hashes
        );
        let manifest_verification = verify_registry_shard_manifest_dir(&snapshot, &root).unwrap();
        assert!(manifest_verification.valid);
        assert!(manifest_verification.snapshot_hash_matches);
        assert!(manifest_verification.manifest_hash_matches);
        assert_eq!(
            manifest_verification.expected_manifest_hash,
            write.manifest.manifest_hash
        );
        assert_eq!(
            manifest_verification.actual_manifest_hash,
            write.manifest.manifest_hash
        );
        assert_eq!(
            manifest_verification.expected_shard_count,
            write.shard_count
        );
        assert_eq!(
            manifest_verification.manifest_shard_count,
            write.shard_count
        );
        assert_eq!(manifest_verification.actual_shard_count, write.shard_count);
        let comparison = compare_registry_shard_manifest(&snapshot, &write.manifest, "test");
        assert!(comparison.matches);
        assert!(comparison.snapshot_hash_matches);
        assert!(comparison.manifest_hash_matches);
        assert_eq!(
            comparison.expected_manifest_hash,
            write.manifest.manifest_hash
        );
        assert!(comparison.changed_shard_ids.is_empty());

        let mut stale_manifest = write.manifest.clone();
        stale_manifest.snapshot_hash = "0".repeat(64);
        stale_manifest.manifest_hash = registry_shard_manifest_hash(&stale_manifest);
        let comparison = compare_registry_shard_manifest(&snapshot, &stale_manifest, "test");
        assert!(!comparison.matches);
        assert!(!comparison.snapshot_hash_matches);
        assert!(comparison.changed_shard_ids.is_empty());
        let manifest_verification = verify_registry_shard_manifest_set(
            &snapshot,
            &stale_manifest,
            build_registry_shards(&snapshot),
            "test",
        );
        assert!(!manifest_verification.valid);
        assert!(!manifest_verification.snapshot_hash_matches);
        assert!(
            manifest_verification
                .issues
                .iter()
                .any(|issue| issue.shard_id == "manifest"
                    && issue.message.contains("snapshotHash"))
        );

        let mut bad_manifest_hash = write.manifest.clone();
        bad_manifest_hash.manifest_hash = "0".repeat(64);
        let manifest_verification = verify_registry_shard_manifest_set(
            &snapshot,
            &bad_manifest_hash,
            build_registry_shards(&snapshot),
            "test",
        );
        assert!(!manifest_verification.valid);
        assert!(!manifest_verification.manifest_hash_matches);
        assert!(
            manifest_verification
                .issues
                .iter()
                .any(|issue| issue.shard_id == "manifest"
                    && issue.message.contains("manifestHash"))
        );

        let mut changed_manifest = write.manifest.clone();
        changed_manifest.shards[0].shard_hash = "0".repeat(64);
        changed_manifest.manifest_hash = registry_shard_manifest_hash(&changed_manifest);
        let comparison = compare_registry_shard_manifest(&snapshot, &changed_manifest, "test");
        assert!(!comparison.matches);
        assert!(!comparison.manifest_hash_matches);
        assert!(
            comparison
                .changed_shard_ids
                .iter()
                .any(|shard_id| shard_id == &changed_manifest.shards[0].shard_id)
        );

        let all_path = root.join("all-all.json");
        let mut all_shard: RegistryShardV1 =
            serde_json::from_slice(&fs::read(&all_path).unwrap()).unwrap();
        all_shard.entry_count += 1;
        fs::write(&all_path, serde_json::to_vec_pretty(&all_shard).unwrap()).unwrap();

        let verification = verify_registry_shards(&snapshot, &root).unwrap();
        assert!(!verification.valid);
        assert_ne!(
            verification.expected_shard_hashes,
            verification.actual_shard_hashes
        );
        assert!(
            verification
                .mismatched_shard_ids
                .iter()
                .any(|shard_id| shard_id == "all-all")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.shard_id == "all-all" && issue.message.contains("entryCount"))
        );
        let manifest_verification = verify_registry_shard_manifest_dir(&snapshot, &root).unwrap();
        assert!(!manifest_verification.valid);
        assert!(
            manifest_verification
                .mismatched_shard_ids
                .iter()
                .any(|shard_id| shard_id == "all-all")
        );
        assert!(manifest_verification.issues.iter().any(|issue| {
            issue.shard_id == "all-all" && issue.message.contains("actual shard file")
        }));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn registry_shard_hash_ignores_generated_at() {
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![index_package(package("bzz://local-manifest")).entry],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };
        let mut shard = build_registry_shards(&snapshot)
            .into_iter()
            .find(|shard| shard.shard_id == "all-all")
            .unwrap();
        let original_hash = registry_shard_hash(&shard);

        shard.generated_at = "2099-01-01T00:00:00Z".to_string();
        assert_eq!(registry_shard_hash(&shard), original_hash);

        shard.entry_count += 1;
        assert_ne!(registry_shard_hash(&shard), original_hash);
    }

    #[test]
    fn registry_shard_manifest_hash_ignores_generated_at_and_self_hash() {
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![index_package(package("bzz://local-manifest")).entry],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
        };
        let shards = build_registry_shards(&snapshot);
        let mut manifest = registry_shard_manifest_for_shards(&snapshot, &shards);
        let original_hash = registry_shard_manifest_hash(&manifest);

        manifest.generated_at = "2099-01-01T00:00:00Z".to_string();
        manifest.manifest_hash = "0".repeat(64);
        assert_eq!(registry_shard_manifest_hash(&manifest), original_hash);

        manifest.entry_count += 1;
        assert_ne!(registry_shard_manifest_hash(&manifest), original_hash);
    }

    #[test]
    fn private_search_results_require_matching_access_grant() {
        let open = index_package(package_with_license(
            "hivemind/open-test",
            "Open Test",
            "bzz://open",
            LicenseType::Open,
        ));
        let private = index_package(package_with_license(
            "hivemind/private-test",
            "Private Test",
            "bzz://private",
            LicenseType::Private,
        ));
        let packages = vec![open, private.clone()];
        let mut query = registry_query();

        let without_grant = search_registry(&packages, &query);
        assert_eq!(without_grant.total_approx, 1);
        assert!(
            without_grant
                .entries
                .iter()
                .all(|entry| entry.package_id != "hivemind/private-test")
        );

        let policy = registry_entry_license_policy(&private.entry, "bzz://private");
        let grant = hivemind_access::dev_access_grant(
            &policy,
            "local-dev",
            "runner-service",
            Some("local-dev-runner".to_string()),
            None,
        );
        query.access_grant = Some(grant.clone());
        query.requester = Some("local-dev".to_string());

        let runner_missing = search_registry(&packages, &query);
        assert!(
            runner_missing
                .entries
                .iter()
                .all(|entry| entry.package_id != "hivemind/private-test")
        );

        query.runner_id = Some("local-dev-runner".to_string());
        let with_grant = search_registry(&packages, &query);
        assert_eq!(with_grant.total_approx, 2);
        assert!(
            with_grant
                .entries
                .iter()
                .any(|entry| entry.package_id == "hivemind/private-test")
        );

        let revocation = hivemind_access::revoke_access_grant(&grant, "local-dev", "grant revoked");
        query.access_revocation_list =
            Some(hivemind_access::access_revocation_list(vec![revocation]));
        let revoked = search_registry(&packages, &query);
        assert!(
            revoked
                .entries
                .iter()
                .all(|entry| entry.package_id != "hivemind/private-test")
        );
    }

    #[test]
    fn public_registry_snapshot_filters_private_entries_and_metadata() {
        let open_package = package_with_license(
            "hivemind/open-test",
            "Open Test",
            "bzz://open",
            LicenseType::Open,
        );
        let private_package = package_with_license(
            "hivemind/private-test",
            "Private Test",
            "bzz://private",
            LicenseType::Private,
        );
        let open_record = signed_publication(&open_package, "bzz://open-published", &["latest"]);
        let private_record =
            signed_publication(&private_package, "bzz://private-published", &["latest"]);
        let records = vec![open_record.clone(), private_record.clone()];
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            entries: vec![
                index_package(open_package).entry,
                index_package(private_package).entry,
            ],
            publication_records: records.clone(),
            publication_statuses: publication_statuses(&records),
            feed_statuses: Vec::new(),
            validation_reports: vec![validation_report("private", "bzz://private", 0.9)],
            evaluation_results: vec![evaluation_result(
                "private",
                "commons/embedding-basic-v1",
                "bzz://private",
                0.9,
            )],
        };

        let public = public_registry_snapshot(&snapshot);

        assert_eq!(public.entries.len(), 1);
        assert_eq!(public.entries[0].package_id, "hivemind/open-test");
        assert_eq!(public.publication_records.len(), 1);
        assert_eq!(
            public.publication_records[0].package_id,
            "hivemind/open-test"
        );
        assert_eq!(public.publication_statuses.len(), 1);
        assert!(public.validation_reports.is_empty());
        assert!(public.evaluation_results.is_empty());
    }

    fn validation_report(id: &str, package_ref: &str, overall: f64) -> ValidationReportV1 {
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: package_ref.to_string(),
            challenge_id: "challenge-1".to_string(),
            receipt_id: "receipt-1".to_string(),
            scores: hivemind_validator::ValidationScoresV1 {
                quality: overall,
                latency: overall,
                cost_efficiency: overall,
                policy_compliance: overall,
                overall,
            },
            evidence_refs: Vec::new(),
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        hivemind_validator::sign_validation_report(&mut report);
        report.report_id = hivemind_validator::canonical_validation_report_id(&report).unwrap();
        if id != "report-1" {
            report.evidence_refs = vec![format!("local://{id}")];
            hivemind_validator::sign_validation_report(&mut report);
            report.report_id = hivemind_validator::canonical_validation_report_id(&report).unwrap();
        }
        report
    }

    fn evaluation_result(
        id: &str,
        benchmark_id: &str,
        package_ref: &str,
        overall: f64,
    ) -> EvaluationResultV1 {
        let mut result = EvaluationResultV1 {
            schema_version: "swarm-ai.evaluation-result.v1".to_string(),
            evaluation_id: String::new(),
            benchmark_id: benchmark_id.to_string(),
            benchmark_version: "1.0.0".to_string(),
            package_ref: package_ref.to_string(),
            runner_id: Some("runner-1".to_string()),
            validator_id: "validator-1".to_string(),
            scores: hivemind_benchmarks::EvaluationScoresV1 {
                quality: overall,
                latency: 1.0,
                overall,
            },
            metrics: hivemind_benchmarks::EvaluationMetricsV1 {
                samples: 1,
                succeeded: 1,
                failed: 0,
                total_ms: 10,
                average_ms: 10.0,
            },
            result_refs: Vec::new(),
            sample_results: Vec::new(),
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        hivemind_benchmarks::sign_evaluation_result(&mut result);
        result.evaluation_id =
            hivemind_benchmarks::canonical_evaluation_result_id(&result).unwrap();
        if id != "evaluation-1" {
            result.result_refs = vec![format!("local://{id}")];
            hivemind_benchmarks::sign_evaluation_result(&mut result);
            result.evaluation_id =
                hivemind_benchmarks::canonical_evaluation_result_id(&result).unwrap();
        }
        result
    }

    fn signed_publication(
        package: &LocalPackage,
        package_ref: &str,
        channels: &[&str],
    ) -> PublicationRecordV1 {
        let channels_updated = channels
            .iter()
            .map(|channel| hivemind_publisher::FeedUpdateV1 {
                channel: (*channel).to_string(),
                feed_ref: hivemind_publisher::feed_ref(&package.manifest.package_id, channel),
            })
            .collect();
        hivemind_publisher::create_signed_publication_record_for_ref(
            package,
            package_ref.to_string(),
            channels_updated,
            hivemind_publisher::PublicationStorageV1 {
                pinned: false,
                redundancy_level: 0,
                postage_batch_id: None,
            },
        )
    }

    fn package(package_ref: &str) -> LocalPackage {
        LocalPackage {
            root: PathBuf::new(),
            manifest: hivemind_core::PackageManifestV1 {
                schema_version: "swarm-ai.package.v1".to_string(),
                package_id: "hivemind/test".to_string(),
                kind: PackageKind::Model,
                name: "Test".to_string(),
                version: "0.1.0".to_string(),
                publisher: Publisher {
                    address: "0x0000000000000000000000000000000000000000".to_string(),
                    display_name: "Hivemind".to_string(),
                    publisher_profile_ref: None,
                },
                capabilities: vec!["embedding".to_string()],
                artifact_groups: vec![ArtifactGroup {
                    id: "local".to_string(),
                    target: "local-mock".to_string(),
                    engine: "rust-mock".to_string(),
                    format: "json".to_string(),
                    paths: vec!["model/config.json".to_string()],
                    total_bytes: 1,
                    sha256: "0".repeat(64),
                    minimum: ArtifactMinimum {
                        memory_mb: Some(1),
                        webgpu: Some(false),
                        disk_mb: None,
                    },
                }],
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                permissions: Vec::new(),
                license: LicenseInfo {
                    license_type: LicenseType::Open,
                    name: Some("Apache-2.0".to_string()),
                    url: None,
                },
            },
            manifest_hash: "0".repeat(64),
            package_ref: package_ref.to_string(),
        }
    }

    fn package_with_license(
        package_id: &str,
        name: &str,
        package_ref: &str,
        license_type: LicenseType,
    ) -> LocalPackage {
        let mut package = package(package_ref);
        package.manifest.package_id = package_id.to_string();
        package.manifest.name = name.to_string();
        package.manifest.license.license_type = license_type;
        package
    }

    fn registry_query() -> RegistryQueryV1 {
        RegistryQueryV1 {
            schema_version: "swarm-ai.registry.query.v1".to_string(),
            kind: None,
            capability: None,
            target: None,
            engine: None,
            license_type: None,
            min_validator_score: None,
            min_benchmark_score: None,
            page_size: 20,
            cursor: None,
            requester: None,
            requested_use: None,
            runner_id: None,
            access_grant: None,
            access_revocation_list: None,
        }
    }

    fn lookup_request(package_id: &str) -> RegistryPackageLookupRequestV1 {
        RegistryPackageLookupRequestV1 {
            schema_version: "swarm-ai.registry.package-lookup.request.v1".to_string(),
            package_id: Some(package_id.to_string()),
            package_ref: None,
            requester: None,
            requested_use: None,
            runner_id: None,
            access_grant: None,
            access_revocation_list: None,
        }
    }
}
