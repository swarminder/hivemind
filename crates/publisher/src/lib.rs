use chrono::{SecondsFormat, Utc};
use hivemind_core::{ValidationIssue, ValidationReport, canonicalize_json, hash_canonical_json};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_package::{LocalPackage, load_package_from_dir, validate_package_dir};
use hivemind_storage::{
    LocalDirectoryStorageProvider, StorageProvider, StorageTransferMetricsV1, UploadResponseV1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const DEV_SIGNATURE_PREFIX: &str = "dev-signature-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedUpdateV1 {
    pub channel: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicationStorageV1 {
    pub pinned: bool,
    #[serde(rename = "redundancyLevel")]
    pub redundancy_level: u8,
    #[serde(rename = "postageBatchId")]
    pub postage_batch_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicationRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    pub publisher: String,
    pub signature: String,
    #[serde(rename = "publishedAt")]
    pub published_at: String,
    #[serde(rename = "channelsUpdated")]
    pub channels_updated: Vec<FeedUpdateV1>,
    pub storage: PublicationStorageV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageSignatureV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub version: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    pub publisher: String,
    pub signature: String,
    #[serde(rename = "signedAt")]
    pub signed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicationVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicationRecordIndexEntryV1 {
    #[serde(rename = "publicationId")]
    pub publication_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    pub publisher: String,
    #[serde(rename = "publishedAt")]
    pub published_at: String,
    #[serde(rename = "channelsUpdated")]
    pub channels_updated: Vec<FeedUpdateV1>,
    pub storage: PublicationStorageV1,
    #[serde(rename = "publicationPath")]
    pub publication_path: String,
    pub verification: PublicationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicationRecordStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "publicationCount")]
    pub publication_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub publications: Vec<PublicationRecordIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicationRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "publicationId")]
    pub publication_id: String,
    #[serde(rename = "publicationPath")]
    pub publication_path: String,
    pub publication: PublicationRecordV1,
    pub verification: PublicationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedPointerV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub channel: String,
    pub version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    pub publisher: String,
    #[serde(rename = "publicationSignature")]
    pub publication_signature: String,
    #[serde(rename = "publicationRecord")]
    pub publication_record: PublicationRecordV1,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedPointerIndexEntryV1 {
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub channel: String,
    pub version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub publisher: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "feedPath")]
    pub feed_path: String,
    #[serde(rename = "feedVerification")]
    pub feed_verification: FeedVerificationV1,
    #[serde(rename = "publicationVerification")]
    pub publication_verification: PublicationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedPointerStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "feedCount")]
    pub feed_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub feeds: Vec<FeedPointerIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedPointerLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    #[serde(rename = "feedPath")]
    pub feed_path: String,
    pub resolution: FeedResolutionV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedUpdateResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub channel: String,
    pub pointer: FeedPointerV1,
    #[serde(rename = "feedPath")]
    pub feed_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedResolveRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub channel: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedResolutionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub pointer: FeedPointerV1,
    #[serde(rename = "feedVerification")]
    pub feed_verification: FeedVerificationV1,
    pub verification: PublicationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublishDryRun {
    pub validation: ValidationReport,
    #[serde(rename = "estimatedBytes")]
    pub estimated_bytes: u64,
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublishResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub validation: ValidationReport,
    pub upload: UploadResponseV1,
    #[serde(rename = "publicationRecord")]
    pub publication_record: PublicationRecordV1,
    #[serde(rename = "recordPath")]
    pub record_path: Option<String>,
    #[serde(rename = "feedUpdates", default)]
    pub feed_updates: Vec<FeedUpdateResultV1>,
}

pub fn dry_run_package(path: &Path) -> anyhow::Result<PublishDryRun> {
    let validation = validate_package_dir(path)?;
    let estimated_bytes = validation
        .manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .artifact_groups
                .iter()
                .map(|group| group.total_bytes)
                .sum()
        })
        .unwrap_or(0);
    let mut warnings = Vec::new();
    if estimated_bytes > 256 * 1024 * 1024 {
        warnings.push(issue(
            "$.artifactGroups",
            "Package artifacts are large for browser-first delivery",
        ));
    }
    Ok(PublishDryRun {
        validation,
        estimated_bytes,
        warnings,
    })
}

pub fn package_signature(package: &LocalPackage) -> PackageSignatureV1 {
    let mut signature = PackageSignatureV1 {
        schema_version: "swarm-ai.package-signature.v1".to_string(),
        package_id: package.manifest.package_id.clone(),
        version: package.manifest.version.clone(),
        manifest_hash: package.manifest_hash.clone(),
        publisher: package.manifest.publisher.address.clone(),
        signature: String::new(),
        signed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    signature.signature = dev_signature(
        "package-manifest",
        &signature.publisher,
        &json!({
            "packageId": signature.package_id,
            "version": signature.version,
            "manifestHash": signature.manifest_hash,
            "publisher": signature.publisher,
        }),
    );
    signature
}

pub fn create_unsigned_publication_record(package: &LocalPackage) -> PublicationRecordV1 {
    create_unsigned_publication_record_for_ref(
        package,
        package.package_ref.clone(),
        Vec::new(),
        PublicationStorageV1 {
            pinned: false,
            redundancy_level: 0,
            postage_batch_id: None,
        },
    )
}

pub fn create_signed_publication_record(package: &LocalPackage) -> PublicationRecordV1 {
    let mut record = create_unsigned_publication_record(package);
    sign_publication_record(&mut record);
    record
}

pub fn create_unsigned_publication_record_for_ref(
    package: &LocalPackage,
    package_ref: String,
    channels_updated: Vec<FeedUpdateV1>,
    storage: PublicationStorageV1,
) -> PublicationRecordV1 {
    PublicationRecordV1 {
        schema_version: "swarm-ai.publication.v1".to_string(),
        package_id: package.manifest.package_id.clone(),
        version: package.manifest.version.clone(),
        package_ref,
        manifest_hash: package.manifest_hash.clone(),
        publisher: package.manifest.publisher.address.clone(),
        signature: "unsigned-dev-publication".to_string(),
        published_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        channels_updated,
        storage,
    }
}

pub fn create_signed_publication_record_for_ref(
    package: &LocalPackage,
    package_ref: String,
    channels_updated: Vec<FeedUpdateV1>,
    storage: PublicationStorageV1,
) -> PublicationRecordV1 {
    let mut record =
        create_unsigned_publication_record_for_ref(package, package_ref, channels_updated, storage);
    sign_publication_record(&mut record);
    record
}

pub fn sign_publication_record(record: &mut PublicationRecordV1) {
    record.signature = expected_publication_signature(record);
}

pub fn sign_publication_record_with_identity(
    record: &mut PublicationRecordV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != record.publisher {
        anyhow::bail!(
            "identity subject {} does not match publication publisher {}",
            identity.subject,
            record.publisher
        );
    }
    let envelope =
        hivemind_identity::sign_value(identity, "publication", &publication_signing_value(record))?;
    record.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    Ok(envelope)
}

pub fn expected_publication_signature(record: &PublicationRecordV1) -> String {
    dev_signature(
        "publication",
        &record.publisher,
        &publication_signing_value(record),
    )
}

pub fn verify_publication_record(record: &PublicationRecordV1) -> PublicationVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if record.schema_version != "swarm-ai.publication.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.publication.v1",
        ));
    }
    if record.package_id.trim().is_empty() || !record.package_id.contains('/') {
        issues.push(issue(
            "$.packageId",
            "Package id must use publisher/name form",
        ));
    }
    if !record.package_ref.starts_with("bzz://") {
        issues.push(issue(
            "$.packageRef",
            "Publication packageRef must be bzz://",
        ));
    }
    if !is_sha256_hex(&record.manifest_hash) {
        issues.push(issue(
            "$.manifestHash",
            "Manifest hash must be a 64-character hex digest",
        ));
    }
    let mut expected_signature = expected_publication_signature(record);
    if record
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &record.signature,
            "publication",
            &publication_signing_value(record),
            Some(&record.publisher),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                publication_signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if record.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Publication signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production wallet signing",
        ));
    }
    PublicationVerificationV1 {
        schema_version: "swarm-ai.publication-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn publication_record_id(record: &PublicationRecordV1) -> String {
    format!(
        "publication-{}",
        hash_canonical_json(&canonicalize_json(&publication_signing_value(record)))
    )
}

pub fn read_publication_record(path: &Path) -> anyhow::Result<PublicationRecordV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse publication record JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn get_publication_record(
    record_dir: &Path,
    publication_id: &str,
) -> anyhow::Result<Option<PublicationRecordLookupV1>> {
    let publication_id = publication_id.trim();
    if publication_id.is_empty() {
        anyhow::bail!("publicationId is required");
    }
    if !record_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(record_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let record = read_publication_record(&path)?;
            if publication_record_id(&record) == publication_id {
                return Ok(Some(publication_record_lookup(record, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_publication_records(
    record_dir: &Path,
) -> anyhow::Result<PublicationRecordStoreSummaryV1> {
    let mut publications = Vec::new();
    if record_dir.exists() {
        for entry in fs::read_dir(record_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let record = read_publication_record(&path)?;
                publications.push(publication_record_index_entry(
                    &record,
                    path.display().to_string(),
                ));
            }
        }
    }
    publications.sort_by(|left, right| {
        left.package_id
            .cmp(&right.package_id)
            .then(left.version.cmp(&right.version))
            .then(left.published_at.cmp(&right.published_at))
            .then(left.publication_id.cmp(&right.publication_id))
    });
    let valid_count = publications
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(PublicationRecordStoreSummaryV1 {
        schema_version: "swarm-ai.publication-record-store-summary.v1".to_string(),
        root: record_dir.display().to_string(),
        publication_count: publications.len(),
        valid_count,
        invalid_count: publications.len().saturating_sub(valid_count),
        publications,
    })
}

pub fn verify_feed_pointer(pointer: &FeedPointerV1) -> FeedVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if pointer.schema_version != "swarm-ai.feed-pointer.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.feed-pointer.v1",
        ));
    }
    if pointer.package_id.trim().is_empty() || !pointer.package_id.contains('/') {
        issues.push(issue(
            "$.packageId",
            "Package id must use publisher/name form",
        ));
    }
    if pointer.channel.trim().is_empty() {
        issues.push(issue("$.channel", "Feed channel is required"));
    }
    if pointer.package_id != pointer.publication_record.package_id {
        issues.push(issue(
            "$.publicationRecord.packageId",
            "Feed pointer packageId must match publicationRecord.packageId",
        ));
    }
    if pointer.version != pointer.publication_record.version {
        issues.push(issue(
            "$.publicationRecord.version",
            "Feed pointer version must match publicationRecord.version",
        ));
    }
    if pointer.package_ref != pointer.publication_record.package_ref {
        issues.push(issue(
            "$.publicationRecord.packageRef",
            "Feed pointer packageRef must match publicationRecord.packageRef",
        ));
    }
    if pointer.manifest_hash != pointer.publication_record.manifest_hash {
        issues.push(issue(
            "$.publicationRecord.manifestHash",
            "Feed pointer manifestHash must match publicationRecord.manifestHash",
        ));
    }
    if pointer.publisher != pointer.publication_record.publisher {
        issues.push(issue(
            "$.publicationRecord.publisher",
            "Feed pointer publisher must match publicationRecord.publisher",
        ));
    }
    if pointer.publication_signature != pointer.publication_record.signature {
        issues.push(issue(
            "$.publicationSignature",
            "Feed pointer publicationSignature must match publicationRecord.signature",
        ));
    }
    let expected_signature = expected_feed_signature(pointer);
    if pointer.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Feed pointer signature does not match canonical dev signature",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production wallet signing",
        ));
    }
    FeedVerificationV1 {
        schema_version: "swarm-ai.feed-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn publish_package_to_local_storage(
    package_path: &Path,
    storage: &mut LocalDirectoryStorageProvider,
    record_dir: Option<&Path>,
    channel: &str,
) -> anyhow::Result<PublishResultV1> {
    publish_package(package_path, storage, record_dir, channel)
}

pub fn publish_package(
    package_path: &Path,
    storage: &mut impl StorageProvider,
    record_dir: Option<&Path>,
    channel: &str,
) -> anyhow::Result<PublishResultV1> {
    let validation = validate_package_dir(package_path)?;
    if !validation.valid {
        return Ok(PublishResultV1 {
            schema_version: "swarm-ai.publish-result.v1".to_string(),
            validation,
            upload: UploadResponseV1 {
                schema_version: "swarm-ai.storage.upload.v1".to_string(),
                reference: String::new(),
                size_bytes: 0,
                pinned: false,
                redundancy_level: 0,
                postage_batch_id: None,
                metrics: empty_storage_metrics(),
            },
            publication_record: empty_publication_record(),
            record_path: None,
            feed_updates: Vec::new(),
        });
    }

    let package = load_package_from_dir(package_path)?;
    let upload = storage
        .upload_directory(package_path)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let channels_updated = channels(channel)
        .into_iter()
        .map(|channel| FeedUpdateV1 {
            feed_ref: feed_ref(&package.manifest.package_id, &channel),
            channel,
        })
        .collect();
    let publication_record = create_signed_publication_record_for_ref(
        &package,
        upload.reference.clone(),
        channels_updated,
        PublicationStorageV1 {
            pinned: upload.pinned,
            redundancy_level: upload.redundancy_level,
            postage_batch_id: upload.postage_batch_id.clone(),
        },
    );
    let record_path = if let Some(record_dir) = record_dir {
        Some(write_publication_record(record_dir, &publication_record)?)
    } else {
        None
    };

    Ok(PublishResultV1 {
        schema_version: "swarm-ai.publish-result.v1".to_string(),
        validation,
        upload,
        publication_record,
        record_path: record_path.map(|path| path.display().to_string()),
        feed_updates: Vec::new(),
    })
}

fn empty_storage_metrics() -> StorageTransferMetricsV1 {
    StorageTransferMetricsV1 {
        schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
        resolve_ms: 0,
        first_byte_ms: 0,
        total_ms: 0,
        size_bytes: 0,
        retry_count: 0,
    }
}

pub fn write_publication_record(
    record_dir: &Path,
    record: &PublicationRecordV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(record_dir)?;
    let file_name = format!(
        "{}-{}.publication.json",
        safe_file_component(&record.package_id),
        safe_file_component(&record.version)
    );
    let path = record_dir.join(file_name);
    let bytes = serde_json::to_vec_pretty(record)?;
    fs::write(&path, bytes)?;
    Ok(path)
}

pub fn write_feed_updates(
    feed_dir: &Path,
    record: &PublicationRecordV1,
) -> anyhow::Result<Vec<FeedUpdateResultV1>> {
    let mut results = Vec::new();
    for update in &record.channels_updated {
        results.push(write_feed_update(feed_dir, record, &update.channel)?);
    }
    Ok(results)
}

pub fn write_feed_update(
    feed_dir: &Path,
    record: &PublicationRecordV1,
    channel: &str,
) -> anyhow::Result<FeedUpdateResultV1> {
    let pointer = feed_pointer_from_record(record, channel);
    let path = feed_path(feed_dir, &record.package_id, channel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(&pointer)?)?;
    Ok(FeedUpdateResultV1 {
        schema_version: "swarm-ai.feed-update-result.v1".to_string(),
        feed_ref: feed_ref(&record.package_id, channel),
        channel: channel.to_string(),
        pointer,
        feed_path: path.display().to_string(),
    })
}

pub fn read_feed_pointer(path: &Path) -> anyhow::Result<FeedPointerV1> {
    let bytes = fs::read(path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!("failed to parse feed pointer {}: {error}", path.display())
    })
}

pub fn get_feed_pointer(
    feed_dir: &Path,
    package_id: &str,
    channel: &str,
) -> anyhow::Result<Option<FeedPointerLookupV1>> {
    let package_id = package_id.trim();
    let channel = channel.trim();
    if package_id.is_empty() {
        anyhow::bail!("packageId is required");
    }
    if channel.is_empty() {
        anyhow::bail!("channel is required");
    }
    let path = feed_path(feed_dir, package_id, channel);
    if !path.exists() {
        return Ok(None);
    }
    let pointer = read_feed_pointer(&path)?;
    if pointer.package_id != package_id || pointer.channel != channel {
        return Ok(None);
    }
    Ok(Some(feed_pointer_lookup(pointer, path)))
}

pub fn list_feed_pointers(feed_dir: &Path) -> anyhow::Result<FeedPointerStoreSummaryV1> {
    let mut feeds = Vec::new();
    if feed_dir.exists() {
        let mut paths = Vec::new();
        collect_json_files(feed_dir, &mut paths)?;
        for path in paths {
            let pointer = read_feed_pointer(&path)?;
            feeds.push(feed_pointer_index_entry(
                &pointer,
                path.display().to_string(),
            ));
        }
    }
    feeds.sort_by(|left, right| {
        left.package_id
            .cmp(&right.package_id)
            .then(left.channel.cmp(&right.channel))
            .then(left.version.cmp(&right.version))
            .then(left.feed_ref.cmp(&right.feed_ref))
    });
    let valid_count = feeds
        .iter()
        .filter(|entry| entry.feed_verification.valid && entry.publication_verification.valid)
        .count();
    Ok(FeedPointerStoreSummaryV1 {
        schema_version: "swarm-ai.feed-pointer-store-summary.v1".to_string(),
        root: feed_dir.display().to_string(),
        feed_count: feeds.len(),
        valid_count,
        invalid_count: feeds.len().saturating_sub(valid_count),
        feeds,
    })
}

pub fn resolve_feed(
    feed_dir: &Path,
    package_id: &str,
    channel: &str,
) -> anyhow::Result<FeedResolutionV1> {
    let path = feed_path(feed_dir, package_id, channel);
    let pointer = read_feed_pointer(&path)?;
    Ok(feed_resolution_from_pointer(pointer))
}

fn feed_resolution_from_pointer(pointer: FeedPointerV1) -> FeedResolutionV1 {
    let record = pointer.publication_record.clone();
    let feed_verification = verify_feed_pointer(&pointer);
    let publication_verification = verify_publication_record(&record);
    let valid = feed_verification.valid && publication_verification.valid;
    FeedResolutionV1 {
        schema_version: "swarm-ai.feed-resolution.v1".to_string(),
        valid,
        feed_ref: feed_ref(&pointer.package_id, &pointer.channel),
        pointer,
        feed_verification,
        verification: publication_verification,
    }
}

pub fn feed_pointer_from_record(record: &PublicationRecordV1, channel: &str) -> FeedPointerV1 {
    let mut pointer = FeedPointerV1 {
        schema_version: "swarm-ai.feed-pointer.v1".to_string(),
        package_id: record.package_id.clone(),
        channel: channel.to_string(),
        version: record.version.clone(),
        package_ref: record.package_ref.clone(),
        manifest_hash: record.manifest_hash.clone(),
        publisher: record.publisher.clone(),
        publication_signature: record.signature.clone(),
        publication_record: record.clone(),
        updated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: String::new(),
    };
    pointer.signature = expected_feed_signature(&pointer);
    pointer
}

pub fn expected_feed_signature(pointer: &FeedPointerV1) -> String {
    dev_signature(
        "feed-pointer",
        &pointer.publisher,
        &feed_signing_value(pointer),
    )
}

pub fn feed_ref(package_id: &str, channel: &str) -> String {
    format!("local://feed/{package_id}/{channel}")
}

fn publication_signing_value(record: &PublicationRecordV1) -> Value {
    json!({
        "schemaVersion": record.schema_version,
        "packageId": record.package_id,
        "version": record.version,
        "packageRef": record.package_ref,
        "manifestHash": record.manifest_hash,
        "publisher": record.publisher,
        "publishedAt": record.published_at,
        "channelsUpdated": record.channels_updated,
        "storage": record.storage,
    })
}

fn feed_signing_value(pointer: &FeedPointerV1) -> Value {
    json!({
        "schemaVersion": pointer.schema_version,
        "packageId": pointer.package_id,
        "channel": pointer.channel,
        "version": pointer.version,
        "packageRef": pointer.package_ref,
        "manifestHash": pointer.manifest_hash,
        "publisher": pointer.publisher,
        "publicationSignature": pointer.publication_signature,
        "publicationRecord": pointer.publication_record,
        "updatedAt": pointer.updated_at,
    })
}

fn dev_signature(label: &str, publisher: &str, payload: &Value) -> String {
    let value = json!({
        "label": label,
        "publisher": publisher,
        "payload": payload,
    });
    format!(
        "{DEV_SIGNATURE_PREFIX}:{label}:{}",
        hash_canonical_json(&canonicalize_json(&value))
    )
}

fn publication_signature_issue_path(path: &str) -> String {
    if path == "$" {
        return "$.signature".to_string();
    }
    if let Some(rest) = path.strip_prefix("$.") {
        return format!("$.signature.{rest}");
    }
    format!("$.signature.{path}")
}

fn publication_record_index_entry(
    record: &PublicationRecordV1,
    publication_path: String,
) -> PublicationRecordIndexEntryV1 {
    let verification = verify_publication_record(record);
    PublicationRecordIndexEntryV1 {
        publication_id: publication_record_id(record),
        package_id: record.package_id.clone(),
        version: record.version.clone(),
        package_ref: record.package_ref.clone(),
        manifest_hash: record.manifest_hash.clone(),
        publisher: record.publisher.clone(),
        published_at: record.published_at.clone(),
        channels_updated: record.channels_updated.clone(),
        storage: record.storage.clone(),
        publication_path,
        verification,
    }
}

fn publication_record_lookup(
    record: PublicationRecordV1,
    path: PathBuf,
) -> PublicationRecordLookupV1 {
    let verification = verify_publication_record(&record);
    PublicationRecordLookupV1 {
        schema_version: "swarm-ai.publication-record-lookup.v1".to_string(),
        publication_id: publication_record_id(&record),
        publication_path: path.display().to_string(),
        publication: record,
        verification,
    }
}

fn feed_pointer_index_entry(pointer: &FeedPointerV1, feed_path: String) -> FeedPointerIndexEntryV1 {
    let feed_verification = verify_feed_pointer(pointer);
    let publication_verification = verify_publication_record(&pointer.publication_record);
    FeedPointerIndexEntryV1 {
        feed_ref: feed_ref(&pointer.package_id, &pointer.channel),
        package_id: pointer.package_id.clone(),
        channel: pointer.channel.clone(),
        version: pointer.version.clone(),
        package_ref: pointer.package_ref.clone(),
        publisher: pointer.publisher.clone(),
        updated_at: pointer.updated_at.clone(),
        feed_path,
        feed_verification,
        publication_verification,
    }
}

fn feed_pointer_lookup(pointer: FeedPointerV1, path: PathBuf) -> FeedPointerLookupV1 {
    let feed_ref = feed_ref(&pointer.package_id, &pointer.channel);
    FeedPointerLookupV1 {
        schema_version: "swarm-ai.feed-pointer-lookup.v1".to_string(),
        feed_ref,
        feed_path: path.display().to_string(),
        resolution: feed_resolution_from_pointer(pointer),
    }
}

fn collect_json_files(dir: &Path, paths: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
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

fn channels(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|channel| !channel.is_empty())
        .map(str::to_string)
        .collect()
}

fn feed_path(feed_dir: &Path, package_id: &str, channel: &str) -> PathBuf {
    feed_dir
        .join(safe_file_component(package_id))
        .join(format!("{}.json", safe_file_component(channel)))
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

fn empty_publication_record() -> PublicationRecordV1 {
    PublicationRecordV1 {
        schema_version: "swarm-ai.publication.v1".to_string(),
        package_id: String::new(),
        version: String::new(),
        package_ref: String::new(),
        manifest_hash: String::new(),
        publisher: String::new(),
        signature: "unsigned-dev-publication".to_string(),
        published_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        channels_updated: Vec::new(),
        storage: PublicationStorageV1 {
            pinned: false,
            redundancy_level: 0,
            postage_batch_id: None,
        },
    }
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, PackageManifestV1,
        Publisher,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn signs_and_verifies_publication_record() {
        let package = package();
        let record = create_signed_publication_record(&package);

        let verification = verify_publication_record(&record);

        assert!(
            record
                .signature
                .starts_with("dev-signature-v1:publication:")
        );
        assert!(verification.valid);
    }

    #[test]
    fn rejects_tampered_publication_record() {
        let package = package();
        let mut record = create_signed_publication_record(&package);
        record.package_ref = "bzz://other".to_string();

        let verification = verify_publication_record(&record);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
    }

    #[test]
    fn signs_and_verifies_publication_record_with_identity() {
        let package = package();
        let mut record = create_unsigned_publication_record(&package);
        let identity =
            hivemind_identity::identity_from_seed(&record.publisher, b"publisher-test").unwrap();

        let envelope = sign_publication_record_with_identity(&mut record, &identity).unwrap();
        let verification = verify_publication_record(&record);

        assert_eq!(envelope.signer, record.publisher);
        assert!(
            record
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{:?}", verification.issues);
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
        assert!(verification.warnings.is_empty());
    }

    #[test]
    fn rejects_tampered_identity_signed_publication_record() {
        let package = package();
        let mut record = create_unsigned_publication_record(&package);
        let identity =
            hivemind_identity::identity_from_seed(&record.publisher, b"publisher-test").unwrap();
        sign_publication_record_with_identity(&mut record, &identity).unwrap();
        record.package_ref = "bzz://other".to_string();

        let verification = verify_publication_record(&record);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn writes_and_resolves_feed_pointer() {
        let root = std::env::temp_dir().join(format!(
            "hivemind-publisher-feed-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let mut record = create_signed_publication_record(&package());
        record.channels_updated = vec![FeedUpdateV1 {
            channel: "stable".to_string(),
            feed_ref: feed_ref(&record.package_id, "stable"),
        }];
        sign_publication_record(&mut record);

        let updates = write_feed_updates(&root, &record).unwrap();
        let resolution = resolve_feed(&root, &record.package_id, "stable").unwrap();
        let summary = list_feed_pointers(&root).unwrap();
        let lookup = get_feed_pointer(&root, &record.package_id, "stable")
            .unwrap()
            .unwrap();
        let missing = get_feed_pointer(&root, &record.package_id, "missing").unwrap();

        assert_eq!(updates.len(), 1);
        assert_eq!(resolution.pointer.package_ref, record.package_ref);
        assert!(
            resolution
                .pointer
                .signature
                .starts_with("dev-signature-v1:feed-pointer:")
        );
        assert!(resolution.feed_verification.valid);
        assert!(resolution.verification.valid);
        assert!(resolution.valid);
        assert_eq!(summary.feed_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(
            summary.feeds[0].feed_ref,
            feed_ref(&record.package_id, "stable")
        );
        assert_eq!(lookup.resolution.pointer.package_ref, record.package_ref);
        assert!(lookup.resolution.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn publication_record_store_lists_and_gets_records() {
        let root = unique_temp_dir("hivemind-publisher-record-store-test");
        let record = create_signed_publication_record(&package());
        let publication_id = publication_record_id(&record);

        let record_path = write_publication_record(&root, &record).unwrap();
        let summary = list_publication_records(&root).unwrap();
        let lookup = get_publication_record(&root, &publication_id)
            .unwrap()
            .unwrap();
        let missing = get_publication_record(&root, "missing-publication").unwrap();

        assert_eq!(summary.publication_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.publications[0].publication_id, publication_id);
        assert_eq!(
            summary.publications[0].publication_path,
            record_path.display().to_string()
        );
        assert_eq!(lookup.publication.package_ref, record.package_ref);
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn package() -> LocalPackage {
        LocalPackage {
            root: PathBuf::new(),
            manifest: PackageManifestV1 {
                schema_version: "swarm-ai.package.v1".to_string(),
                package_id: "hivemind/publisher-test".to_string(),
                kind: PackageKind::Model,
                name: "Publisher Test".to_string(),
                version: "0.1.0".to_string(),
                publisher: Publisher {
                    address: "0x0000000000000000000000000000000000000000".to_string(),
                    display_name: "Publisher".to_string(),
                    publisher_profile_ref: None,
                },
                capabilities: vec!["embedding".to_string()],
                artifact_groups: vec![ArtifactGroup {
                    id: "local".to_string(),
                    target: "local-mock".to_string(),
                    engine: "rust-mock".to_string(),
                    format: "json".to_string(),
                    paths: vec!["model/config.json".to_string()],
                    total_bytes: 512,
                    sha256: "0".repeat(64),
                    minimum: ArtifactMinimum {
                        memory_mb: Some(128),
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
            package_ref: "bzz://pkg".to_string(),
        }
    }
}
