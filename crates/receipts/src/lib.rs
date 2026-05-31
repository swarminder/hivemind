pub use hivemind_core::{
    ExecutionReceiptV1, ReceiptDraft, canonical_receipt_id, create_signed_receipt,
    create_unsigned_receipt, expected_receipt_signature, policy_decision_id,
    receipt_policy_evidence, sign_receipt,
};

use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{ExecutionResponseV1, hash_canonical_json};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_storage::{StorageProvider, UploadResponseV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const DEV_DISPUTE_SIGNATURE_PREFIX: &str = "dev-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptVerificationIssueV1 {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptIndexEntryV1 {
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "routeId", default)]
    pub route_id: Option<String>,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
    #[serde(rename = "licenseGrantId", default)]
    pub license_grant_id: Option<String>,
    #[serde(rename = "receiptPath", default)]
    pub receipt_path: Option<String>,
    #[serde(rename = "verification")]
    pub verification: ReceiptVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "receiptCount")]
    pub receipt_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub receipts: Vec<ReceiptIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptCaptureResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receipt")]
    pub receipt: ExecutionReceiptV1,
    #[serde(rename = "verification")]
    pub verification: ReceiptVerificationV1,
    #[serde(rename = "receiptPath")]
    pub receipt_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptLookupResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "receiptPath")]
    pub receipt_path: String,
    pub receipt: ExecutionReceiptV1,
    pub verification: ReceiptVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptStorageObjectV1 {
    #[serde(rename = "receiptRef")]
    pub receipt_ref: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptUploadResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "receiptRef")]
    pub receipt_ref: String,
    pub storage: ReceiptStorageObjectV1,
    pub upload: UploadResponseV1,
    pub verification: ReceiptVerificationV1,
    #[serde(rename = "uploadedAt")]
    pub uploaded_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptDownloadResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptRef")]
    pub receipt_ref: String,
    pub storage: ReceiptStorageObjectV1,
    pub receipt: ExecutionReceiptV1,
    pub verification: ReceiptVerificationV1,
    #[serde(rename = "downloadedAt")]
    pub downloaded_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DisputeClaimKind {
    OutputMismatch,
    IncorrectBilling,
    AccessViolation,
    PolicyViolation,
    RunnerFailure,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub claimant: String,
    #[serde(rename = "claimKind")]
    pub claim_kind: DisputeClaimKind,
    pub summary: String,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "evidenceRefs")]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub receipt: ExecutionReceiptV1,
    #[serde(rename = "receiptVerification")]
    pub receipt_verification: ReceiptVerificationV1,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceIndexEntryV1 {
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub claimant: String,
    #[serde(rename = "claimKind")]
    pub claim_kind: DisputeClaimKind,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "evidenceRefCount")]
    pub evidence_ref_count: usize,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "disputePath")]
    pub dispute_path: String,
    pub verification: DisputeEvidenceVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "disputeCount")]
    pub dispute_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub disputes: Vec<DisputeEvidenceIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceLookupResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "disputePath")]
    pub dispute_path: String,
    pub evidence: DisputeEvidenceV1,
    pub verification: DisputeEvidenceVerificationV1,
}

pub fn receipt_from_response(response: &ExecutionResponseV1) -> Option<ExecutionReceiptV1> {
    serde_json::from_value(response.metadata.get("receipt")?.clone()).ok()
}

pub fn receipt_id_matches(receipt: &ExecutionReceiptV1) -> bool {
    canonical_receipt_id(receipt)
        .map(|id| id == receipt.receipt_id)
        .unwrap_or(false)
}

pub fn sign_receipt_with_identity(
    receipt: &mut ExecutionReceiptV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != receipt.runner_id {
        anyhow::bail!(
            "identity subject {} does not match receipt runner {}",
            identity.subject,
            receipt.runner_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "execution-receipt",
        &receipt_signing_value(receipt),
    )?;
    receipt.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    receipt.receipt_id = canonical_receipt_id(receipt)?;
    Ok(envelope)
}

pub fn verify_receipt(receipt: &ExecutionReceiptV1) -> ReceiptVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if receipt.schema_version != "swarm-ai.receipt.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.receipt.v1",
        ));
    }
    if receipt.receipt_id.trim().is_empty() {
        issues.push(issue("$.receiptId", "Receipt id is required"));
    } else if !receipt_id_matches(receipt) {
        issues.push(issue(
            "$.receiptId",
            "Receipt id does not match canonical receipt hash",
        ));
    }
    for (path, value, message) in [
        (
            "$.requestId",
            receipt.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.packageId",
            receipt.package_id.as_str(),
            "Package id is required",
        ),
        (
            "$.packageRef",
            receipt.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.artifactGroup",
            receipt.artifact_group.as_str(),
            "Artifact group is required",
        ),
        (
            "$.packageManifestHash",
            receipt.package_manifest_hash.as_str(),
            "Package manifest hash is required",
        ),
        (
            "$.runnerId",
            receipt.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.inputHash",
            receipt.input_hash.as_str(),
            "Input hash is required",
        ),
        (
            "$.outputHash",
            receipt.output_hash.as_str(),
            "Output hash is required",
        ),
        (
            "$.signature",
            receipt.signature.as_str(),
            "Signature is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if !receipt.package_ref.starts_with("bzz://") {
        warnings.push(issue(
            "$.packageRef",
            "Receipt packageRef is not a Swarm bzz:// reference",
        ));
    }
    if !is_sha256_hex(&receipt.package_manifest_hash) {
        issues.push(issue(
            "$.packageManifestHash",
            "Package manifest hash must be a 64-character hex digest",
        ));
    }
    if !is_sha256_hex(&receipt.input_hash) {
        issues.push(issue(
            "$.inputHash",
            "Input hash must be a 64-character hex digest",
        ));
    }
    if !is_sha256_hex(&receipt.output_hash) {
        issues.push(issue(
            "$.outputHash",
            "Output hash must be a 64-character hex digest",
        ));
    }
    if !matches!(
        receipt.privacy_mode.as_str(),
        "hash-only" | "encrypted-evidence" | "public-evidence"
    ) {
        issues.push(issue(
            "$.privacyMode",
            "Privacy mode must be hash-only, encrypted-evidence, or public-evidence",
        ));
    }
    if receipt.privacy_mode == "hash-only" {
        warnings.push(issue(
            "$.privacyMode",
            "Hash-only receipt stores no raw private input or output",
        ));
    }
    if let Some(policy) = &receipt.policy {
        let expected_policy_id = policy_decision_id(&policy.policy_decision);
        if policy.policy_decision_id != expected_policy_id {
            issues.push(issue(
                "$.policy.policyDecisionId",
                "Policy decision id does not match canonical policy decision hash",
            ));
        }
        if policy.policy_decision.package_id != receipt.package_id {
            issues.push(issue(
                "$.policy.policyDecision.packageId",
                "Policy decision packageId must match receipt packageId",
            ));
        }
        if policy.policy_decision.package_ref != receipt.package_ref {
            issues.push(issue(
                "$.policy.policyDecision.packageRef",
                "Policy decision packageRef must match receipt packageRef",
            ));
        }
        if let Some(policy_runner) = &policy.policy_decision.runner_id
            && policy_runner != &receipt.runner_id
        {
            issues.push(issue(
                "$.policy.policyDecision.runnerId",
                "Policy decision runnerId must match receipt runnerId",
            ));
        }
        if DateTime::parse_from_rfc3339(&policy.enforced_at).is_err() {
            issues.push(issue(
                "$.policy.enforcedAt",
                "Policy enforcement timestamp must be RFC3339",
            ));
        }
    }
    if let (Ok(started), Ok(finished)) = (
        DateTime::parse_from_rfc3339(&receipt.started_at),
        DateTime::parse_from_rfc3339(&receipt.finished_at),
    ) {
        if finished < started {
            issues.push(issue(
                "$.finishedAt",
                "Finished timestamp must not be earlier than startedAt",
            ));
        }
    } else {
        issues.push(issue(
            "$.startedAt",
            "startedAt and finishedAt must be RFC3339 timestamps",
        ));
    }
    let mut expected_signature = expected_receipt_signature(receipt);
    if receipt
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &receipt.signature,
            "execution-receipt",
            &receipt_signing_value(receipt),
            Some(&receipt.runner_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if receipt.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Receipt signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production runner signing",
        ));
    }

    ReceiptVerificationV1 {
        schema_version: "swarm-ai.receipt-verification.v1".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn index_entry(
    receipt: &ExecutionReceiptV1,
    receipt_path: Option<impl Into<String>>,
) -> ReceiptIndexEntryV1 {
    let verification = verify_receipt(receipt);
    ReceiptIndexEntryV1 {
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        package_id: receipt.package_id.clone(),
        package_ref: receipt.package_ref.clone(),
        runner_id: receipt.runner_id.clone(),
        route_id: receipt.route_id.clone(),
        privacy_mode: receipt.privacy_mode.clone(),
        started_at: receipt.started_at.clone(),
        finished_at: receipt.finished_at.clone(),
        total_ms: receipt.metrics.total_ms,
        estimated_cost: receipt.billing.estimated_cost,
        currency: receipt.billing.currency.clone(),
        license_grant_id: receipt.access.license_grant_id.clone(),
        receipt_path: receipt_path.map(Into::into),
        verification,
    }
}

pub fn read_receipt(path: &Path) -> anyhow::Result<ExecutionReceiptV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse receipt JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_receipt(receipts_dir: &Path, receipt: &ExecutionReceiptV1) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(receipts_dir)?;
    let path = receipts_dir.join(format!("{}.json", safe_file_component(&receipt.receipt_id)));
    fs::write(&path, serde_json::to_vec_pretty(receipt)?)?;
    Ok(path)
}

pub fn get_receipt(
    receipts_dir: &Path,
    receipt_id: &str,
) -> anyhow::Result<Option<ReceiptLookupResultV1>> {
    let receipt_id = receipt_id.trim();
    if receipt_id.is_empty() {
        anyhow::bail!("receiptId is required");
    }

    let direct_path = receipts_dir.join(format!("{}.json", safe_file_component(receipt_id)));
    if direct_path.exists() {
        let receipt = read_receipt(&direct_path)?;
        if receipt.receipt_id == receipt_id {
            return Ok(Some(receipt_lookup(receipt, direct_path)));
        }
    }

    if !receipts_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(receipts_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let receipt = read_receipt(&path)?;
            if receipt.receipt_id == receipt_id {
                return Ok(Some(receipt_lookup(receipt, path)));
            }
        }
    }
    Ok(None)
}

pub fn capture_response_receipt(
    receipts_dir: &Path,
    response: &ExecutionResponseV1,
) -> anyhow::Result<Option<ReceiptCaptureResultV1>> {
    let Some(receipt) = receipt_from_response(response) else {
        return Ok(None);
    };
    let verification = verify_receipt(&receipt);
    let path = write_receipt(receipts_dir, &receipt)?;
    Ok(Some(ReceiptCaptureResultV1 {
        schema_version: "swarm-ai.receipt-capture-result.v1".to_string(),
        receipt,
        verification,
        receipt_path: path.display().to_string(),
    }))
}

pub fn list_receipts(receipts_dir: &Path) -> anyhow::Result<ReceiptStoreSummaryV1> {
    let mut entries = Vec::new();
    if receipts_dir.exists() {
        for entry in fs::read_dir(receipts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let receipt = read_receipt(&path)?;
                entries.push(index_entry(&receipt, Some(path.display().to_string())));
            }
        }
    }
    entries.sort_by(|left, right| {
        left.started_at
            .cmp(&right.started_at)
            .then(left.receipt_id.cmp(&right.receipt_id))
    });
    let valid_count = entries
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(ReceiptStoreSummaryV1 {
        schema_version: "swarm-ai.receipt-store-summary.v1".to_string(),
        root: receipts_dir.display().to_string(),
        receipt_count: entries.len(),
        valid_count,
        invalid_count: entries.len().saturating_sub(valid_count),
        receipts: entries,
    })
}

fn receipt_lookup(receipt: ExecutionReceiptV1, path: PathBuf) -> ReceiptLookupResultV1 {
    let verification = verify_receipt(&receipt);
    ReceiptLookupResultV1 {
        schema_version: "swarm-ai.receipt-lookup.v1".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        receipt_path: path.display().to_string(),
        receipt,
        verification,
    }
}

fn dispute_index_entry(
    evidence: &DisputeEvidenceV1,
    dispute_path: String,
) -> DisputeEvidenceIndexEntryV1 {
    let verification = verify_dispute_evidence(evidence);
    DisputeEvidenceIndexEntryV1 {
        dispute_id: evidence.dispute_id.clone(),
        receipt_id: evidence.receipt_id.clone(),
        request_id: evidence.request_id.clone(),
        package_id: evidence.package_id.clone(),
        package_ref: evidence.package_ref.clone(),
        runner_id: evidence.runner_id.clone(),
        claimant: evidence.claimant.clone(),
        claim_kind: evidence.claim_kind.clone(),
        privacy_mode: evidence.privacy_mode.clone(),
        evidence_ref_count: evidence.evidence_refs.len(),
        created_at: evidence.created_at.clone(),
        dispute_path,
        verification,
    }
}

fn dispute_lookup(evidence: DisputeEvidenceV1, path: PathBuf) -> DisputeEvidenceLookupResultV1 {
    let verification = verify_dispute_evidence(&evidence);
    DisputeEvidenceLookupResultV1 {
        schema_version: "swarm-ai.dispute-evidence-lookup.v1".to_string(),
        dispute_id: evidence.dispute_id.clone(),
        dispute_path: path.display().to_string(),
        evidence,
        verification,
    }
}

pub fn upload_receipt(
    storage: &mut impl StorageProvider,
    receipt: &ExecutionReceiptV1,
) -> anyhow::Result<ReceiptUploadResultV1> {
    let verification = verify_receipt(receipt);
    if !verification.valid {
        anyhow::bail!("receipt is invalid and will not be uploaded");
    }
    let bytes = serde_json::to_vec_pretty(receipt)?;
    let sha256 = Some(hash_bytes(&bytes));
    let upload = storage
        .upload_bytes(bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let receipt_ref = upload.reference.clone();
    Ok(ReceiptUploadResultV1 {
        schema_version: "swarm-ai.receipt-upload.v1".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        receipt_ref: receipt_ref.clone(),
        storage: ReceiptStorageObjectV1 {
            receipt_ref,
            content_type: "application/json".to_string(),
            size_bytes: upload.size_bytes,
            sha256,
        },
        upload,
        verification,
        uploaded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn download_receipt(
    storage: &impl StorageProvider,
    receipt_ref: &str,
) -> anyhow::Result<ReceiptDownloadResultV1> {
    let download = storage
        .download_bytes(receipt_ref)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let receipt: ExecutionReceiptV1 = serde_json::from_slice(&download.bytes)?;
    let verification = verify_receipt(&receipt);
    Ok(ReceiptDownloadResultV1 {
        schema_version: "swarm-ai.receipt-download.v1".to_string(),
        receipt_ref: receipt_ref.to_string(),
        storage: ReceiptStorageObjectV1 {
            receipt_ref: download.reference,
            content_type: download.content_type,
            size_bytes: download.size_bytes,
            sha256: download.sha256,
        },
        receipt,
        verification,
        downloaded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn create_dispute_evidence(
    receipt: ExecutionReceiptV1,
    claimant: impl Into<String>,
    claim_kind: DisputeClaimKind,
    summary: impl Into<String>,
    evidence_refs: Vec<String>,
) -> DisputeEvidenceV1 {
    let receipt_verification = verify_receipt(&receipt);
    let mut evidence = DisputeEvidenceV1 {
        schema_version: "swarm-ai.receipt-dispute-evidence.v1".to_string(),
        dispute_id: String::new(),
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        package_id: receipt.package_id.clone(),
        package_ref: receipt.package_ref.clone(),
        runner_id: receipt.runner_id.clone(),
        claimant: claimant.into(),
        claim_kind,
        summary: summary.into(),
        privacy_mode: receipt.privacy_mode.clone(),
        evidence_refs,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        receipt,
        receipt_verification,
        signature: String::new(),
    };
    sign_dispute_evidence(&mut evidence);
    evidence.dispute_id =
        canonical_dispute_id(&evidence).expect("dispute evidence should serialize for id");
    evidence
}

pub fn sign_dispute_evidence(evidence: &mut DisputeEvidenceV1) {
    evidence.signature = expected_dispute_signature(evidence);
}

pub fn sign_dispute_evidence_with_identity(
    evidence: &mut DisputeEvidenceV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != evidence.claimant {
        anyhow::bail!(
            "identity subject {} does not match dispute claimant {}",
            identity.subject,
            evidence.claimant
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "receipt-dispute-evidence",
        &dispute_signing_value(evidence),
    )?;
    evidence.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    evidence.dispute_id = canonical_dispute_id(evidence)?;
    Ok(envelope)
}

pub fn expected_dispute_signature(evidence: &DisputeEvidenceV1) -> String {
    let value = json!({
        "label": "receipt-dispute-evidence",
        "claimant": evidence.claimant,
        "payload": dispute_signing_value(evidence),
    });
    format!(
        "{DEV_DISPUTE_SIGNATURE_PREFIX}:receipt-dispute-evidence:{}",
        hash_canonical_json(&value)
    )
}

pub fn canonical_dispute_id(evidence: &DisputeEvidenceV1) -> serde_json::Result<String> {
    let mut signed = evidence.clone();
    signed.dispute_id.clear();
    let value: Value = serde_json::to_value(signed)?;
    Ok(format!(
        "dispute-{}",
        hash_canonical_json(&value)
            .chars()
            .take(24)
            .collect::<String>()
    ))
}

pub fn verify_dispute_evidence(evidence: &DisputeEvidenceV1) -> DisputeEvidenceVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if evidence.schema_version != "swarm-ai.receipt-dispute-evidence.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.receipt-dispute-evidence.v1",
        ));
    }
    if evidence.dispute_id.trim().is_empty() {
        issues.push(issue("$.disputeId", "Dispute id is required"));
    } else {
        match canonical_dispute_id(evidence) {
            Ok(expected_id) if expected_id != evidence.dispute_id => issues.push(issue(
                "$.disputeId",
                "Dispute id does not match canonical dispute hash",
            )),
            Err(_) => issues.push(issue("$.disputeId", "Dispute id could not be recomputed")),
            _ => {}
        }
    }

    for (path, value, message) in [
        (
            "$.receiptId",
            evidence.receipt_id.as_str(),
            "Receipt id is required",
        ),
        (
            "$.requestId",
            evidence.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.packageId",
            evidence.package_id.as_str(),
            "Package id is required",
        ),
        (
            "$.packageRef",
            evidence.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.runnerId",
            evidence.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.claimant",
            evidence.claimant.as_str(),
            "Claimant is required",
        ),
        (
            "$.summary",
            evidence.summary.as_str(),
            "Summary is required",
        ),
        (
            "$.signature",
            evidence.signature.as_str(),
            "Signature is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }

    if evidence.receipt_id != evidence.receipt.receipt_id {
        issues.push(issue(
            "$.receiptId",
            "Dispute receiptId must match embedded receipt",
        ));
    }
    if evidence.request_id != evidence.receipt.request_id {
        issues.push(issue(
            "$.requestId",
            "Dispute requestId must match embedded receipt",
        ));
    }
    if evidence.package_id != evidence.receipt.package_id {
        issues.push(issue(
            "$.packageId",
            "Dispute packageId must match embedded receipt",
        ));
    }
    if evidence.package_ref != evidence.receipt.package_ref {
        issues.push(issue(
            "$.packageRef",
            "Dispute packageRef must match embedded receipt",
        ));
    }
    if evidence.runner_id != evidence.receipt.runner_id {
        issues.push(issue(
            "$.runnerId",
            "Dispute runnerId must match embedded receipt",
        ));
    }
    if evidence.privacy_mode != evidence.receipt.privacy_mode {
        issues.push(issue(
            "$.privacyMode",
            "Dispute privacyMode must match embedded receipt",
        ));
    }
    if DateTime::parse_from_rfc3339(&evidence.created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "Dispute createdAt must be an RFC3339 timestamp",
        ));
    }

    let receipt_verification = verify_receipt(&evidence.receipt);
    if !receipt_verification.valid {
        issues.push(issue("$.receipt", "Embedded receipt does not verify"));
    }
    if !evidence.receipt_verification.valid {
        issues.push(issue(
            "$.receiptVerification.valid",
            "Embedded receipt verification claims the receipt is invalid",
        ));
    }
    if evidence.receipt_verification.receipt_id != evidence.receipt_id {
        issues.push(issue(
            "$.receiptVerification.receiptId",
            "Embedded receipt verification receiptId must match dispute receiptId",
        ));
    }

    if evidence.evidence_refs.is_empty() {
        warnings.push(issue(
            "$.evidenceRefs",
            "Dispute has no external evidence references",
        ));
    }
    for (index, reference) in evidence.evidence_refs.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_evidence_ref(reference) {
            warnings.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized bzz://, local://, ipfs://, http(s)://, or file path reference",
            ));
        }
    }

    let mut expected_signature = expected_dispute_signature(evidence);
    if evidence
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &evidence.signature,
            "receipt-dispute-evidence",
            &dispute_signing_value(evidence),
            Some(&evidence.claimant),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if evidence.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Dispute evidence signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Dispute evidence uses deterministic local-dev signing",
        ));
    }

    DisputeEvidenceVerificationV1 {
        schema_version: "swarm-ai.receipt-dispute-verification.v1".to_string(),
        dispute_id: evidence.dispute_id.clone(),
        receipt_id: evidence.receipt_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_dispute_evidence(path: &Path) -> anyhow::Result<DisputeEvidenceV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse dispute evidence JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_dispute_evidence(
    disputes_dir: &Path,
    evidence: &DisputeEvidenceV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(disputes_dir)?;
    let path = disputes_dir.join(format!(
        "{}.json",
        safe_file_component(&evidence.dispute_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(evidence)?)?;
    Ok(path)
}

pub fn get_dispute_evidence(
    disputes_dir: &Path,
    dispute_id: &str,
) -> anyhow::Result<Option<DisputeEvidenceLookupResultV1>> {
    let dispute_id = dispute_id.trim();
    if dispute_id.is_empty() {
        anyhow::bail!("disputeId is required");
    }

    let direct_path = disputes_dir.join(format!("{}.json", safe_file_component(dispute_id)));
    if direct_path.exists() {
        let evidence = read_dispute_evidence(&direct_path)?;
        if evidence.dispute_id == dispute_id {
            return Ok(Some(dispute_lookup(evidence, direct_path)));
        }
    }

    if !disputes_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(disputes_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let evidence = read_dispute_evidence(&path)?;
            if evidence.dispute_id == dispute_id {
                return Ok(Some(dispute_lookup(evidence, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_dispute_evidence(disputes_dir: &Path) -> anyhow::Result<DisputeEvidenceStoreSummaryV1> {
    let mut disputes = Vec::new();
    if disputes_dir.exists() {
        for entry in fs::read_dir(disputes_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let evidence = read_dispute_evidence(&path)?;
                disputes.push(dispute_index_entry(&evidence, path.display().to_string()));
            }
        }
    }
    disputes.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.dispute_id.cmp(&right.dispute_id))
    });
    let valid_count = disputes
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(DisputeEvidenceStoreSummaryV1 {
        schema_version: "swarm-ai.dispute-evidence-store-summary.v1".to_string(),
        root: disputes_dir.display().to_string(),
        dispute_count: disputes.len(),
        valid_count,
        invalid_count: disputes.len().saturating_sub(valid_count),
        disputes,
    })
}

fn dispute_signing_value(evidence: &DisputeEvidenceV1) -> Value {
    json!({
        "schemaVersion": evidence.schema_version,
        "receiptId": evidence.receipt_id,
        "requestId": evidence.request_id,
        "packageId": evidence.package_id,
        "packageRef": evidence.package_ref,
        "runnerId": evidence.runner_id,
        "claimant": evidence.claimant,
        "claimKind": evidence.claim_kind,
        "summary": evidence.summary,
        "privacyMode": evidence.privacy_mode,
        "evidenceRefs": evidence.evidence_refs,
        "createdAt": evidence.created_at,
        "receipt": evidence.receipt,
        "receiptVerification": evidence.receipt_verification,
    })
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

fn signature_issue_path(path: &str) -> String {
    if path == "$" {
        return "$.signature".to_string();
    }
    if let Some(rest) = path.strip_prefix("$.") {
        return format!("$.signature.{rest}");
    }
    format!("$.signature.{path}")
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ReceiptVerificationIssueV1 {
    ReceiptVerificationIssueV1 {
        path: path.into(),
        message: message.into(),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
}

fn hash_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn looks_like_evidence_ref(value: &str) -> bool {
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("file:")
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

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ExecutionMetrics, PolicyDecision, PolicyDecisionV1,
        policy::RiskLevel,
        receipt::{AccessInfo, BillingInfo},
    };
    use hivemind_storage::MemoryStorageProvider;
    use serde_json::json;

    #[test]
    fn verifies_canonical_receipt_id() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let verification = verify_receipt(&receipt);

        assert!(verification.valid, "{verification:#?}");
    }

    #[test]
    fn identity_signed_receipt_verifies() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let identity =
            hivemind_identity::identity_from_seed(&receipt.runner_id, b"runner-seed").unwrap();

        let envelope = sign_receipt_with_identity(&mut receipt, &identity).unwrap();
        let verification = verify_receipt(&receipt);

        assert_eq!(envelope.signer, receipt.runner_id);
        assert!(
            receipt
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
        assert!(
            !verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_receipt() {
        let mut receipt = receipt();
        let identity =
            hivemind_identity::identity_from_seed(&receipt.runner_id, b"runner-seed").unwrap();
        sign_receipt_with_identity(&mut receipt, &identity).unwrap();
        receipt.output_hash = "1".repeat(64);

        let verification = verify_receipt(&receipt);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.receiptId"
                    || issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn rejects_modified_receipt_id() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        receipt.output_hash = "1".repeat(64);

        let verification = verify_receipt(&receipt);

        assert!(!verification.valid);
    }

    #[test]
    fn rejects_modified_receipt_signature() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        receipt.signature = "dev-signature-v1:execution-receipt:bad".to_string();

        let verification = verify_receipt(&receipt);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
    }

    #[test]
    fn verifies_embedded_policy_evidence() {
        let mut receipt = receipt();
        let policy = policy_decision(&receipt);
        receipt.policy = Some(receipt_policy_evidence(&policy, receipt.started_at.clone()));
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let verification = verify_receipt(&receipt);

        assert!(verification.valid, "{verification:#?}");

        let mut tampered = receipt;
        tampered.policy.as_mut().unwrap().policy_decision_id = "policy-bad".to_string();
        sign_receipt(&mut tampered);
        tampered.receipt_id = canonical_receipt_id(&tampered).unwrap();

        let verification = verify_receipt(&tampered);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.policy.policyDecisionId")
        );
    }

    #[test]
    fn creates_and_verifies_dispute_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::OutputMismatch,
            "Output did not match expected benchmark answer",
            vec!["bzz://evidence".to_string()],
        );

        let verification = verify_dispute_evidence(&evidence);

        assert!(verification.valid, "{verification:#?}");
        assert!(evidence.dispute_id.starts_with("dispute-"));
        assert_eq!(evidence.claim_kind, DisputeClaimKind::OutputMismatch);
    }

    #[test]
    fn identity_signed_dispute_evidence_verifies() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::OutputMismatch,
            "Output did not match expected benchmark answer",
            vec!["bzz://evidence".to_string()],
        );
        let identity =
            hivemind_identity::identity_from_seed("0xClaimant", b"claimant-seed").unwrap();

        let envelope = sign_dispute_evidence_with_identity(&mut evidence, &identity).unwrap();
        let verification = verify_dispute_evidence(&evidence);

        assert_eq!(envelope.signer, evidence.claimant);
        assert!(
            evidence
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
        assert!(
            !verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_dispute_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::IncorrectBilling,
            "Billing was higher than the quote",
            vec!["local://quote".to_string()],
        );
        let identity =
            hivemind_identity::identity_from_seed("0xClaimant", b"claimant-seed").unwrap();
        sign_dispute_evidence_with_identity(&mut evidence, &identity).unwrap();
        evidence.summary = "A different claim after signing".to_string();

        let verification = verify_dispute_evidence(&evidence);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.disputeId"
                    || issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn rejects_tampered_dispute_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::IncorrectBilling,
            "Billing was higher than the quote",
            vec!["local://quote".to_string()],
        );
        evidence.summary = "A different claim after signing".to_string();

        let verification = verify_dispute_evidence(&evidence);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.disputeId" || issue.path == "$.signature")
        );
    }

    #[test]
    fn uploads_and_downloads_verified_receipt() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut storage = MemoryStorageProvider::default();

        let upload = upload_receipt(&mut storage, &receipt).unwrap();
        let download = download_receipt(&storage, &upload.receipt_ref).unwrap();

        assert!(upload.verification.valid);
        assert!(download.verification.valid);
        assert_eq!(download.receipt.receipt_id, receipt.receipt_id);
        assert_eq!(download.storage.sha256, upload.storage.sha256);
    }

    #[test]
    fn gets_receipt_by_id_from_store() {
        let root = unique_temp_dir("hivemind-receipt-lookup-test");
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        write_receipt(&root, &receipt).unwrap();

        let lookup = get_receipt(&root, &receipt.receipt_id)
            .unwrap()
            .expect("receipt should be found");
        let missing = get_receipt(&root, "missing-receipt").unwrap();

        assert_eq!(lookup.receipt.receipt_id, receipt.receipt_id);
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lists_and_gets_dispute_evidence_from_store() {
        let root = unique_temp_dir("hivemind-dispute-lookup-test");
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::OutputMismatch,
            "Output did not match expected benchmark answer",
            vec!["bzz://evidence".to_string()],
        );
        let dispute_path = write_dispute_evidence(&root, &evidence).unwrap();

        let summary = list_dispute_evidence(&root).unwrap();
        let lookup = get_dispute_evidence(&root, &evidence.dispute_id)
            .unwrap()
            .expect("dispute should be found");
        let missing = get_dispute_evidence(&root, "missing-dispute").unwrap();

        assert_eq!(summary.dispute_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.disputes[0].dispute_id, evidence.dispute_id);
        assert_eq!(
            summary.disputes[0].dispute_path,
            dispute_path.display().to_string()
        );
        assert_eq!(lookup.evidence.dispute_id, evidence.dispute_id);
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    fn receipt() -> ExecutionReceiptV1 {
        ExecutionReceiptV1 {
            schema_version: "swarm-ai.receipt.v1".to_string(),
            receipt_id: String::new(),
            request_id: "request-1".to_string(),
            package_id: "hivemind/test".to_string(),
            package_ref: "bzz://pkg".to_string(),
            artifact_group: "local".to_string(),
            package_manifest_hash: "0".repeat(64),
            runner_id: "runner-1".to_string(),
            route_id: None,
            input_hash: "a".repeat(64),
            output_hash: "b".repeat(64),
            privacy_mode: "hash-only".to_string(),
            started_at: "2026-05-22T00:00:00Z".to_string(),
            finished_at: "2026-05-22T00:00:01Z".to_string(),
            metrics: ExecutionMetrics::default(),
            billing: BillingInfo {
                estimated_cost: 0.0,
                currency: "none".to_string(),
            },
            access: AccessInfo {
                license_grant_id: None,
            },
            policy: None,
            signature: String::new(),
        }
    }

    fn policy_decision(receipt: &ExecutionReceiptV1) -> PolicyDecisionV1 {
        PolicyDecisionV1 {
            schema_version: "swarm-ai.policy-decision.v1".to_string(),
            package_id: receipt.package_id.clone(),
            package_ref: receipt.package_ref.clone(),
            runner_id: Some(receipt.runner_id.clone()),
            decision: PolicyDecision::AllowWithRestrictions,
            reasons: vec!["test policy".to_string()],
            restrictions: json!({ "network": "blocked-except-allowlist" }),
            risk_level: RiskLevel::Medium,
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path
    }
}
