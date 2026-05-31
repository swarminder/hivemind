use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hivemind_core::canonicalize_json;
use rand_core::OsRng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ED25519_ALGORITHM: &str = "ed25519";
pub const COMPACT_SIGNATURE_PREFIX: &str = "ed25519:v1:";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityKeypairV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub subject: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: String,
    #[serde(rename = "publicKeyHex")]
    pub public_key_hex: String,
    #[serde(rename = "secretKeyHex")]
    pub secret_key_hex: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicIdentityV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub subject: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: String,
    #[serde(rename = "publicKeyHex")]
    pub public_key_hex: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SignatureEnvelopeV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub algorithm: String,
    pub signer: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub label: String,
    #[serde(rename = "publicKeyHex")]
    pub public_key_hex: String,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    #[serde(rename = "signatureHex")]
    pub signature_hex: String,
    #[serde(rename = "signedAt")]
    pub signed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SignatureIssueV1 {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SignatureVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<SignatureIssueV1>,
    pub signer: Option<String>,
    #[serde(rename = "keyId")]
    pub key_id: Option<String>,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("{field} is required")]
    Required { field: &'static str },
    #[error("unsupported signature format")]
    UnsupportedSignatureFormat,
    #[error("unsupported algorithm {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },
    #[error("invalid {field} hex: {message}")]
    InvalidHex {
        field: &'static str,
        message: String,
    },
    #[error("invalid {field} length: expected {expected} bytes, got {actual}")]
    InvalidByteLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid public key: {message}")]
    InvalidPublicKey { message: String },
    #[error("invalid signature: {message}")]
    InvalidSignature { message: String },
    #[error("identity public key does not match secret key")]
    PublicKeyMismatch,
    #[error("failed to encode signature envelope: {0}")]
    Encode(serde_json::Error),
    #[error("failed to decode signature envelope: {0}")]
    Decode(serde_json::Error),
}

pub fn generate_identity(subject: impl Into<String>) -> Result<IdentityKeypairV1, IdentityError> {
    let subject = normalize_required("subject", subject.into())?;
    let signing_key = SigningKey::generate(&mut OsRng);
    Ok(identity_from_signing_key(subject, signing_key))
}

pub fn identity_from_seed(
    subject: impl Into<String>,
    seed: &[u8],
) -> Result<IdentityKeypairV1, IdentityError> {
    let subject = normalize_required("subject", subject.into())?;
    if seed.is_empty() {
        return Err(IdentityError::Required { field: "seed" });
    }
    let digest = Sha256::digest(seed);
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&digest);
    Ok(identity_from_signing_key(
        subject,
        SigningKey::from_bytes(&secret_key),
    ))
}

pub fn public_identity(identity: &IdentityKeypairV1) -> PublicIdentityV1 {
    PublicIdentityV1 {
        schema_version: "swarm-ai.identity.public.v1".to_string(),
        subject: identity.subject.clone(),
        key_id: identity.key_id.clone(),
        algorithm: identity.algorithm.clone(),
        public_key_hex: identity.public_key_hex.clone(),
        created_at: identity.created_at.clone(),
    }
}

pub fn sign_value(
    identity: &IdentityKeypairV1,
    label: &str,
    payload: &Value,
) -> Result<SignatureEnvelopeV1, IdentityError> {
    if identity.algorithm != ED25519_ALGORITHM {
        return Err(IdentityError::UnsupportedAlgorithm {
            algorithm: identity.algorithm.clone(),
        });
    }
    let label = normalize_required("label", label.to_string())?;
    let secret_key = hex_to_array::<32>("secretKeyHex", &identity.secret_key_hex)?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    let derived_public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    if derived_public_key_hex != identity.public_key_hex {
        return Err(IdentityError::PublicKeyMismatch);
    }
    let payload_hash = signature_payload_hash_for_value(&label, payload);
    let mut envelope = SignatureEnvelopeV1 {
        schema_version: "swarm-ai.signature.ed25519.v1".to_string(),
        algorithm: ED25519_ALGORITHM.to_string(),
        signer: identity.subject.clone(),
        key_id: identity.key_id.clone(),
        label,
        public_key_hex: identity.public_key_hex.clone(),
        payload_hash,
        signature_hex: String::new(),
        signed_at: timestamp(),
    };
    let signature = signing_key.sign(&canonical_signature_input_bytes(&envelope));
    envelope.signature_hex = hex::encode(signature.to_bytes());
    Ok(envelope)
}

pub fn signature_payload_hash_for_value(label: &str, payload: &Value) -> String {
    let signing_bytes = canonical_signature_payload_bytes(label, payload);
    hash_bytes(&signing_bytes)
}

pub fn encode_signature_envelope(envelope: &SignatureEnvelopeV1) -> Result<String, IdentityError> {
    let bytes = serde_json::to_vec(envelope).map_err(IdentityError::Encode)?;
    Ok(format!("{COMPACT_SIGNATURE_PREFIX}{}", hex::encode(bytes)))
}

pub fn decode_signature_envelope(compact: &str) -> Result<SignatureEnvelopeV1, IdentityError> {
    let Some(encoded) = compact.strip_prefix(COMPACT_SIGNATURE_PREFIX) else {
        return Err(IdentityError::UnsupportedSignatureFormat);
    };
    let bytes = hex::decode(encoded).map_err(|error| IdentityError::InvalidHex {
        field: "signature",
        message: error.to_string(),
    })?;
    let envelope: SignatureEnvelopeV1 =
        serde_json::from_slice(&bytes).map_err(IdentityError::Decode)?;
    Ok(envelope)
}

pub fn verify_value_signature_string(
    compact: &str,
    expected_label: &str,
    payload: &Value,
    expected_signer: Option<&str>,
) -> SignatureVerificationV1 {
    match decode_signature_envelope(compact) {
        Ok(envelope) => verify_value_signature(&envelope, expected_label, payload, expected_signer),
        Err(error) => invalid_verification(
            expected_label,
            payload,
            vec![signature_issue("$", error.to_string())],
            None,
            None,
        ),
    }
}

pub fn verify_value_signature(
    envelope: &SignatureEnvelopeV1,
    expected_label: &str,
    payload: &Value,
    expected_signer: Option<&str>,
) -> SignatureVerificationV1 {
    let mut issues = Vec::new();
    let expected_payload_hash = signature_payload_hash_for_value(expected_label, payload);

    if envelope.schema_version != "swarm-ai.signature.ed25519.v1" {
        issues.push(signature_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.signature.ed25519.v1",
        ));
    }
    if envelope.algorithm != ED25519_ALGORITHM {
        issues.push(signature_issue(
            "$.algorithm",
            "Expected algorithm to be ed25519",
        ));
    }
    if envelope.label != expected_label {
        issues.push(signature_issue(
            "$.label",
            "Signature label does not match payload use",
        ));
    }
    if envelope.payload_hash != expected_payload_hash {
        issues.push(signature_issue(
            "$.payloadHash",
            "Signature payload hash does not match canonical payload",
        ));
    }
    let public_key = match hex_to_array::<32>("publicKeyHex", &envelope.public_key_hex) {
        Ok(public_key) => {
            if envelope.key_id != key_id(&public_key) {
                issues.push(signature_issue(
                    "$.keyId",
                    "Signature keyId does not match public key",
                ));
            }
            Some(public_key)
        }
        Err(error) => {
            issues.push(signature_issue("$.publicKeyHex", error.to_string()));
            None
        }
    };
    let signature_bytes = match hex_to_array::<64>("signatureHex", &envelope.signature_hex) {
        Ok(signature_bytes) => Some(signature_bytes),
        Err(error) => {
            issues.push(signature_issue("$.signatureHex", error.to_string()));
            None
        }
    };
    if let Some(expected_signer) = expected_signer {
        if envelope.signer != expected_signer {
            issues.push(signature_issue(
                "$.signer",
                "Signature signer does not match expected signer",
            ));
        }
    }

    if let (Some(public_key), Some(signature_bytes)) = (public_key, signature_bytes) {
        match verify_ed25519(envelope, &public_key, &signature_bytes) {
            Ok(()) => {}
            Err(error) => issues.push(signature_issue("$.signatureHex", error.to_string())),
        }
    }

    SignatureVerificationV1 {
        schema_version: "swarm-ai.signature-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
        signer: Some(envelope.signer.clone()),
        key_id: Some(envelope.key_id.clone()),
        payload_hash: expected_payload_hash,
        verified_at: timestamp(),
    }
}

fn verify_ed25519(
    envelope: &SignatureEnvelopeV1,
    public_key: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> Result<(), IdentityError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|error| IdentityError::InvalidPublicKey {
            message: error.to_string(),
        })?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(&canonical_signature_input_bytes(envelope), &signature)
        .map_err(|error| IdentityError::InvalidSignature {
            message: error.to_string(),
        })
}

fn identity_from_signing_key(subject: String, signing_key: SigningKey) -> IdentityKeypairV1 {
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_hex = hex::encode(public_key);
    IdentityKeypairV1 {
        schema_version: "swarm-ai.identity.keypair.v1".to_string(),
        subject,
        key_id: key_id(&public_key),
        algorithm: ED25519_ALGORITHM.to_string(),
        public_key_hex,
        secret_key_hex: hex::encode(signing_key.to_bytes()),
        created_at: timestamp(),
    }
}

fn canonical_signature_payload_bytes(label: &str, payload: &Value) -> Vec<u8> {
    let value = json!({
        "schemaVersion": "swarm-ai.signature-payload.v1",
        "label": label,
        "payload": payload,
    });
    let canonical = canonicalize_json(&value);
    serde_json::to_vec(&canonical).expect("canonical signature payload should serialize")
}

fn canonical_signature_input_bytes(envelope: &SignatureEnvelopeV1) -> Vec<u8> {
    let value = json!({
        "schemaVersion": "swarm-ai.signature-input.v1",
        "algorithm": &envelope.algorithm,
        "signer": &envelope.signer,
        "keyId": &envelope.key_id,
        "label": &envelope.label,
        "publicKeyHex": &envelope.public_key_hex,
        "payloadHash": &envelope.payload_hash,
    });
    let canonical = canonicalize_json(&value);
    serde_json::to_vec(&canonical).expect("canonical signature input should serialize")
}

fn hash_bytes(signing_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(signing_bytes))
}

fn invalid_verification(
    expected_label: &str,
    payload: &Value,
    issues: Vec<SignatureIssueV1>,
    signer: Option<String>,
    key_id: Option<String>,
) -> SignatureVerificationV1 {
    SignatureVerificationV1 {
        schema_version: "swarm-ai.signature-verification.v1".to_string(),
        valid: false,
        issues,
        signer,
        key_id,
        payload_hash: signature_payload_hash_for_value(expected_label, payload),
        verified_at: timestamp(),
    }
}

fn key_id(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("ed25519:{}", hex::encode(&digest[..8]))
}

fn hex_to_array<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], IdentityError> {
    let bytes = hex::decode(value).map_err(|error| IdentityError::InvalidHex {
        field,
        message: error.to_string(),
    })?;
    if bytes.len() != N {
        return Err(IdentityError::InvalidByteLength {
            field,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn normalize_required(field: &'static str, value: String) -> Result<String, IdentityError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(IdentityError::Required { field });
    }
    Ok(value)
}

fn signature_issue(path: impl Into<String>, message: impl Into<String>) -> SignatureIssueV1 {
    SignatureIssueV1 {
        path: path.into(),
        message: message.into(),
    }
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_value() {
        let identity = identity_from_seed("0xpublisher", b"publisher-seed").unwrap();
        let payload = json!({
            "packageId": "hivemind/example",
            "version": "0.1.0",
        });
        let envelope = sign_value(&identity, "publication", &payload).unwrap();
        let compact = encode_signature_envelope(&envelope).unwrap();

        let verification =
            verify_value_signature_string(&compact, "publication", &payload, Some("0xpublisher"));

        assert!(compact.starts_with(COMPACT_SIGNATURE_PREFIX));
        assert!(verification.valid, "{:?}", verification.issues);
        assert_eq!(verification.signer.as_deref(), Some("0xpublisher"));
    }

    #[test]
    fn rejects_tampered_payload() {
        let identity = identity_from_seed("0xpublisher", b"publisher-seed").unwrap();
        let payload = json!({ "packageId": "hivemind/example" });
        let envelope = sign_value(&identity, "publication", &payload).unwrap();
        let compact = encode_signature_envelope(&envelope).unwrap();
        let tampered = json!({ "packageId": "hivemind/other" });

        let verification =
            verify_value_signature_string(&compact, "publication", &tampered, Some("0xpublisher"));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.payloadHash")
        );
    }

    #[test]
    fn rejects_wrong_expected_signer() {
        let identity = identity_from_seed("0xpublisher", b"publisher-seed").unwrap();
        let payload = json!({ "packageId": "hivemind/example" });
        let envelope = sign_value(&identity, "publication", &payload).unwrap();
        let compact = encode_signature_envelope(&envelope).unwrap();

        let verification =
            verify_value_signature_string(&compact, "publication", &payload, Some("0xother"));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signer")
        );
    }

    #[test]
    fn rejects_tampered_envelope_signer() {
        let identity = identity_from_seed("0xpublisher", b"publisher-seed").unwrap();
        let payload = json!({ "packageId": "hivemind/example" });
        let mut envelope = sign_value(&identity, "publication", &payload).unwrap();
        envelope.signer = "0xother".to_string();
        let compact = encode_signature_envelope(&envelope).unwrap();

        let verification =
            verify_value_signature_string(&compact, "publication", &payload, Some("0xother"));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signatureHex")
        );
    }

    #[test]
    fn rejects_tampered_key_id() {
        let identity = identity_from_seed("0xpublisher", b"publisher-seed").unwrap();
        let payload = json!({ "packageId": "hivemind/example" });
        let mut envelope = sign_value(&identity, "publication", &payload).unwrap();
        envelope.key_id = "ed25519:wrong".to_string();
        let compact = encode_signature_envelope(&envelope).unwrap();

        let verification =
            verify_value_signature_string(&compact, "publication", &payload, Some("0xpublisher"));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.keyId")
        );
    }
}
