//! Rekor log entry types

use base64::Engine;
use serde::{Deserialize, Serialize};
use sigstore_crypto::{PublicKeyPem, Signature};
use sigstore_types::{
    CanonicalizedBody, CheckpointData, DerCertificate, EntryUuid, HashAlgorithm, HexLogId,
    InclusionPromise, KindVersion, LogId, PemContent, Sha256Hash, SignatureBytes, SignedTimestamp,
};
use std::collections::HashMap;

/// A log entry from Rekor
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// UUID of the entry (the key in the response map)
    #[serde(skip)]
    pub uuid: EntryUuid,
    /// Body of the entry (base64 encoded canonicalized body)
    pub body: CanonicalizedBody,
    /// Integrated time (Unix timestamp)
    pub integrated_time: i64,
    /// Log ID (hex-encoded SHA-256 of the log's public key)
    #[serde(rename = "logID")]
    pub log_id: HexLogId,
    /// Log index
    pub log_index: i64,
    /// Verification data
    #[serde(default)]
    pub verification: Option<Verification>,
}

/// Verification data for a log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    /// Inclusion proof
    #[serde(default)]
    pub inclusion_proof: Option<InclusionProof>,
    /// Signed entry timestamp (SET)
    #[serde(default)]
    pub signed_entry_timestamp: Option<SignedTimestamp>,
}

/// Inclusion proof for a log entry (V1 API - uses i64 for indices)
/// Note: V1 API returns hashes as hex strings, not base64
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// Checkpoint (signed tree head)
    pub checkpoint: String,
    /// Hashes in the proof path (hex-encoded in V1 API)
    pub hashes: Vec<String>,
    /// Log index
    pub log_index: i64,
    /// Root hash (hex-encoded in V1 API)
    pub root_hash: String,
    /// Tree size
    pub tree_size: i64,
}

/// Log info response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogInfo {
    /// Root hash of the tree
    pub root_hash: String,
    /// Signed tree head (checkpoint)
    pub signed_tree_head: String,
    /// Tree ID
    pub tree_i_d: String,
    /// Tree size
    pub tree_size: i64,
    /// Inactive shards
    #[serde(default)]
    pub inactive_shards: Vec<InactiveShard>,
}

/// Inactive shard info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InactiveShard {
    /// Root hash
    pub root_hash: String,
    /// Signed tree head
    pub signed_tree_head: String,
    /// Tree ID
    pub tree_i_d: String,
    /// Tree size
    pub tree_size: i64,
}

/// Response from creating a log entry (map of UUID to LogEntry)
pub type LogEntryResponse = HashMap<String, LogEntry>;

/// Search index query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchIndex {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<SearchIndexPublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchIndexPublicKey {
    pub format: String,
    pub content: String,
}

/// DSSE entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEntry {
    pub api_version: String,
    pub kind: String,
    pub spec: DsseEntrySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEntrySpec {
    pub proposed_content: DsseProposedContent,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseProposedContent {
    pub envelope: String,
    pub verifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    pub signature: String,
    pub verifier: String,
}

impl DsseEntry {
    /// Create a new DSSE entry
    ///
    /// # Arguments
    /// * `envelope_json` - JSON-encoded DSSE envelope (passed as-is, not base64-encoded)
    /// * `certificate_pem` - PEM-encoded certificate (will be base64-encoded for API)
    pub fn new(envelope_json: &str, certificate_pem: &str) -> Self {
        use base64::Engine;
        // Rekor API expects the envelope as a JSON string, NOT base64-encoded
        // Rekor API expects the PEM to be base64-encoded
        let cert_base64 = base64::engine::general_purpose::STANDARD.encode(certificate_pem);

        Self {
            api_version: "0.0.1".to_string(),
            kind: "dsse".to_string(),
            spec: DsseEntrySpec {
                proposed_content: DsseProposedContent {
                    envelope: envelope_json.to_string(),
                    verifiers: vec![cert_base64],
                },
                signatures: vec![],
            },
        }
    }
}

/// HashedRekord entry for creating new log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekord {
    /// API version
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Entry kind
    pub kind: String,
    /// Spec containing the actual data
    pub spec: HashedRekordSpec,
}

/// HashedRekord specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordSpec {
    /// Data containing the hash
    pub data: HashedRekordData,
    /// Signature
    pub signature: HashedRekordSignature,
}

/// Data portion of HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordData {
    /// Hash of the artifact
    pub hash: HashedRekordHash,
}

/// Hash in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordHash {
    /// Hash algorithm (serializes as lowercase for Rekor API)
    #[serde(with = "sigstore_types::hash::hash_algorithm_lowercase")]
    pub algorithm: HashAlgorithm,
    /// Hash value (hex encoded)
    pub value: String,
}

/// Signature in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordSignature {
    /// Signature content (base64 encoded)
    pub content: SignatureBytes,
    /// Public key
    #[serde(rename = "publicKey")]
    pub public_key: HashedRekordPublicKey,
}

/// Public key in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordPublicKey {
    /// PEM-encoded public key or certificate (base64-encoded PEM)
    pub content: PemContent,
}

impl HashedRekord {
    /// Create a new HashedRekord entry
    ///
    /// # Arguments
    /// * `artifact_hash` - SHA256 hash of the artifact
    /// * `signature` - Signature bytes
    /// * `public_key_pem` - PEM-encoded public key or certificate (will be base64-encoded for API)
    pub fn new(
        artifact_hash: &Sha256Hash,
        signature: &Signature,
        public_key_pem: &PublicKeyPem,
    ) -> Self {
        Self {
            api_version: "0.0.1".to_string(),
            kind: "hashedrekord".to_string(),
            spec: HashedRekordSpec {
                data: HashedRekordData {
                    hash: HashedRekordHash {
                        algorithm: HashAlgorithm::Sha2256,
                        value: artifact_hash.to_hex(),
                    },
                },
                signature: HashedRekordSignature {
                    content: signature.clone().into(),
                    public_key: HashedRekordPublicKey {
                        content: public_key_pem.clone().into(),
                    },
                },
            },
        }
    }
}

/// HashedRekord entry for creating new log entries (V2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV2 {
    #[serde(rename = "hashedRekordRequestV002")]
    pub request: HashedRekordRequestV002,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordRequestV002 {
    pub digest: Sha256Hash,
    pub signature: HashedRekordSignatureV2,
}

/// Signature in HashedRekord V2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordSignatureV2 {
    /// Signature content
    pub content: SignatureBytes,
    /// Verifier
    pub verifier: HashedRekordVerifierV2,
}

/// Verifier in HashedRekord V2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashedRekordVerifierV2 {
    /// Key details (enum value as string)
    pub key_details: String,
    /// X.509 certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<HashedRekordPublicKeyV2>,
    /// Public key (alternative to certificate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<HashedRekordPublicKeyV2>,
}

/// Public key/Certificate in HashedRekord V2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordPublicKeyV2 {
    /// Raw bytes (DER-encoded certificate)
    #[serde(rename = "rawBytes")]
    pub content: DerCertificate,
}

impl HashedRekordV2 {
    /// Create a new HashedRekordV2 entry
    ///
    /// # Arguments
    /// * `artifact_hash` - Hex-encoded SHA256 hash of the artifact
    /// * `signature_base64` - Base64-encoded signature
    /// * `public_key_pem` - PEM-encoded public key or certificate
    pub fn new(artifact_hash: &str, signature_base64: &str, public_key_pem: &str) -> Self {
        // Extract DER from PEM
        let cert_der =
            sigstore_crypto::x509::der_from_pem(public_key_pem).expect("invalid PEM certificate");

        // Convert hex hash to bytes
        let hash_bytes = hex::decode(artifact_hash).expect("invalid hex hash");
        let hash = Sha256Hash::try_from_slice(&hash_bytes).expect("invalid hash length");

        // Decode signature from base64
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_base64)
            .expect("invalid base64 signature");

        Self {
            request: HashedRekordRequestV002 {
                digest: hash,
                signature: HashedRekordSignatureV2 {
                    content: SignatureBytes::new(sig_bytes),
                    verifier: HashedRekordVerifierV2 {
                        // Assuming ECDSA P-256 SHA-256 for now as per conformance tests
                        key_details: "PKIX_ECDSA_P256_SHA_256".to_string(),
                        x509_certificate: Some(HashedRekordPublicKeyV2 {
                            content: DerCertificate::new(cert_der),
                        }),
                        public_key: None,
                    },
                },
            },
        }
    }
}

/// V2 Log Entry response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntryV2 {
    pub log_index: String,
    pub log_id: LogId,
    pub kind_version: KindVersion,
    pub integrated_time: String,
    pub inclusion_promise: Option<InclusionPromise>,
    pub inclusion_proof: Option<InclusionProofV2>,
    pub canonicalized_body: CanonicalizedBody,
}

/// Inclusion proof V2 (similar to bundle InclusionProof but with String log_index)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProofV2 {
    pub log_index: String,
    pub root_hash: Sha256Hash,
    pub tree_size: String,
    #[serde(with = "sha256_hash_vec")]
    pub hashes: Vec<Sha256Hash>,
    pub checkpoint: CheckpointData,
}

/// Serde helper for Vec<Sha256Hash>
mod sha256_hash_vec {
    use super::Sha256Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(hashes: &[Sha256Hash], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hashes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Sha256Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<Sha256Hash>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashed_rekord_creation() {
        let entry = HashedRekord::new(
            &Sha256Hash::from_bytes([0u8; 32]),
            &Signature::from_bytes(b"signature"),
            &PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
            ),
        );
        assert_eq!(entry.kind, "hashedrekord");
        assert_eq!(entry.api_version, "0.0.1");
        assert_eq!(entry.spec.data.hash.algorithm, HashAlgorithm::Sha2256);
        assert_eq!(
            entry.spec.data.hash.value,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        // SignatureBytes serializes as base64
        assert_eq!(
            entry.spec.signature.content,
            SignatureBytes::from_bytes(b"signature")
        );
    }

    #[test]
    fn test_hashed_rekord_serializes_lowercase_algorithm() {
        let entry = HashedRekord::new(
            &Sha256Hash::from_bytes([0u8; 32]),
            &Signature::from_bytes(b"signature"),
            &PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
            ),
        );
        let json = serde_json::to_string(&entry).unwrap();
        // Verify the algorithm is serialized as lowercase "sha256" for Rekor API
        assert!(json.contains("\"algorithm\":\"sha256\""));
        assert!(!json.contains("SHA2_256"));
    }
}
