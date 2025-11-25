//! Rekor log entry types

use base64::Engine;
use serde::{Deserialize, Serialize};
use sigstore_crypto::{PublicKeyPem, Signature};
use sigstore_types::{
    Base64Body, Base64Der, Base64Hash, Base64Pem, Base64Signature, Base64Timestamp, CheckpointData,
    InclusionPromise, KindVersion, LogId, Sha256Hash,
};
use std::collections::HashMap;

/// A log entry from Rekor
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// UUID of the entry (the key in the response map)
    #[serde(skip)]
    pub uuid: String,
    /// Body of the entry (base64 encoded)
    pub body: String,
    /// Integrated time (Unix timestamp)
    pub integrated_time: i64,
    /// Log ID (SHA-256 of the public key)
    #[serde(rename = "logID")]
    pub log_id: String,
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
    pub signed_entry_timestamp: Option<Base64Timestamp>,
}

/// Inclusion proof for a log entry (V1 API - uses i64 for indices)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// Checkpoint (signed tree head)
    pub checkpoint: String,
    /// Hashes in the proof path
    pub hashes: Vec<Base64Hash>,
    /// Log index
    pub log_index: i64,
    /// Root hash
    pub root_hash: Base64Hash,
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
    /// Hash algorithm
    pub algorithm: String,
    /// Hash value (hex encoded)
    pub value: String,
}

/// Signature in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordSignature {
    /// Signature content (base64 encoded)
    pub content: Base64Signature,
    /// Public key
    #[serde(rename = "publicKey")]
    pub public_key: HashedRekordPublicKey,
}

/// Public key in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordPublicKey {
    /// PEM-encoded public key or certificate
    pub content: Base64Pem,
}

impl HashedRekord {
    /// Create a new HashedRekord entry
    ///
    /// # Arguments
    /// * `artifact_hash` - Hex-encoded SHA256 hash of the artifact
    /// * `signature_base64` - Base64-encoded signature
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
                        algorithm: "sha256".to_string(),
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
    pub digest: Base64Hash,
    pub signature: HashedRekordSignatureV2,
}

/// Signature in HashedRekord V2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordSignatureV2 {
    /// Signature content (base64 encoded)
    pub content: Base64Signature,
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
    /// Raw bytes (base64 encoded DER)
    #[serde(rename = "rawBytes")]
    pub content: Base64Der,
}

impl HashedRekordV2 {
    /// Create a new HashedRekordV2 entry
    ///
    /// # Arguments
    /// * `artifact_hash` - Hex-encoded SHA256 hash of the artifact
    /// * `signature_base64` - Base64-encoded signature
    /// * `public_key_pem` - PEM-encoded public key or certificate
    pub fn new(artifact_hash: &str, signature_base64: &str, public_key_pem: &str) -> Self {
        // Extract base64 DER from PEM
        // PEM format: -----BEGIN CERTIFICATE-----\nbase64\n-----END CERTIFICATE-----
        let start_marker = "-----BEGIN CERTIFICATE-----";
        let end_marker = "-----END CERTIFICATE-----";

        let cert_base64 = if let Some(start) = public_key_pem.find(start_marker) {
            if let Some(end) = public_key_pem.find(end_marker) {
                let content = &public_key_pem[start + start_marker.len()..end];
                content
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
            } else {
                // Fallback: assume it's already base64 or raw key
                public_key_pem.to_string()
            }
        } else {
            // Fallback: assume it's already base64 or raw key
            public_key_pem.to_string()
        };

        // Convert hex hash to base64
        let hash_bytes = hex::decode(artifact_hash).expect("invalid hex hash");
        let hash_base64 = base64::engine::general_purpose::STANDARD.encode(hash_bytes);

        Self {
            request: HashedRekordRequestV002 {
                digest: hash_base64.into(),
                signature: HashedRekordSignatureV2 {
                    content: signature_base64.to_string().into(),
                    verifier: HashedRekordVerifierV2 {
                        // Assuming ECDSA P-256 SHA-256 for now as per conformance tests
                        key_details: "PKIX_ECDSA_P256_SHA_256".to_string(),
                        x509_certificate: Some(HashedRekordPublicKeyV2 {
                            content: cert_base64.into(),
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
    pub canonicalized_body: Base64Body,
}

/// Inclusion proof V2 (similar to bundle InclusionProof but with String log_index)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProofV2 {
    pub log_index: String,
    pub root_hash: Base64Hash,
    pub tree_size: String,
    pub hashes: Vec<Base64Hash>,
    pub checkpoint: CheckpointData,
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
        assert_eq!(entry.spec.data.hash.algorithm, "sha256");
        assert_eq!(
            entry.spec.data.hash.value,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            entry.spec.signature.content,
            Base64Signature::new("c2lnbmF0dXJl".to_string())
        );
    }

    #[test]
    fn test_hashed_rekord_v2_creation() {
        let entry = HashedRekordV2::new(
            "abcd1234",
            "c2lnbmF0dXJl",
            "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        );
        assert!(!entry.request.digest.as_str().is_empty());
        assert_eq!(entry.request.signature.content.as_str(), "c2lnbmF0dXJl");
    }
}
