//! Sigstore bundle format types
//!
//! The bundle is the core artifact produced by signing and consumed by verification.
//! It contains the signature, verification material (certificate or public key),
//! and transparency log entries.

use crate::checkpoint::Checkpoint;
use crate::dsse::DsseEnvelope;
use crate::encoding::{
    string_i64, CanonicalizedBody, DerCertificate, LogIndex, LogKeyId, Sha256Hash, SignatureBytes,
    SignedTimestamp, TimestampToken,
};
use crate::error::{Error, Result};
use crate::hash::HashAlgorithm;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// Deserialize a field that may be null as the default value
fn deserialize_null_as_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Helper for skip_serializing_if to check if i64 is zero
fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// Sigstore bundle media types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// Bundle format version 0.1
    Bundle0_1,
    /// Bundle format version 0.2
    Bundle0_2,
    /// Bundle format version 0.3
    Bundle0_3,
}

impl MediaType {
    /// Get the media type string
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaType::Bundle0_1 => "application/vnd.dev.sigstore.bundle+json;version=0.1",
            MediaType::Bundle0_2 => "application/vnd.dev.sigstore.bundle+json;version=0.2",
            MediaType::Bundle0_3 => "application/vnd.dev.sigstore.bundle.v0.3+json",
        }
    }
}

impl FromStr for MediaType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "application/vnd.dev.sigstore.bundle+json;version=0.1" => Ok(MediaType::Bundle0_1),
            "application/vnd.dev.sigstore.bundle+json;version=0.2" => Ok(MediaType::Bundle0_2),
            "application/vnd.dev.sigstore.bundle.v0.3+json" => Ok(MediaType::Bundle0_3),
            // Also accept alternative v0.3 format
            "application/vnd.dev.sigstore.bundle+json;version=0.3" => Ok(MediaType::Bundle0_3),
            _ => Err(Error::InvalidMediaType(s.to_string())),
        }
    }
}

/// Bundle version enum for serde
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleVersion {
    /// Version 0.1
    #[serde(rename = "0.1")]
    V0_1,
    /// Version 0.2
    #[serde(rename = "0.2")]
    V0_2,
    /// Version 0.3
    #[serde(rename = "0.3")]
    V0_3,
}

/// The main Sigstore bundle structure
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    /// Media type identifying the bundle version
    pub media_type: String,
    /// Verification material (certificate chain or public key)
    pub verification_material: VerificationMaterial,
    /// The content being signed (message signature or DSSE envelope)
    #[serde(flatten)]
    pub content: SignatureContent,
}

impl Bundle {
    /// Parse a bundle from JSON, preserving raw DSSE envelope for hash verification
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(Error::Json)
    }

    /// Serialize the bundle to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::Json)
    }

    /// Serialize the bundle to pretty-printed JSON
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Error::Json)
    }

    /// Get the bundle version from the media type
    pub fn version(&self) -> Result<MediaType> {
        MediaType::from_str(&self.media_type)
    }

    /// Get the signing certificate if present
    pub fn signing_certificate(&self) -> Option<&DerCertificate> {
        match &self.verification_material.content {
            VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                certificates.first().map(|c| &c.raw_bytes)
            }
            VerificationMaterialContent::PublicKey { .. } => None,
        }
    }

    /// Check if the bundle has an inclusion proof
    pub fn has_inclusion_proof(&self) -> bool {
        self.verification_material
            .tlog_entries
            .iter()
            .any(|e| e.inclusion_proof.is_some())
    }

    /// Check if the bundle has an inclusion promise (SET)
    pub fn has_inclusion_promise(&self) -> bool {
        self.verification_material
            .tlog_entries
            .iter()
            .any(|e| e.inclusion_promise.is_some())
    }
}

/// The signature content (either a message signature or DSSE envelope)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignatureContent {
    /// A simple message signature
    MessageSignature(MessageSignature),
    /// A DSSE envelope
    DsseEnvelope(DsseEnvelope),
}

/// A simple message signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignature {
    /// Message digest (optional, for detached signatures)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_digest: Option<MessageDigest>,
    /// The signature bytes
    pub signature: SignatureBytes,
}

/// Message digest with algorithm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDigest {
    /// Hash algorithm
    pub algorithm: HashAlgorithm,
    /// Digest bytes
    pub digest: Sha256Hash,
}

/// Verification material containing certificate/key and log entries
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMaterial {
    /// Certificate, certificate chain, or public key
    #[serde(flatten)]
    pub content: VerificationMaterialContent,
    /// Transparency log entries
    #[serde(default)]
    pub tlog_entries: Vec<TransparencyLogEntry>,
    /// RFC 3161 timestamp verification data
    #[serde(default, deserialize_with = "deserialize_null_as_default")]
    pub timestamp_verification_data: TimestampVerificationData,
}

/// The verification material content type
///
/// The field name in JSON determines which variant is used:
/// - "certificate" -> Certificate variant (v0.3 format)
/// - "x509CertificateChain" -> X509CertificateChain variant (v0.1/v0.2 format)
/// - "publicKey" -> PublicKey variant
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationMaterialContent {
    /// Single certificate (v0.3 format)
    Certificate(CertificateContent),
    /// Certificate chain (v0.1/v0.2 format)
    X509CertificateChain {
        /// Chain of certificates
        certificates: Vec<X509Certificate>,
    },
    /// Public key (keyless alternative)
    PublicKey {
        /// Public key hint
        hint: String,
    },
}

/// Certificate content for v0.3 bundles
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateContent {
    /// DER-encoded certificate
    pub raw_bytes: DerCertificate,
}

/// X.509 certificate in the chain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X509Certificate {
    /// DER-encoded certificate
    pub raw_bytes: DerCertificate,
}

/// A transparency log entry
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLogEntry {
    /// Log index
    pub log_index: LogIndex,
    /// Log ID
    pub log_id: LogId,
    /// Kind and version of the entry
    pub kind_version: KindVersion,
    /// Integrated time (Unix timestamp)
    /// For Rekor V2 entries, this field may be omitted (defaults to 0)
    #[serde(default, with = "string_i64", skip_serializing_if = "is_zero")]
    pub integrated_time: i64,
    /// Inclusion promise (Signed Entry Timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_promise: Option<InclusionPromise>,
    /// Inclusion proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProof>,
    /// Canonicalized body
    pub canonicalized_body: CanonicalizedBody,
}

/// Log identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogId {
    /// Key ID (base64 encoded SHA-256 of public key)
    pub key_id: LogKeyId,
}

/// Entry kind and version
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindVersion {
    /// Entry kind (e.g., "hashedrekord")
    pub kind: String,
    /// Entry version (e.g., "0.0.1")
    pub version: String,
}

/// Inclusion promise (Signed Entry Timestamp)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionPromise {
    /// Signed entry timestamp
    pub signed_entry_timestamp: SignedTimestamp,
}

/// Inclusion proof in the Merkle tree
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// Index of the entry in the log
    pub log_index: LogIndex,
    /// Root hash of the tree
    pub root_hash: Sha256Hash,
    /// Tree size at time of proof
    #[serde(with = "string_i64")]
    pub tree_size: i64,
    /// Hashes in the inclusion proof path
    #[serde(with = "sha256_hash_vec")]
    pub hashes: Vec<Sha256Hash>,
    /// Checkpoint (signed tree head) - optional
    #[serde(default, skip_serializing_if = "CheckpointData::is_empty")]
    pub checkpoint: CheckpointData,
}

/// Serde helper for `Vec<Sha256Hash>`
mod sha256_hash_vec {
    use super::Sha256Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(hashes: &[Sha256Hash], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Sha256Hash already implements Serialize (as base64)
        hashes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Sha256Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<Sha256Hash>::deserialize(deserializer)
    }
}

/// Checkpoint data in inclusion proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointData {
    /// Text representation of the checkpoint
    #[serde(default)]
    pub envelope: String,
}

impl CheckpointData {
    /// Parse the checkpoint text
    pub fn parse(&self) -> Result<Checkpoint> {
        Checkpoint::from_text(&self.envelope)
    }

    /// Check if checkpoint data is empty
    pub fn is_empty(&self) -> bool {
        self.envelope.is_empty()
    }
}

/// RFC 3161 timestamp verification data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TimestampVerificationData {
    /// RFC 3161 signed timestamps
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rfc3161_timestamps: Vec<Rfc3161Timestamp>,
}

/// An RFC 3161 timestamp
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rfc3161Timestamp {
    /// Signed timestamp data (DER-encoded)
    pub signed_timestamp: TimestampToken,
}

/// Default media type for bundles that don't specify one (pre-v0.1 format)
fn default_media_type() -> String {
    "application/vnd.dev.sigstore.bundle+json;version=0.1".to_string()
}

// Custom Deserialize implementation for Bundle
impl<'de> Deserialize<'de> for Bundle {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct BundleHelper {
            // Cosign V1 bundles may not have mediaType - default to v0.1
            #[serde(default = "default_media_type")]
            media_type: String,
            verification_material: VerificationMaterial,
            #[serde(flatten)]
            content: SignatureContent,
        }

        let helper = BundleHelper::deserialize(deserializer)?;

        Ok(Bundle {
            media_type: helper.media_type,
            verification_material: helper.verification_material,
            content: helper.content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_type_parsing() {
        assert_eq!(
            MediaType::from_str("application/vnd.dev.sigstore.bundle+json;version=0.1").unwrap(),
            MediaType::Bundle0_1
        );
        assert_eq!(
            MediaType::from_str("application/vnd.dev.sigstore.bundle+json;version=0.2").unwrap(),
            MediaType::Bundle0_2
        );
        assert_eq!(
            MediaType::from_str("application/vnd.dev.sigstore.bundle.v0.3+json").unwrap(),
            MediaType::Bundle0_3
        );
    }

    #[test]
    fn test_media_type_invalid() {
        assert!(MediaType::from_str("invalid").is_err());
    }
}
