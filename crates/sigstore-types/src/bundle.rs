//! Sigstore bundle format types
//!
//! The bundle is the core artifact produced by signing and consumed by verification.
//! It contains the signature, verification material (certificate or public key),
//! and transparency log entries.

use crate::checkpoint::Checkpoint;
use crate::dsse::DsseEnvelope;
use crate::encoding::{Base64, Base64Signature, LogIndex, LogKeyId};
use crate::error::{Error, Result};
use crate::hash::HashAlgorithm;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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
    /// Raw JSON of the DSSE envelope (for hash verification)
    /// This field is not serialized but preserved during deserialization
    #[serde(skip)]
    pub raw_dsse_envelope: Option<String>,
}

impl Bundle {
    /// Parse a bundle from JSON, preserving raw DSSE envelope for hash verification
    pub fn from_json(json: &str) -> Result<Self> {
        // First, extract the raw DSSE envelope JSON if present
        let raw_dsse_envelope = extract_dsse_envelope_json(json);

        // Parse the bundle normally
        let mut bundle: Bundle = serde_json::from_str(json).map_err(Error::Json)?;
        bundle.raw_dsse_envelope = raw_dsse_envelope;

        Ok(bundle)
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

    /// Get the signing certificate if present (base64-encoded DER)
    pub fn signing_certificate(&self) -> Option<&str> {
        match &self.verification_material.content {
            VerificationMaterialContent::Certificate(cert) => Some(cert.raw_bytes.as_str()),
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                certificates.first().map(|c| c.raw_bytes.as_str())
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
    /// The signature bytes (base64 encoded)
    pub signature: Base64Signature,
}

/// Message digest with algorithm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDigest {
    /// Hash algorithm
    pub algorithm: HashAlgorithm,
    /// Digest bytes (base64 encoded)
    pub digest: Base64,
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
    #[serde(default)]
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
    /// Base64-encoded DER certificate
    pub raw_bytes: Base64,
}

/// X.509 certificate in the chain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X509Certificate {
    /// Base64-encoded DER certificate
    pub raw_bytes: Base64,
}

/// A transparency log entry
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLogEntry {
    /// Log index
    pub log_index: LogIndex,
    /// Log ID (base64 encoded)
    pub log_id: LogId,
    /// Kind and version of the entry
    pub kind_version: KindVersion,
    /// Integrated time (Unix timestamp)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub integrated_time: String,
    /// Inclusion promise (Signed Entry Timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_promise: Option<InclusionPromise>,
    /// Inclusion proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProof>,
    /// Canonicalized body (base64 encoded)
    pub canonicalized_body: String,
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
    /// Signed entry timestamp (base64 encoded)
    pub signed_entry_timestamp: String,
}

/// Inclusion proof in the Merkle tree
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// Index of the entry in the log
    pub log_index: LogIndex,
    /// Root hash of the tree (base64 encoded)
    pub root_hash: String,
    /// Tree size at time of proof
    pub tree_size: String,
    /// Hashes in the inclusion proof path (base64 encoded)
    pub hashes: Vec<String>,
    /// Checkpoint (signed tree head)
    pub checkpoint: CheckpointData,
}

/// Checkpoint data in inclusion proof
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointData {
    /// Text representation of the checkpoint
    pub envelope: String,
}

impl CheckpointData {
    /// Parse the checkpoint text
    pub fn parse(&self) -> Result<Checkpoint> {
        Checkpoint::from_text(&self.envelope)
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
    /// Signed timestamp data (base64 encoded DER)
    pub signed_timestamp: String,
}

/// Extract the raw DSSE envelope JSON from a bundle JSON string
fn extract_dsse_envelope_json(json: &str) -> Option<String> {
    // Find the dsseEnvelope field and extract its value
    // We need to be careful to extract the exact JSON object, including nested objects

    let start_pattern = r#""dsseEnvelope":"#;
    let start_idx = json.find(start_pattern)?;
    let json_start = start_idx + start_pattern.len();

    // Find the matching brace
    let json_bytes = json.as_bytes();
    let mut brace_count = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut end_idx = json_start;

    for i in json_start..json_bytes.len() {
        let ch = json_bytes[i] as char;

        if escape_next {
            escape_next = false;
            continue;
        }

        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => brace_count += 1,
            '}' if !in_string => {
                brace_count -= 1;
                if brace_count == 0 {
                    end_idx = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }

    if brace_count == 0 && end_idx > json_start {
        Some(json[json_start..end_idx].to_string())
    } else {
        None
    }
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
            raw_dsse_envelope: None, // Will be set by from_json
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
