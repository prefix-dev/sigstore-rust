//! Sigstore bundle format types
//!
//! The bundle is the core artifact produced by signing and consumed by verification.
//! It contains the signature, verification material (certificate or public key),
//! and transparency log entries.
//!
//! This module re-exports the official Sigstore protobuf types and provides
//! extension traits for common operations.

use crate::checkpoint::Checkpoint;
use crate::encoding::DerCertificate;
use crate::error::{Error, Result};
use std::str::FromStr;

// Re-export protobuf types
pub use sigstore_protobuf_specs::dev::sigstore::{
    bundle::v1::{
        bundle::Content as BundleContent,
        verification_material::Content as VerificationMaterialContent, Bundle,
        TimestampVerificationData, VerificationMaterial,
    },
    common::v1::{
        HashAlgorithm as ProtoHashAlgorithm, HashOutput, LogId, MessageSignature,
        PublicKeyIdentifier, Rfc3161SignedTimestamp, X509Certificate, X509CertificateChain,
    },
    rekor::v1::{
        Checkpoint as ProtoCheckpoint, InclusionPromise, InclusionProof, KindVersion,
        TransparencyLogEntry,
    },
};

// Re-export DSSE envelope from intoto
pub use sigstore_protobuf_specs::io::intoto::{
    Envelope as DsseEnvelope, Signature as DsseSignature,
};

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

/// Extension trait for Bundle with helper methods
pub trait BundleExt {
    /// Parse a bundle from JSON
    fn from_json(json: &str) -> Result<Bundle>;

    /// Serialize the bundle to JSON
    fn to_json(&self) -> Result<String>;

    /// Serialize the bundle to pretty-printed JSON
    fn to_json_pretty(&self) -> Result<String>;

    /// Get the bundle version from the media type
    fn version(&self) -> Result<MediaType>;

    /// Get the signing certificate if present (DER-encoded)
    fn signing_certificate(&self) -> Option<DerCertificate>;

    /// Check if the bundle has an inclusion proof
    fn has_inclusion_proof(&self) -> bool;

    /// Check if the bundle has an inclusion promise (SET)
    fn has_inclusion_promise(&self) -> bool;

    /// Get the transparency log entries
    fn tlog_entries(&self) -> &[TransparencyLogEntry];

    /// Check if bundle contains a message signature
    fn is_message_signature(&self) -> bool;

    /// Check if bundle contains a DSSE envelope
    fn is_dsse_envelope(&self) -> bool;

    /// Get the message signature if present
    fn message_signature(&self) -> Option<&MessageSignature>;

    /// Get the DSSE envelope if present
    fn dsse_envelope(&self) -> Option<&DsseEnvelope>;
}

impl BundleExt for Bundle {
    fn from_json(json: &str) -> Result<Bundle> {
        serde_json::from_str(json).map_err(Error::Json)
    }

    fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::Json)
    }

    fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Error::Json)
    }

    fn version(&self) -> Result<MediaType> {
        MediaType::from_str(&self.media_type)
    }

    fn signing_certificate(&self) -> Option<DerCertificate> {
        let vm = self.verification_material.as_ref()?;
        match &vm.content {
            Some(VerificationMaterialContent::Certificate(cert)) => {
                Some(DerCertificate::from_bytes(&cert.raw_bytes))
            }
            Some(VerificationMaterialContent::X509CertificateChain(chain)) => chain
                .certificates
                .first()
                .map(|c| DerCertificate::from_bytes(&c.raw_bytes)),
            Some(VerificationMaterialContent::PublicKey(_)) => None,
            None => None,
        }
    }

    fn has_inclusion_proof(&self) -> bool {
        self.tlog_entries()
            .iter()
            .any(|e| e.inclusion_proof.is_some())
    }

    fn has_inclusion_promise(&self) -> bool {
        self.tlog_entries()
            .iter()
            .any(|e| e.inclusion_promise.is_some())
    }

    fn tlog_entries(&self) -> &[TransparencyLogEntry] {
        self.verification_material
            .as_ref()
            .map(|vm| vm.tlog_entries.as_slice())
            .unwrap_or(&[])
    }

    fn is_message_signature(&self) -> bool {
        matches!(self.content, Some(BundleContent::MessageSignature(_)))
    }

    fn is_dsse_envelope(&self) -> bool {
        matches!(self.content, Some(BundleContent::DsseEnvelope(_)))
    }

    fn message_signature(&self) -> Option<&MessageSignature> {
        match &self.content {
            Some(BundleContent::MessageSignature(sig)) => Some(sig),
            _ => None,
        }
    }

    fn dsse_envelope(&self) -> Option<&DsseEnvelope> {
        match &self.content {
            Some(BundleContent::DsseEnvelope(env)) => Some(env),
            _ => None,
        }
    }
}

/// Extension trait for TransparencyLogEntry
pub trait TransparencyLogEntryExt {
    /// Get the log index as u64
    fn log_index_u64(&self) -> u64;

    /// Get the log key ID as base64 string
    fn log_key_id(&self) -> Option<String>;

    /// Get the integrated time as Unix timestamp
    fn integrated_time_secs(&self) -> i64;
}

impl TransparencyLogEntryExt for TransparencyLogEntry {
    fn log_index_u64(&self) -> u64 {
        self.log_index as u64
    }

    fn log_key_id(&self) -> Option<String> {
        use base64::Engine;
        self.log_id
            .as_ref()
            .map(|id| base64::engine::general_purpose::STANDARD.encode(&id.key_id))
    }

    fn integrated_time_secs(&self) -> i64 {
        self.integrated_time
    }
}

/// Extension trait for InclusionProof
pub trait InclusionProofExt {
    /// Get the log index as u64
    fn log_index_u64(&self) -> u64;

    /// Get the tree size as u64
    fn tree_size_u64(&self) -> u64;

    /// Parse the checkpoint text
    fn parse_checkpoint(&self) -> Result<Checkpoint>;
}

impl InclusionProofExt for InclusionProof {
    fn log_index_u64(&self) -> u64 {
        self.log_index as u64
    }

    fn tree_size_u64(&self) -> u64 {
        self.tree_size as u64
    }

    fn parse_checkpoint(&self) -> Result<Checkpoint> {
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::MissingField("checkpoint".to_string()))?;
        Checkpoint::from_text(&checkpoint.envelope)
    }
}

/// Extension trait for DsseEnvelope
pub trait DsseEnvelopeExt {
    /// Get the Pre-Authentication Encoding (PAE) bytes
    ///
    /// PAE is the string that gets signed in DSSE:
    /// `DSSEv1 <payload_type_len> <payload_type> <payload_len> <payload>`
    fn pae(&self) -> Vec<u8>;
}

impl DsseEnvelopeExt for DsseEnvelope {
    fn pae(&self) -> Vec<u8> {
        pae(&self.payload_type, &self.payload)
    }
}

/// Compute the Pre-Authentication Encoding (PAE)
///
/// Format: `DSSEv1 <len(type)> <type> <len(body)> <body>`
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // "DSSEv1" + space
    result.extend_from_slice(b"DSSEv1 ");

    // payload_type length + space
    result.extend_from_slice(format!("{} ", payload_type.len()).as_bytes());

    // payload_type + space
    result.extend_from_slice(payload_type.as_bytes());
    result.push(b' ');

    // payload length + space
    result.extend_from_slice(format!("{} ", payload.len()).as_bytes());

    // payload
    result.extend_from_slice(payload);

    result
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

    #[test]
    fn test_pae() {
        // Test vector from DSSE spec
        let pae_result = pae("application/example", b"hello world");
        let expected = b"DSSEv1 19 application/example 11 hello world";
        assert_eq!(pae_result, expected);
    }
}
