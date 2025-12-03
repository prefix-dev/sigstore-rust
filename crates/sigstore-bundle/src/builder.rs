//! Bundle builder for creating Sigstore bundles
//!
//! This module re-exports the type-safe bundle builders from `sigstore_types::proto`
//! and provides convenience functions for creating bundles from Rekor log entries.

use sigstore_rekor::entry::LogEntry;
use sigstore_types::{
    proto::{Bundle, BundleBuilder, InclusionProofBuilder, OwnedDsseEnvelope, TlogEntryBuilder},
    DerCertificate, Sha256Hash, SignatureBytes,
};


/// Verification material for v0.3 bundles.
///
/// In v0.3 bundles, only a single certificate or a public key hint is allowed.
/// Certificate chains are NOT permitted in v0.3 format.
#[derive(Debug, Clone)]
pub enum VerificationMaterialV03 {
    /// Single certificate (the common case for Fulcio-issued certs)
    Certificate(DerCertificate),
    /// Public key hint (for pre-existing keys)
    PublicKey { hint: String },
}

/// Signature content for a bundle
#[derive(Debug, Clone)]
pub enum SignatureContent {
    /// A message signature with digest
    MessageSignature {
        signature: SignatureBytes,
        digest: Sha256Hash,
    },
    /// A DSSE envelope
    DsseEnvelope(OwnedDsseEnvelope),
}

/// A Sigstore bundle in v0.3 format.
///
/// The v0.3 format requires:
/// - A single certificate (not a chain) or public key hint
/// - Either a message signature or DSSE envelope
/// - Optional transparency log entries and RFC 3161 timestamps
///
/// # Example
///
/// ```ignore
/// use sigstore_bundle::BundleV03;
///
/// let bundle = BundleV03::with_certificate_and_signature(cert_der, signature, artifact_hash)
///     .with_tlog_entry(tlog_entry)
///     .into_bundle();
/// ```
#[derive(Debug, Clone)]
pub struct BundleV03 {
    /// Verification material - either a certificate or public key
    pub verification: VerificationMaterialV03,
    /// The signature content (message signature or DSSE envelope)
    pub content: SignatureContent,
    /// Transparency log entries (using the proto builder)
    pub tlog_entries: Vec<TlogEntryBuilder>,
    /// RFC 3161 timestamps (raw DER bytes)
    pub rfc3161_timestamps: Vec<Vec<u8>>,
}

impl BundleV03 {
    /// Create a new v0.3 bundle with the required fields.
    pub fn new(verification: VerificationMaterialV03, content: SignatureContent) -> Self {
        Self {
            verification,
            content,
            tlog_entries: Vec::new(),
            rfc3161_timestamps: Vec::new(),
        }
    }

    /// Create a new v0.3 bundle with a certificate and message signature.
    ///
    /// This is the most common case for Sigstore signing with Fulcio certificates.
    pub fn with_certificate_and_signature(
        certificate: DerCertificate,
        signature: SignatureBytes,
        artifact_digest: Sha256Hash,
    ) -> Self {
        Self::new(
            VerificationMaterialV03::Certificate(certificate),
            SignatureContent::MessageSignature {
                signature,
                digest: artifact_digest,
            },
        )
    }

    /// Create a new v0.3 bundle with a certificate and DSSE envelope.
    ///
    /// Used for attestations (in-toto statements).
    pub fn with_certificate_and_dsse(certificate: DerCertificate, envelope: OwnedDsseEnvelope) -> Self {
        Self::new(
            VerificationMaterialV03::Certificate(certificate),
            SignatureContent::DsseEnvelope(envelope),
        )
    }

    /// Add a transparency log entry using the proto builder.
    pub fn with_tlog_entry(mut self, entry: TlogEntryBuilder) -> Self {
        self.tlog_entries.push(entry);
        self
    }

    /// Add an RFC 3161 timestamp.
    pub fn with_rfc3161_timestamp(mut self, timestamp: Vec<u8>) -> Self {
        self.rfc3161_timestamps.push(timestamp);
        self
    }

    /// Convert to a proto Bundle.
    pub fn into_bundle(self) -> Bundle {
        let mut builder = BundleBuilder::new();

        // Set verification material
        builder = match self.verification {
            VerificationMaterialV03::Certificate(cert) => builder.certificate(cert),
            VerificationMaterialV03::PublicKey { hint } => builder.public_key_hint(hint),
        };

        // Set content
        builder = match self.content {
            SignatureContent::MessageSignature { signature, digest } => {
                builder.message_signature(signature, digest)
            }
            SignatureContent::DsseEnvelope(env) => builder.dsse_envelope(env),
        };

        // Add tlog entries
        for entry in self.tlog_entries {
            builder = builder.tlog_entry(entry);
        }

        // Add timestamps
        for ts in self.rfc3161_timestamps {
            builder = builder.rfc3161_timestamp(ts);
        }

        // Build - unwrap is safe because we've set all required fields
        builder.build_v03().expect("BundleV03 should have all required fields")
    }
}

/// Create a TlogEntryBuilder from a Rekor LogEntry response.
///
/// This function extracts all relevant fields from a Rekor API response
/// and creates a builder automatically.
///
/// # Arguments
/// * `entry` - The LogEntry returned from the Rekor API
/// * `kind` - The entry kind (e.g., "hashedrekord", "dsse")
/// * `version` - The entry version (e.g., "0.0.1")
pub fn tlog_entry_from_log_entry(entry: &LogEntry, kind: &str, version: &str) -> TlogEntryBuilder {
    // Convert hex log_id to raw bytes
    let log_id_bytes = entry.log_id.decode().unwrap_or_default();

    let mut builder = TlogEntryBuilder::new()
        .log_index(entry.log_index)
        .log_id(log_id_bytes)
        .kind_version(kind, version)
        .integrated_time(entry.integrated_time)
        .canonicalized_body(entry.body.as_bytes().to_vec());

    // Add verification data if present
    if let Some(verification) = &entry.verification {
        if let Some(set) = &verification.signed_entry_timestamp {
            builder = builder.inclusion_promise(set.as_bytes().to_vec());
        }

        if let Some(proof) = &verification.inclusion_proof {
            // Rekor V1 API returns hashes as hex, convert to bytes
            let root_hash = Sha256Hash::from_hex(&proof.root_hash)
                .unwrap_or_else(|_| Sha256Hash::from_bytes([0u8; 32]));

            let hashes: Vec<Sha256Hash> = proof
                .hashes
                .iter()
                .filter_map(|h| Sha256Hash::from_hex(h).ok())
                .collect();

            let proof_builder = InclusionProofBuilder::new()
                .log_index(proof.log_index)
                .root_hash(root_hash)
                .tree_size(proof.tree_size)
                .hashes(hashes)
                .checkpoint(&proof.checkpoint);

            builder = builder.inclusion_proof(proof_builder);
        }
    }

    builder
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::proto::MediaType;

    #[test]
    fn test_bundle_v03_creation() {
        let cert = DerCertificate::from_bytes(b"test cert");
        let sig = SignatureBytes::from_bytes(b"test sig");
        let digest = Sha256Hash::from_bytes([0u8; 32]);

        let bundle = BundleV03::with_certificate_and_signature(cert, sig, digest).into_bundle();

        assert_eq!(bundle.version().unwrap(), MediaType::Bundle0_3);
        assert!(bundle.signing_certificate().is_some());
        assert!(bundle.message_signature().is_some());
    }

    #[test]
    fn test_bundle_v03_with_dsse() {
        let cert = DerCertificate::from_bytes(b"test cert");
        let sig = SignatureBytes::from_bytes(b"test sig");
        let dsse = OwnedDsseEnvelope::new("application/vnd.in-toto+json", b"payload")
            .with_signature(sig);

        let bundle = BundleV03::with_certificate_and_dsse(cert, dsse).into_bundle();

        assert!(bundle.dsse_envelope().is_some());
    }
}
