//! Bundle builder for creating Sigstore bundles

use sigstore_rekor::entry::LogEntry;
use sigstore_types::{
    bundle::{
        BundleContent, InclusionPromise, InclusionProof, KindVersion, LogId, MessageSignature,
        ProtoCheckpoint, Rfc3161SignedTimestamp, TimestampVerificationData, TransparencyLogEntry,
        VerificationMaterial, VerificationMaterialContent, X509Certificate,
    },
    Bundle, DerCertificate, DsseEnvelope, HashOutput, MediaType, ProtoHashAlgorithm,
    PublicKeyIdentifier, Sha256Hash, SignatureBytes, SignedTimestamp,
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
    DsseEnvelope(DsseEnvelope),
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
    /// Transparency log entries
    pub tlog_entries: Vec<TransparencyLogEntry>,
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
    pub fn with_certificate_and_dsse(certificate: DerCertificate, envelope: DsseEnvelope) -> Self {
        Self::new(
            VerificationMaterialV03::Certificate(certificate),
            SignatureContent::DsseEnvelope(envelope),
        )
    }

    /// Add a transparency log entry.
    pub fn with_tlog_entry(mut self, entry: TransparencyLogEntry) -> Self {
        self.tlog_entries.push(entry);
        self
    }

    /// Add an RFC 3161 timestamp.
    pub fn with_rfc3161_timestamp(mut self, timestamp: Vec<u8>) -> Self {
        self.rfc3161_timestamps.push(timestamp);
        self
    }

    /// Convert to a serializable Bundle.
    pub fn into_bundle(self) -> Bundle {
        let verification_content = match self.verification {
            VerificationMaterialV03::Certificate(cert) => {
                VerificationMaterialContent::Certificate(X509Certificate {
                    raw_bytes: cert.as_bytes().to_vec(),
                })
            }
            VerificationMaterialV03::PublicKey { hint } => {
                VerificationMaterialContent::PublicKey(PublicKeyIdentifier { hint })
            }
        };

        let bundle_content = match self.content {
            SignatureContent::MessageSignature { signature, digest } => {
                BundleContent::MessageSignature(MessageSignature {
                    message_digest: Some(HashOutput {
                        algorithm: ProtoHashAlgorithm::Sha2256 as i32,
                        digest: digest.as_bytes().to_vec(),
                    }),
                    signature: signature.as_bytes().to_vec(),
                })
            }
            SignatureContent::DsseEnvelope(envelope) => BundleContent::DsseEnvelope(envelope),
        };

        Bundle {
            media_type: MediaType::Bundle0_3.as_str().to_string(),
            verification_material: Some(VerificationMaterial {
                content: Some(verification_content),
                tlog_entries: self.tlog_entries,
                timestamp_verification_data: Some(TimestampVerificationData {
                    rfc3161_timestamps: self
                        .rfc3161_timestamps
                        .into_iter()
                        .map(|ts| Rfc3161SignedTimestamp {
                            signed_timestamp: ts,
                        })
                        .collect(),
                }),
            }),
            content: Some(bundle_content),
        }
    }
}

/// Helper to create a transparency log entry.
pub struct TlogEntryBuilder {
    log_index: i64,
    log_id: Vec<u8>,
    kind: String,
    kind_version: String,
    integrated_time: i64,
    canonicalized_body: Vec<u8>,
    inclusion_promise: Option<InclusionPromise>,
    inclusion_proof: Option<InclusionProof>,
}

impl TlogEntryBuilder {
    /// Create a new tlog entry builder.
    pub fn new() -> Self {
        Self {
            log_index: 0,
            log_id: Vec::new(),
            kind: "hashedrekord".to_string(),
            kind_version: "0.0.1".to_string(),
            integrated_time: 0,
            canonicalized_body: Vec::new(),
            inclusion_promise: None,
            inclusion_proof: None,
        }
    }

    /// Create a tlog entry builder from a Rekor LogEntry response.
    ///
    /// This method extracts all relevant fields from a Rekor API response
    /// and populates the builder automatically.
    ///
    /// # Arguments
    /// * `entry` - The LogEntry returned from the Rekor API
    /// * `kind` - The entry kind (e.g., "hashedrekord", "dsse")
    /// * `version` - The entry version (e.g., "0.0.1")
    pub fn from_log_entry(entry: &LogEntry, kind: &str, version: &str) -> Self {
        // Convert hex log_id to raw bytes
        let log_id_bytes = entry.log_id.decode().unwrap_or_default();

        let mut builder = Self {
            log_index: entry.log_index,
            log_id: log_id_bytes,
            kind: kind.to_string(),
            kind_version: version.to_string(),
            integrated_time: entry.integrated_time,
            canonicalized_body: entry.body.as_bytes().to_vec(),
            inclusion_promise: None,
            inclusion_proof: None,
        };

        // Add verification data if present
        if let Some(verification) = &entry.verification {
            if let Some(set) = &verification.signed_entry_timestamp {
                builder.inclusion_promise = Some(InclusionPromise {
                    signed_entry_timestamp: set.as_bytes().to_vec(),
                });
            }

            if let Some(proof) = &verification.inclusion_proof {
                // Rekor V1 API returns hashes as hex, bundle format expects raw bytes
                let root_hash = Sha256Hash::from_hex(&proof.root_hash)
                    .map(|h| h.as_bytes().to_vec())
                    .unwrap_or_default();

                // Convert all proof hashes from hex to raw bytes
                let hashes: Vec<Vec<u8>> = proof
                    .hashes
                    .iter()
                    .filter_map(|h| Sha256Hash::from_hex(h).ok())
                    .map(|h| h.as_bytes().to_vec())
                    .collect();

                builder.inclusion_proof = Some(InclusionProof {
                    log_index: proof.log_index,
                    root_hash,
                    tree_size: proof.tree_size,
                    hashes,
                    checkpoint: Some(ProtoCheckpoint {
                        envelope: proof.checkpoint.clone(),
                    }),
                });
            }
        }

        builder
    }

    /// Set the log index.
    pub fn log_index(mut self, index: i64) -> Self {
        self.log_index = index;
        self
    }

    /// Set the integrated time (Unix timestamp).
    pub fn integrated_time(mut self, time: i64) -> Self {
        self.integrated_time = time;
        self
    }

    /// Set the inclusion promise (Signed Entry Timestamp).
    pub fn inclusion_promise(mut self, signed_entry_timestamp: SignedTimestamp) -> Self {
        self.inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp: signed_entry_timestamp.as_bytes().to_vec(),
        });
        self
    }

    /// Set the inclusion proof.
    ///
    /// # Arguments
    /// * `log_index` - The log index
    /// * `root_hash` - The root hash
    /// * `tree_size` - The tree size
    /// * `hashes` - The proof hashes
    /// * `checkpoint` - The checkpoint envelope
    pub fn inclusion_proof(
        mut self,
        log_index: i64,
        root_hash: Sha256Hash,
        tree_size: i64,
        hashes: Vec<Sha256Hash>,
        checkpoint: String,
    ) -> Self {
        self.inclusion_proof = Some(InclusionProof {
            log_index,
            root_hash: root_hash.as_bytes().to_vec(),
            tree_size,
            hashes: hashes.iter().map(|h| h.as_bytes().to_vec()).collect(),
            checkpoint: Some(ProtoCheckpoint {
                envelope: checkpoint,
            }),
        });
        self
    }

    /// Build the transparency log entry.
    pub fn build(self) -> TransparencyLogEntry {
        TransparencyLogEntry {
            log_index: self.log_index,
            log_id: Some(LogId {
                key_id: self.log_id,
            }),
            kind_version: Some(KindVersion {
                kind: self.kind,
                version: self.kind_version,
            }),
            integrated_time: self.integrated_time,
            inclusion_promise: self.inclusion_promise,
            inclusion_proof: self.inclusion_proof,
            canonicalized_body: self.canonicalized_body,
        }
    }
}

impl Default for TlogEntryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
