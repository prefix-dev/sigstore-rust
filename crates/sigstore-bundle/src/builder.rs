//! Bundle builder for creating Sigstore bundles

use sigstore_rekor::entry::LogEntry;
use sigstore_types::{
    bundle::{
        CheckpointData, InclusionPromise, InclusionProof, KindVersion, LogId, MessageSignature,
        Rfc3161Timestamp, SignatureContent, TimestampVerificationData, TransparencyLogEntry,
        VerificationMaterial, VerificationMaterialContent,
    },
    Base64Hash, Bundle, DsseEnvelope, MediaType,
};

/// Builder for creating Sigstore bundles
pub struct BundleBuilder {
    /// Bundle version
    version: MediaType,
    /// Verification material content
    verification_content: Option<VerificationMaterialContent>,
    /// Transparency log entries
    tlog_entries: Vec<TransparencyLogEntry>,
    /// RFC 3161 timestamps
    rfc3161_timestamps: Vec<Rfc3161Timestamp>,
    /// Signature content
    signature_content: Option<SignatureContent>,
}

impl BundleBuilder {
    /// Create a new bundle builder with default version (0.3)
    pub fn new() -> Self {
        Self {
            version: MediaType::Bundle0_3,
            verification_content: None,
            tlog_entries: Vec::new(),
            rfc3161_timestamps: Vec::new(),
            signature_content: None,
        }
    }

    /// Set the bundle version
    pub fn version(mut self, version: MediaType) -> Self {
        self.version = version;
        self
    }

    /// Set the signing certificate (base64-encoded DER)
    pub fn certificate(mut self, cert_b64: String) -> Self {
        self.verification_content = Some(VerificationMaterialContent::Certificate(
            sigstore_types::bundle::CertificateContent {
                raw_bytes: cert_b64.into(),
            },
        ));
        self
    }

    /// Set the certificate chain (base64-encoded DER)
    pub fn certificate_chain(mut self, certs_b64: Vec<String>) -> Self {
        self.verification_content = Some(VerificationMaterialContent::X509CertificateChain {
            certificates: certs_b64
                .into_iter()
                .map(|c| sigstore_types::bundle::X509Certificate {
                    raw_bytes: c.into(),
                })
                .collect(),
        });
        self
    }

    /// Set the public key hint
    pub fn public_key(mut self, hint: String) -> Self {
        self.verification_content = Some(VerificationMaterialContent::PublicKey { hint });
        self
    }

    /// Add a transparency log entry
    pub fn add_tlog_entry(mut self, entry: TransparencyLogEntry) -> Self {
        self.tlog_entries.push(entry);
        self
    }

    /// Add an RFC 3161 timestamp (base64 encoded)
    pub fn add_rfc3161_timestamp(mut self, signed_timestamp: String) -> Self {
        self.rfc3161_timestamps.push(Rfc3161Timestamp {
            signed_timestamp: signed_timestamp.into(),
        });
        self
    }

    /// Set the message signature
    pub fn message_signature(mut self, signature: String) -> Self {
        self.signature_content = Some(SignatureContent::MessageSignature(MessageSignature {
            message_digest: None,
            signature: signature.into(),
        }));
        self
    }

    /// Set the DSSE envelope
    pub fn dsse_envelope(mut self, envelope: DsseEnvelope) -> Self {
        self.signature_content = Some(SignatureContent::DsseEnvelope(envelope));
        self
    }

    /// Build the bundle
    pub fn build(self) -> Result<Bundle, &'static str> {
        let verification_content = self
            .verification_content
            .ok_or("verification material not set")?;

        let signature_content = self.signature_content.ok_or("signature content not set")?;

        Ok(Bundle {
            media_type: self.version.as_str().to_string(),
            verification_material: VerificationMaterial {
                content: verification_content,
                tlog_entries: self.tlog_entries,
                timestamp_verification_data: TimestampVerificationData {
                    rfc3161_timestamps: self.rfc3161_timestamps,
                },
            },
            content: signature_content,
        })
    }
}

impl Default for BundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create a transparency log entry
pub struct TlogEntryBuilder {
    log_index: u64,
    log_id: String,
    kind: String,
    kind_version: String,
    integrated_time: u64,
    canonicalized_body: String,
    inclusion_promise: Option<InclusionPromise>,
    inclusion_proof: Option<InclusionProof>,
}

impl TlogEntryBuilder {
    /// Create a new tlog entry builder
    pub fn new() -> Self {
        Self {
            log_index: 0,
            log_id: String::new(),
            kind: "hashedrekord".to_string(),
            kind_version: "0.0.1".to_string(),
            integrated_time: 0,
            canonicalized_body: String::new(),
            inclusion_promise: None,
            inclusion_proof: None,
        }
    }

    /// Create a tlog entry builder from a Rekor LogEntry response
    ///
    /// This method extracts all relevant fields from a Rekor API response
    /// and populates the builder automatically.
    ///
    /// # Arguments
    /// * `entry` - The LogEntry returned from the Rekor API
    /// * `kind` - The entry kind (e.g., "hashedrekord", "dsse")
    /// * `version` - The entry version (e.g., "0.0.1")
    pub fn from_log_entry(entry: &LogEntry, kind: &str, version: &str) -> Self {
        // Convert hex log_id to base64 using the type-safe method
        let log_id_base64 = entry
            .log_id
            .to_base64()
            .unwrap_or_else(|_| entry.log_id.to_string());

        let mut builder = Self {
            log_index: entry.log_index as u64,
            log_id: log_id_base64,
            kind: kind.to_string(),
            kind_version: version.to_string(),
            integrated_time: entry.integrated_time as u64,
            canonicalized_body: entry.body.to_string(),
            inclusion_promise: None,
            inclusion_proof: None,
        };

        // Add verification data if present
        if let Some(verification) = &entry.verification {
            if let Some(set) = &verification.signed_entry_timestamp {
                builder.inclusion_promise = Some(InclusionPromise {
                    signed_entry_timestamp: set.clone(),
                });
            }

            if let Some(proof) = &verification.inclusion_proof {
                builder.inclusion_proof = Some(InclusionProof {
                    log_index: proof.log_index.to_string().into(),
                    root_hash: proof.root_hash.clone(),
                    tree_size: proof.tree_size.to_string(),
                    hashes: proof.hashes.clone(),
                    checkpoint: CheckpointData {
                        envelope: proof.checkpoint.clone(),
                    },
                });
            }
        }

        builder
    }

    /// Set the log index
    pub fn log_index(mut self, index: u64) -> Self {
        self.log_index = index;
        self
    }

    /// Set the integrated time (Unix timestamp)
    pub fn integrated_time(mut self, time: u64) -> Self {
        self.integrated_time = time;
        self
    }

    /// Set the inclusion promise (Signed Entry Timestamp)
    pub fn inclusion_promise(
        mut self,
        signed_entry_timestamp: impl Into<sigstore_types::Base64Timestamp>,
    ) -> Self {
        self.inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp: signed_entry_timestamp.into(),
        });
        self
    }

    /// Set the inclusion proof
    ///
    /// # Arguments
    /// * `log_index` - The log index
    /// * `root_hash` - The root hash (base64 encoded)
    /// * `tree_size` - The tree size
    /// * `hashes` - The proof hashes (base64 encoded)
    /// * `checkpoint` - The checkpoint envelope
    pub fn inclusion_proof(
        mut self,
        log_index: u64,
        root_hash: impl Into<Base64Hash>,
        tree_size: u64,
        hashes: Vec<Base64Hash>,
        checkpoint: String,
    ) -> Self {
        self.inclusion_proof = Some(InclusionProof {
            log_index: log_index.to_string().into(),
            root_hash: root_hash.into(),
            tree_size: tree_size.to_string(),
            hashes,
            checkpoint: CheckpointData {
                envelope: checkpoint,
            },
        });
        self
    }

    /// Build the transparency log entry
    pub fn build(self) -> TransparencyLogEntry {
        TransparencyLogEntry {
            log_index: self.log_index.to_string().into(),
            log_id: LogId {
                key_id: self.log_id.into(),
            },
            kind_version: KindVersion {
                kind: self.kind,
                version: self.kind_version,
            },
            integrated_time: self.integrated_time.to_string(),
            inclusion_promise: self.inclusion_promise,
            inclusion_proof: self.inclusion_proof,
            canonicalized_body: self.canonicalized_body.into(),
        }
    }
}

impl Default for TlogEntryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
