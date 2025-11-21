//! Bundle builder for creating Sigstore bundles

use sigstore_types::{
    bundle::{
        CheckpointData, InclusionPromise, InclusionProof, KindVersion, LogId, MessageSignature,
        Rfc3161Timestamp, SignatureContent, TimestampVerificationData, TransparencyLogEntry,
        VerificationMaterial, VerificationMaterialContent,
    },
    Bundle, DsseEnvelope, MediaType,
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
        self.rfc3161_timestamps
            .push(Rfc3161Timestamp { signed_timestamp });
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
            raw_dsse_envelope: None, // Will be set if parsed from JSON
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

    /// Set the log index
    pub fn log_index(mut self, index: u64) -> Self {
        self.log_index = index;
        self
    }

    /// Set the log ID (base64 encoded)
    pub fn log_id(mut self, id: String) -> Self {
        self.log_id = id;
        self
    }

    /// Set the entry kind
    pub fn kind(mut self, kind: String, version: String) -> Self {
        self.kind = kind;
        self.kind_version = version;
        self
    }

    /// Set the integrated time (Unix timestamp)
    pub fn integrated_time(mut self, time: u64) -> Self {
        self.integrated_time = time;
        self
    }

    /// Set the canonicalized body (base64 encoded)
    pub fn canonicalized_body(mut self, body: String) -> Self {
        self.canonicalized_body = body;
        self
    }

    /// Set the inclusion promise (Signed Entry Timestamp)
    pub fn inclusion_promise(mut self, signed_entry_timestamp: String) -> Self {
        self.inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp,
        });
        self
    }

    /// Set the inclusion proof
    pub fn inclusion_proof(
        mut self,
        log_index: u64,
        root_hash: String,
        tree_size: u64,
        hashes: Vec<String>,
        checkpoint: String,
    ) -> Self {
        self.inclusion_proof = Some(InclusionProof {
            log_index: log_index.to_string().into(),
            root_hash,
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
            canonicalized_body: self.canonicalized_body,
        }
    }
}

impl Default for TlogEntryBuilder {
    fn default() -> Self {
        Self::new()
    }
}
