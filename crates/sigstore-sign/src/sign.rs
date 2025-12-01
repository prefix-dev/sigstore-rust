//! High-level signing API
//!
//! This module provides the main entry point for signing artifacts with Sigstore.

use crate::error::{Error, Result};
use sigstore_bundle::{BundleV03, TlogEntryBuilder};
use sigstore_crypto::{KeyPair, SigningScheme};
use sigstore_fulcio::FulcioClient;
use sigstore_oidc::IdentityToken;
use sigstore_rekor::{
    DsseEntry, DsseEntryV2, HashedRekord, HashedRekordV2, RekorApiVersion, RekorClient,
};
use sigstore_trust_root::SigningConfig as TufSigningConfig;
use sigstore_tsa::TimestampClient;
use sigstore_types::{
    Artifact, Bundle, DerCertificate, DsseEnvelope, DsseSignature, KeyId, PayloadBytes, Sha256Hash,
    SignatureBytes, Subject, TimestampToken,
};

/// Configuration for signing operations
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Fulcio URL
    pub fulcio_url: String,
    /// Rekor URL
    pub rekor_url: String,
    /// TSA URL (optional)
    pub tsa_url: Option<String>,
    /// Signing scheme to use
    pub signing_scheme: SigningScheme,
    /// Rekor API version to use (defaults to V2)
    pub rekor_api_version: RekorApiVersion,
}

impl Default for SigningConfig {
    fn default() -> Self {
        let rekor_api_version = RekorApiVersion::default();
        Self {
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: rekor_api_version.default_url().to_string(),
            tsa_url: Some("https://timestamp.sigstore.dev/api/v1/timestamp".to_string()),
            signing_scheme: SigningScheme::EcdsaP256Sha256,
            rekor_api_version,
        }
    }
}

impl SigningConfig {
    /// Create configuration for Sigstore public-good instance
    ///
    /// This uses the embedded signing config to get the best available endpoints.
    pub fn production() -> Self {
        Self::from_tuf_config(&TufSigningConfig::production().expect("embedded config is valid"))
    }

    /// Create configuration for Sigstore staging instance
    ///
    /// This uses the embedded signing config to get the best available endpoints.
    pub fn staging() -> Self {
        Self::from_tuf_config(&TufSigningConfig::staging().expect("embedded config is valid"))
    }

    /// Create configuration from a TUF signing config
    ///
    /// This extracts the best available endpoints from the signing config,
    /// preferring higher API versions when available.
    ///
    /// # Arguments
    ///
    /// * `tuf_config` - The signing config from TUF
    pub fn from_tuf_config(tuf_config: &TufSigningConfig) -> Self {
        Self::from_tuf_config_with_rekor_version(tuf_config, None)
    }

    /// Create configuration from a TUF signing config with optional forced Rekor version
    ///
    /// # Arguments
    ///
    /// * `tuf_config` - The signing config from TUF
    /// * `force_rekor_version` - If Some, force a specific Rekor API version
    pub fn from_tuf_config_with_rekor_version(
        tuf_config: &TufSigningConfig,
        force_rekor_version: Option<u32>,
    ) -> Self {
        let fulcio_url = tuf_config
            .get_fulcio_url()
            .map(|e| e.url.clone())
            .unwrap_or_else(|| "https://fulcio.sigstore.dev".to_string());

        let (rekor_url, rekor_api_version) =
            if let Some(rekor) = tuf_config.get_rekor_url(force_rekor_version) {
                let version = if rekor.major_api_version == 2 {
                    RekorApiVersion::V2
                } else {
                    RekorApiVersion::V1
                };
                (rekor.url.clone(), version)
            } else {
                (
                    "https://rekor.sigstore.dev".to_string(),
                    RekorApiVersion::V1,
                )
            };

        let tsa_url = tuf_config.get_tsa_url().map(|e| e.url.clone());

        Self {
            fulcio_url,
            rekor_url,
            tsa_url,
            signing_scheme: SigningScheme::EcdsaP256Sha256,
            rekor_api_version,
        }
    }

    /// Set the Rekor API version and automatically update the URL
    pub fn with_rekor_version(mut self, version: RekorApiVersion) -> Self {
        self.rekor_api_version = version;
        self.rekor_url = version.default_url().to_string();
        self
    }
}

/// Context for signing operations
pub struct SigningContext {
    /// Configuration
    config: SigningConfig,
}

impl SigningContext {
    /// Create a new signing context with default configuration
    pub fn new() -> Self {
        Self::with_config(SigningConfig::default())
    }

    /// Create a new signing context with custom configuration
    pub fn with_config(config: SigningConfig) -> Self {
        Self { config }
    }

    /// Create a signing context for the public-good instance
    pub fn production() -> Self {
        Self::with_config(SigningConfig::production())
    }

    /// Create a signing context for the staging instance
    pub fn staging() -> Self {
        Self::with_config(SigningConfig::staging())
    }

    /// Get the configuration
    pub fn config(&self) -> &SigningConfig {
        &self.config
    }

    /// Create a signer with the given identity token
    pub fn signer(&self, identity_token: IdentityToken) -> Signer {
        Signer {
            identity_token,
            signing_scheme: self.config.signing_scheme,
            fulcio_url: self.config.fulcio_url.clone(),
            rekor_url: self.config.rekor_url.clone(),
            tsa_url: self.config.tsa_url.clone(),
            rekor_api_version: self.config.rekor_api_version,
        }
    }
}

impl Default for SigningContext {
    fn default() -> Self {
        Self::new()
    }
}

/// A signer for creating Sigstore signatures
pub struct Signer {
    identity_token: IdentityToken,
    signing_scheme: SigningScheme,
    fulcio_url: String,
    rekor_url: String,
    tsa_url: Option<String>,
    rekor_api_version: RekorApiVersion,
}

impl Signer {
    /// Sign an artifact and return a Sigstore bundle (hashedrekord format)
    ///
    /// This creates a hashedrekord bundle that includes a signature over the artifact.
    /// The artifact can be provided as raw bytes or as an `Artifact` enum.
    ///
    /// **Note:** For hashedrekord bundles, the raw artifact bytes are required to create
    /// the signature. If you only have a pre-computed digest and don't need to sign the
    /// raw bytes, use [`sign_attestation`](Self::sign_attestation) instead to create a
    /// DSSE/in-toto attestation bundle.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_sign::{SigningContext, Signer};
    /// use sigstore_oidc::IdentityToken;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let context = SigningContext::production();
    /// let token = IdentityToken::new("your-token-here".to_string());
    /// let signer = context.signer(token);
    /// let artifact = b"hello world";
    /// let bundle = signer.sign(artifact.as_slice()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign<'a>(&self, artifact: impl Into<Artifact<'a>>) -> Result<Bundle> {
        let artifact = artifact.into();

        // For hashedrekord bundles, we need the raw bytes to sign
        let bytes = match &artifact {
            Artifact::Bytes(b) => *b,
            Artifact::Digest(_) => {
                return Err(Error::Signing(
                    "Cannot create hashedrekord bundle with only a digest. \
                     The raw artifact bytes are required to create the signature. \
                     Use sign_attestation() to create a DSSE bundle with just a digest."
                        .to_string(),
                ));
            }
        };

        // 1. Generate ephemeral key pair
        let key_pair = self.generate_ephemeral_keypair()?;

        // 2. Get signing certificate from Fulcio
        let leaf_cert_der = self.request_certificate(&key_pair).await?;

        // 3. Sign the artifact
        let signature = key_pair.sign(bytes)?;

        // 4. Create Rekor entry (with certificate, not just public key)
        let tlog_entry = self
            .create_rekor_entry(bytes, &signature, &leaf_cert_der)
            .await?;

        // 5. Get timestamp from TSA (optional)
        let timestamp = if let Some(tsa_url) = &self.tsa_url {
            Some(self.request_timestamp(tsa_url, &signature).await?)
        } else {
            None
        };

        // 6. Build bundle
        let artifact_hash = sigstore_crypto::sha256(bytes);
        let mut bundle =
            BundleV03::with_certificate_and_signature(leaf_cert_der, signature, artifact_hash)
                .with_tlog_entry(tlog_entry.build());

        if let Some(ts) = timestamp {
            bundle = bundle.with_rfc3161_timestamp(ts);
        }

        Ok(bundle.into_bundle())
    }

    /// Generate an ephemeral key pair based on the configured signing scheme
    fn generate_ephemeral_keypair(&self) -> Result<KeyPair> {
        match self.signing_scheme {
            SigningScheme::EcdsaP256Sha256 => KeyPair::generate_ecdsa_p256().map_err(|e| {
                Error::Signing(format!("Failed to generate ECDSA P-256 key pair: {}", e))
            }),
            _ => Err(Error::Signing(format!(
                "Signing scheme {:?} not yet supported",
                self.signing_scheme
            ))),
        }
    }

    /// Request a signing certificate from Fulcio
    ///
    /// Returns the leaf certificate as DerCertificate.
    async fn request_certificate(&self, key_pair: &KeyPair) -> Result<DerCertificate> {
        // Create Fulcio client and request certificate
        let fulcio = FulcioClient::new(&self.fulcio_url);
        let cert_response = fulcio
            .create_signing_certificate(&self.identity_token, key_pair)
            .await
            .map_err(|e| Error::Signing(format!("Failed to get certificate from Fulcio: {}", e)))?;

        // Get the leaf certificate (v0.3 bundles use single cert, not chain)
        cert_response
            .leaf_certificate()
            .map_err(|e| Error::Signing(format!("Failed to get certificate: {}", e)))
    }

    /// Create a Rekor entry for the signed artifact
    async fn create_rekor_entry(
        &self,
        artifact: &[u8],
        signature: &SignatureBytes,
        certificate: &DerCertificate,
    ) -> Result<TlogEntryBuilder> {
        // Compute artifact hash
        let artifact_hash = sigstore_crypto::sha256(artifact);

        // Create Rekor client
        let rekor = RekorClient::new(&self.rekor_url);

        // Use V1 or V2 API based on configuration
        let (log_entry, version) =
            match self.rekor_api_version {
                RekorApiVersion::V1 => {
                    let hashed_rekord = HashedRekord::new(&artifact_hash, signature, certificate);
                    let entry = rekor.create_entry(hashed_rekord).await.map_err(|e| {
                        Error::Signing(format!("Failed to create Rekor entry: {}", e))
                    })?;
                    (entry, "0.0.1")
                }
                RekorApiVersion::V2 => {
                    let hashed_rekord = HashedRekordV2::new(&artifact_hash, signature, certificate);
                    let entry = rekor.create_entry_v2(hashed_rekord).await.map_err(|e| {
                        Error::Signing(format!("Failed to create Rekor entry: {}", e))
                    })?;
                    (entry, "0.0.2")
                }
            };

        // Build TlogEntry from the log entry response
        let tlog_builder = TlogEntryBuilder::from_log_entry(&log_entry, "hashedrekord", version);

        Ok(tlog_builder)
    }

    /// Request a timestamp from the Timestamp Authority
    async fn request_timestamp(
        &self,
        tsa_url: &str,
        signature: &SignatureBytes,
    ) -> Result<TimestampToken> {
        let tsa = TimestampClient::new(tsa_url.to_string());
        tsa.timestamp_signature(signature)
            .await
            .map_err(|e| Error::Signing(format!("Failed to get timestamp: {}", e)))
    }

    /// Sign an attestation (DSSE envelope with in-toto statement)
    ///
    /// This creates a GitHub-style attestation bundle with a DSSE envelope containing
    /// an in-toto statement. Unlike `sign()`, this method doesn't need the raw artifact
    /// bytes - only the artifact name and digest.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_sign::{SigningContext, Attestation};
    /// use sigstore_oidc::IdentityToken;
    /// use sigstore_types::Sha256Hash;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let context = SigningContext::production();
    /// let token = IdentityToken::new("your-token-here".to_string());
    /// let signer = context.signer(token);
    ///
    /// // Create attestation with pre-computed digest (no raw bytes needed!)
    /// let digest = Sha256Hash::from_hex("54303491a8418fbed24344b51354618c29b43bf282ceb433af65e2299f9271f")?;
    /// let attestation = Attestation::new(
    ///     "https://example.com/attestation-type/v1",
    ///     serde_json::json!({"key": "value"})
    /// )
    /// .add_subject("my-package-1.0.0.tar.gz", digest);
    ///
    /// let bundle = signer.sign_attestation(attestation).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign_attestation(&self, attestation: Attestation) -> Result<Bundle> {
        // 1. Generate ephemeral key pair
        let key_pair = self.generate_ephemeral_keypair()?;

        // 2. Get signing certificate from Fulcio
        let leaf_cert_der = self.request_certificate(&key_pair).await?;

        // 3. Build the in-toto statement
        let statement = attestation.build_statement();
        let statement_json = serde_json::to_string(&statement)
            .map_err(|e| Error::Signing(format!("Failed to serialize statement: {}", e)))?;

        // 4. Create DSSE envelope and sign it
        let payload_type = "application/vnd.in-toto+json".to_string();
        let payload = PayloadBytes::from_bytes(statement_json.as_bytes());

        // Compute PAE and sign it
        let pae = sigstore_types::pae(&payload_type, statement_json.as_bytes());
        let signature = key_pair.sign(&pae)?;

        let dsse_envelope = DsseEnvelope::new(
            payload_type,
            payload,
            vec![DsseSignature {
                sig: signature.clone(),
                keyid: KeyId::default(),
            }],
        );

        // 5. Create DSSE Rekor entry
        let tlog_entry = self
            .create_dsse_rekor_entry(&dsse_envelope, &leaf_cert_der)
            .await?;

        // 6. Get timestamp from TSA (optional)
        let timestamp = if let Some(tsa_url) = &self.tsa_url {
            Some(self.request_timestamp(tsa_url, &signature).await?)
        } else {
            None
        };

        // 7. Build bundle with DSSE envelope
        let mut bundle = BundleV03::with_certificate_and_dsse(leaf_cert_der, dsse_envelope)
            .with_tlog_entry(tlog_entry.build());

        if let Some(ts) = timestamp {
            bundle = bundle.with_rfc3161_timestamp(ts);
        }

        Ok(bundle.into_bundle())
    }

    /// Create a DSSE Rekor entry
    async fn create_dsse_rekor_entry(
        &self,
        envelope: &DsseEnvelope,
        certificate: &DerCertificate,
    ) -> Result<TlogEntryBuilder> {
        // Create Rekor client
        let rekor = RekorClient::new(&self.rekor_url);

        // Use V1 or V2 API based on configuration
        let (log_entry, version) = match self.rekor_api_version {
            RekorApiVersion::V1 => {
                let dsse_entry = DsseEntry::new(envelope, certificate);
                let entry = rekor.create_dsse_entry(dsse_entry).await.map_err(|e| {
                    Error::Signing(format!("Failed to create DSSE Rekor entry: {}", e))
                })?;
                (entry, "0.0.1")
            }
            RekorApiVersion::V2 => {
                let dsse_entry = DsseEntryV2::new(envelope, certificate);
                let entry = rekor.create_dsse_entry_v2(dsse_entry).await.map_err(|e| {
                    Error::Signing(format!("Failed to create DSSE Rekor entry: {}", e))
                })?;
                (entry, "0.0.2")
            }
        };

        // Build TlogEntry from the log entry response
        let tlog_builder = TlogEntryBuilder::from_log_entry(&log_entry, "dsse", version);

        Ok(tlog_builder)
    }
}

/// An attestation to be signed (in-toto statement)
///
/// Attestations are used to make claims about artifacts without needing the raw
/// artifact bytes. Each attestation contains:
/// - One or more subjects (artifacts) identified by name and digest
/// - A predicate type URI identifying the attestation format
/// - The predicate content (attestation-specific data)
///
/// # Example
///
/// ```
/// use sigstore_sign::Attestation;
/// use sigstore_types::Sha256Hash;
///
/// let digest = Sha256Hash::from_hex(
///     "54303491a8418fbed24344b51354618c29b43bf282ceb433af65e2299f9271ff"
/// ).unwrap();
///
/// let attestation = Attestation::new(
///     "https://slsa.dev/provenance/v1",
///     serde_json::json!({
///         "buildType": "https://example.com/build/v1",
///         "builder": {"id": "https://github.com/actions/runner"}
///     })
/// )
/// .add_subject("my-package-1.0.0.tar.gz", digest);
/// ```
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Subjects (artifacts being attested about)
    subjects: Vec<AttestationSubject>,
    /// Predicate type URI
    predicate_type: String,
    /// Predicate content
    predicate: serde_json::Value,
}

/// A subject in an attestation
#[derive(Debug, Clone)]
pub struct AttestationSubject {
    /// Name of the artifact
    pub name: String,
    /// SHA-256 digest of the artifact
    pub digest: Sha256Hash,
}

impl Attestation {
    /// Create a new attestation with the given predicate type and content
    pub fn new(predicate_type: impl Into<String>, predicate: serde_json::Value) -> Self {
        Self {
            subjects: Vec::new(),
            predicate_type: predicate_type.into(),
            predicate,
        }
    }

    /// Add a subject to the attestation
    pub fn add_subject(mut self, name: impl Into<String>, digest: Sha256Hash) -> Self {
        self.subjects.push(AttestationSubject {
            name: name.into(),
            digest,
        });
        self
    }

    /// Add multiple subjects at once
    pub fn with_subjects(mut self, subjects: Vec<(String, Sha256Hash)>) -> Self {
        for (name, digest) in subjects {
            self.subjects.push(AttestationSubject { name, digest });
        }
        self
    }

    /// Build the in-toto statement
    fn build_statement(&self) -> sigstore_types::Statement {
        use sigstore_types::Digest;

        sigstore_types::Statement {
            type_: "https://in-toto.io/Statement/v1".to_string(),
            subject: self
                .subjects
                .iter()
                .map(|s| Subject {
                    name: s.name.clone(),
                    digest: Digest {
                        sha256: Some(s.digest.to_hex()),
                        sha512: None,
                    },
                })
                .collect(),
            predicate_type: self.predicate_type.clone(),
            predicate: self.predicate.clone(),
        }
    }
}

/// Convenience function to create a signing context
pub fn sign_context() -> SigningContext {
    SigningContext::production()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_config_default() {
        let config = SigningConfig::default();
        assert!(config.fulcio_url.contains("sigstore.dev"));
        assert!(config.rekor_url.contains("sigstore.dev"));
    }

    #[test]
    fn test_signing_context_creation() {
        let _context = SigningContext::new();
        let _prod = SigningContext::production();
        let _staging = SigningContext::staging();
    }
}
