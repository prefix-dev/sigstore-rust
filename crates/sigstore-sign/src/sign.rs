//! High-level signing API
//!
//! This module provides the main entry point for signing artifacts with Sigstore.

use crate::error::{Error, Result};
use sigstore_bundle::{BundleV03, TlogEntryBuilder};
use sigstore_crypto::{CertificatePem, KeyPair, Signature, SigningScheme};
use sigstore_fulcio::FulcioClient;
use sigstore_oidc::{parse_identity_token, IdentityToken};
use sigstore_rekor::{HashedRekord, RekorClient};
use sigstore_tsa::TimestampClient;
use sigstore_types::{Bundle, DerCertificate};

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
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            tsa_url: Some("https://timestamp.sigstore.dev/api/v1/timestamp".to_string()),
            signing_scheme: SigningScheme::EcdsaP256Sha256,
        }
    }
}

impl SigningConfig {
    /// Create configuration for Sigstore public-good instance
    pub fn production() -> Self {
        Self::default()
    }

    /// Create configuration for Sigstore staging instance
    pub fn staging() -> Self {
        Self {
            fulcio_url: "https://fulcio.sigstage.dev".to_string(),
            rekor_url: "https://rekor.sigstage.dev".to_string(),
            tsa_url: Some("https://timestamp.sigstage.dev/api/v1/timestamp".to_string()),
            signing_scheme: SigningScheme::EcdsaP256Sha256,
        }
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
}

impl Signer {
    /// Sign an artifact and return a Sigstore bundle
    ///
    /// # Arguments
    /// * `artifact` - The artifact bytes to sign
    ///
    /// # Returns
    /// A complete Sigstore bundle containing the signature, certificate chain, and transparency log entry
    ///
    /// # Example
    /// ```no_run
    /// use sigstore_sign::{SigningContext, Signer};
    /// use sigstore_oidc::IdentityToken;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let context = SigningContext::production();
    /// let token = IdentityToken::new("your-token-here".to_string());
    /// let signer = context.signer(token);
    /// let artifact = b"hello world";
    /// let bundle = signer.sign(artifact).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign(&self, artifact: &[u8]) -> Result<Bundle> {
        // 1. Generate ephemeral key pair
        let key_pair = self.generate_ephemeral_keypair()?;

        // 2. Get signing certificate from Fulcio
        let (leaf_cert_der, leaf_cert_pem) = self.request_certificate(&key_pair).await?;

        // 3. Sign the artifact
        let signature = key_pair.sign(artifact)?;

        // 4. Create Rekor entry (with certificate, not just public key)
        let tlog_entry = self
            .create_rekor_entry(artifact, &signature, &leaf_cert_pem)
            .await?;

        // 5. Get timestamp from TSA (optional)
        let timestamp_der = if let Some(tsa_url) = &self.tsa_url {
            Some(self.request_timestamp(tsa_url, &signature).await?)
        } else {
            None
        };

        // 6. Build bundle
        let artifact_hash = sigstore_crypto::sha256(artifact);
        let mut bundle =
            BundleV03::with_certificate_and_signature(leaf_cert_der, signature, artifact_hash)
                .with_tlog_entry(tlog_entry.build());

        if let Some(ts_der) = timestamp_der {
            bundle = bundle.with_rfc3161_timestamp(ts_der);
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
    /// Returns the leaf certificate as (DerCertificate, PEM string).
    async fn request_certificate(&self, key_pair: &KeyPair) -> Result<(DerCertificate, String)> {
        // Parse identity token to extract email or subject
        let token_info = parse_identity_token(self.identity_token.raw())?;
        let subject = token_info.email().unwrap_or(token_info.subject());

        // Export public key to PEM
        let public_key_pem = key_pair
            .public_key_to_pem()
            .map_err(|e| Error::Signing(format!("Failed to export public key: {}", e)))?;

        // Create proof of possession
        let proof_of_possession = key_pair.sign(subject.as_bytes())?;

        // Create Fulcio client and request certificate
        let fulcio = FulcioClient::new(&self.fulcio_url);
        let cert_response = fulcio
            .create_signing_certificate(
                self.identity_token.raw(),
                &public_key_pem,
                &proof_of_possession,
            )
            .await
            .map_err(|e| Error::Signing(format!("Failed to get certificate from Fulcio: {}", e)))?;

        // Get the leaf certificate (v0.3 bundles use single cert, not chain)
        let leaf_cert_pem = cert_response
            .leaf_certificate()
            .ok_or_else(|| Error::Signing("No leaf certificate in response".to_string()))?
            .to_string();

        // Parse PEM to type-safe DerCertificate (validates CERTIFICATE header)
        let leaf_cert_der = DerCertificate::from_pem(&leaf_cert_pem)
            .map_err(|e| Error::Signing(format!("Invalid certificate PEM: {}", e)))?;

        Ok((leaf_cert_der, leaf_cert_pem))
    }

    /// Create a Rekor entry for the signed artifact
    async fn create_rekor_entry(
        &self,
        artifact: &[u8],
        signature: &Signature,
        certificate_pem: &str,
    ) -> Result<TlogEntryBuilder> {
        // Compute artifact hash
        let artifact_hash = sigstore_crypto::sha256(artifact);

        // Use the certificate PEM for Rekor (not just the public key)
        // This is required for proper verification - the Rekor entry must contain
        // the certificate so verifiers can match it against the bundle
        let cert_pem_obj = CertificatePem::new(certificate_pem.to_string());

        // Create hashedrekord entry with the certificate
        let hashed_rekord = HashedRekord::new(&artifact_hash, signature, &cert_pem_obj);

        // Create Rekor client and upload
        let rekor = RekorClient::new(&self.rekor_url);
        let log_entry = rekor
            .create_entry(hashed_rekord)
            .await
            .map_err(|e| Error::Signing(format!("Failed to create Rekor entry: {}", e)))?;

        // Build TlogEntry from the log entry response
        let tlog_builder = TlogEntryBuilder::from_log_entry(&log_entry, "hashedrekord", "0.0.1");

        Ok(tlog_builder)
    }

    /// Request a timestamp from the Timestamp Authority
    async fn request_timestamp(&self, tsa_url: &str, signature: &Signature) -> Result<Vec<u8>> {
        let signature_digest = sigstore_crypto::sha256(signature.as_bytes());
        let tsa = TimestampClient::new(tsa_url.to_string());
        tsa.timestamp_sha256(&signature_digest)
            .await
            .map_err(|e| Error::Signing(format!("Failed to get timestamp: {}", e)))
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
