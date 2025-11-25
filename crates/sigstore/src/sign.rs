//! High-level signing API
//!
//! This module provides the main entry point for signing artifacts with Sigstore.

use crate::bundle::{BundleBuilder, TlogEntryBuilder};
use crate::crypto::{KeyPair, PublicKeyPem, Signature};
use crate::error::{Error, Result};
use crate::rekor::{HashedRekord, RekorClient};
use crate::types::{Bundle, MediaType, Sha256Hash};
use base64::Engine as _;
use sigstore_crypto::SigningScheme;
use sigstore_fulcio::FulcioClient;
use sigstore_oidc::{parse_identity_token, IdentityToken};
use sigstore_tsa::TimestampClient;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::Certificate;

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
    /// use sigstore::sign::SigningContext;
    /// use sigstore::oidc::IdentityToken;
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

        // 2. Get certificate from Fulcio
        let (chain_der_b64, _leaf_cert_pem) = self.request_certificate(&key_pair).await?;

        // 3. Sign the artifact
        let signature = key_pair.sign(artifact)?;

        // 4. Create Rekor entry
        let (tlog_entry, _public_key_pem) = self
            .create_rekor_entry(artifact, &signature, &key_pair)
            .await?;

        // 5. Get timestamp from TSA (optional)
        let timestamp_b64 = if let Some(tsa_url) = &self.tsa_url {
            Some(self.request_timestamp(tsa_url, &signature).await?)
        } else {
            None
        };

        // 6. Build and return bundle
        self.build_bundle(chain_der_b64, signature, tlog_entry, timestamp_b64)
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
    async fn request_certificate(&self, key_pair: &KeyPair) -> Result<(Vec<String>, String)> {
        // Parse identity token to extract email or subject
        let token_info = parse_identity_token(self.identity_token.raw())?;
        let subject = token_info.email().unwrap_or(token_info.subject());

        // Export public key to PEM
        let public_key_pem = key_pair
            .public_key_to_pem()
            .map_err(|e| Error::Signing(format!("Failed to export public key: {}", e)))?;

        // Create proof of possession
        let proof_of_possession = key_pair.sign(subject.as_bytes())?;

        // Create Fulcio client
        let fulcio = FulcioClient::new(&self.fulcio_url);

        // Request certificate from Fulcio
        let cert_response = fulcio
            .create_signing_certificate(
                self.identity_token.raw(),
                &public_key_pem,
                &proof_of_possession,
            )
            .await
            .map_err(|e| Error::Signing(format!("Failed to get certificate from Fulcio: {}", e)))?;

        let leaf_cert_pem = cert_response
            .leaf_certificate()
            .ok_or_else(|| Error::Signing("No leaf certificate in response".to_string()))?;

        // Extract full chain and filter out CA certificates
        let chain_pem = cert_response
            .certificate_chain()
            .ok_or_else(|| Error::Signing("No certificate chain in response".to_string()))?;

        let chain_der_b64 = self.filter_ca_certificates(chain_pem)?;

        Ok((chain_der_b64, leaf_cert_pem.to_string()))
    }

    /// Filter out CA certificates from the certificate chain
    /// The conformance test test_sign_does_not_produce_root asserts that no cert in the bundle is a CA.
    fn filter_ca_certificates(&self, chain_pem: &[String]) -> Result<Vec<String>> {
        let mut chain_der_b64 = Vec::new();

        for cert_pem in chain_pem {
            let der_b64 = pem_to_der_base64(cert_pem)?;
            let der = base64::engine::general_purpose::STANDARD
                .decode(&der_b64)
                .map_err(|e| Error::Signing(format!("Failed to decode certificate: {}", e)))?;

            if let Ok(cert) = Certificate::from_der(&der) {
                // Check BasicConstraints to exclude CA certificates (Root and Intermediates)
                let basic_constraints_oid = "2.5.29.19"
                    .parse::<x509_cert::der::asn1::ObjectIdentifier>()
                    .map_err(|e| Error::Signing(format!("Invalid OID: {}", e)))?;

                let mut is_ca = false;
                if let Some(extensions) = &cert.tbs_certificate.extensions {
                    for ext in extensions.iter() {
                        if ext.extn_id == basic_constraints_oid {
                            if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                                if bc.ca {
                                    is_ca = true;
                                }
                            }
                        }
                    }
                }

                if is_ca {
                    continue;
                }
            }

            chain_der_b64.push(der_b64);
        }

        Ok(chain_der_b64)
    }

    /// Create a Rekor entry for the signed artifact
    async fn create_rekor_entry(
        &self,
        artifact: &[u8],
        signature: &Signature,
        key_pair: &KeyPair,
    ) -> Result<(TlogEntryBuilder, PublicKeyPem)> {
        // Compute artifact hash
        let hash_bytes = sigstore_crypto::sha256(artifact);
        let artifact_hash = Sha256Hash::from_bytes(hash_bytes);

        // Export public key for Rekor
        let public_key_pem = key_pair
            .public_key_to_pem()
            .map_err(|e| Error::Signing(format!("Failed to export public key: {}", e)))?;
        let public_key_pem_obj = PublicKeyPem::new(public_key_pem.to_string());

        // Create hashedrekord entry
        let hashed_rekord = HashedRekord::new(&artifact_hash, signature, &public_key_pem_obj);

        // Create Rekor client and upload
        let rekor = RekorClient::new(&self.rekor_url);
        let log_entry = rekor
            .create_entry(hashed_rekord)
            .await
            .map_err(|e| Error::Signing(format!("Failed to create Rekor entry: {}", e)))?;

        // Build TlogEntry from the log entry response
        let tlog_builder = TlogEntryBuilder::from_log_entry(&log_entry, "hashedrekord", "0.0.1");

        Ok((tlog_builder, public_key_pem_obj))
    }

    /// Request a timestamp from the Timestamp Authority
    async fn request_timestamp(&self, tsa_url: &str, signature: &Signature) -> Result<String> {
        // Hash the signature
        let signature_digest = sigstore_crypto::sha256(signature.as_bytes());

        // Create TSA client and request timestamp
        let tsa = TimestampClient::new(tsa_url.to_string());
        let timestamp_der = tsa
            .timestamp_sha256(&signature_digest)
            .await
            .map_err(|e| Error::Signing(format!("Failed to get timestamp: {}", e)))?;

        // Encode to base64
        let timestamp_b64 = base64::engine::general_purpose::STANDARD.encode(&timestamp_der);
        Ok(timestamp_b64)
    }

    /// Build the final Sigstore bundle
    fn build_bundle(
        &self,
        chain_der_b64: Vec<String>,
        signature: Signature,
        tlog_builder: TlogEntryBuilder,
        timestamp_b64: Option<String>,
    ) -> Result<Bundle> {
        // Decode certificate chain from base64 to DER bytes
        let chain_der: Vec<Vec<u8>> = chain_der_b64
            .into_iter()
            .map(|cert_b64| {
                base64::engine::general_purpose::STANDARD
                    .decode(&cert_b64)
                    .map_err(|e| Error::Signing(format!("Invalid certificate base64: {}", e)))
            })
            .collect::<Result<Vec<_>>>()?;

        // Build bundle with raw bytes
        let mut bundle_builder = BundleBuilder::new()
            .version(MediaType::Bundle0_2)
            .certificate_chain(chain_der)
            .message_signature(signature.into_bytes())
            .add_tlog_entry(tlog_builder.build());

        // Add timestamp if present
        if let Some(ts_b64) = timestamp_b64 {
            let ts_bytes = base64::engine::general_purpose::STANDARD
                .decode(&ts_b64)
                .map_err(|e| Error::Signing(format!("Invalid timestamp base64: {}", e)))?;
            bundle_builder = bundle_builder.add_rfc3161_timestamp(ts_bytes);
        }

        bundle_builder
            .build()
            .map_err(|e| Error::Signing(format!("Failed to build bundle: {}", e)))
    }
}

/// Convenience function to create a signing context
pub fn sign_context() -> SigningContext {
    SigningContext::production()
}

/// Convert PEM certificate to base64-encoded DER
fn pem_to_der_base64(pem: &str) -> Result<String> {
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem
        .find(start_marker)
        .ok_or_else(|| Error::Signing("Invalid PEM: missing start marker".to_string()))?;
    let end = pem
        .find(end_marker)
        .ok_or_else(|| Error::Signing("Invalid PEM: missing end marker".to_string()))?;

    if start > end {
        return Err(Error::Signing("Invalid PEM: start after end".to_string()));
    }

    let content = &pem[start + start_marker.len()..end];
    let clean_content: String = content.chars().filter(|c| !c.is_whitespace()).collect();

    Ok(clean_content)
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
