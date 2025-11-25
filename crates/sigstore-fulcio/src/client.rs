//! Fulcio client for certificate operations

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sigstore_crypto::{PublicKeyPem, Signature};
use sigstore_types::SignatureBytes;

/// A client for interacting with Fulcio
pub struct FulcioClient {
    /// Base URL of the Fulcio instance
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl FulcioClient {
    /// Create a new Fulcio client
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for the public Sigstore Fulcio instance
    pub fn public() -> Self {
        Self::new("https://fulcio.sigstore.dev")
    }

    /// Create a client for the Sigstore staging Fulcio instance
    pub fn staging() -> Self {
        Self::new("https://fulcio.sigstage.dev")
    }

    /// Get the OIDC configuration (supported issuers)
    pub async fn get_configuration(&self) -> Result<Configuration> {
        let url = format!("{}/api/v2/configuration", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get configuration: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Request a signing certificate
    ///
    /// # Arguments
    /// * `identity_token` - The OIDC identity token
    /// * `public_key` - The public key in PEM format
    /// * `proof_of_possession` - Signature proving possession of the private key
    pub async fn create_signing_certificate(
        &self,
        identity_token: &str,
        public_key: &PublicKeyPem,
        proof_of_possession: &Signature,
    ) -> Result<SigningCertificate> {
        let url = format!("{}/api/v2/signingCert", self.url);

        let request = CreateSigningCertificateRequest {
            credentials: Credentials {
                oidc_identity_token: identity_token.to_string(),
            },
            public_key_request: PublicKeyRequest {
                public_key: PublicKeyData {
                    algorithm: String::new(), // Not needed for PEM (contains algorithm info)
                    content: public_key.as_str().to_string(),
                },
                proof_of_possession: proof_of_possession.clone().into(),
            },
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create signing certificate: {} - {}",
                status, body
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Get the trust bundle (CA certificates)
    pub async fn get_trust_bundle(&self) -> Result<TrustBundle> {
        let url = format!("{}/api/v2/trustBundle", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get trust bundle: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }
}

/// OIDC configuration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    /// List of supported OIDC issuers
    pub issuers: Vec<OIDCIssuer>,
}

/// OIDC issuer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OIDCIssuer {
    /// Issuer URL
    pub issuer_url: String,
    /// Audience
    pub audience: String,
    /// Challenge claim
    #[serde(default)]
    pub challenge_claim: Option<String>,
    /// SPIFFE trust domain
    #[serde(default)]
    pub spiffe_trust_domain: Option<String>,
}

/// Request to create a signing certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSigningCertificateRequest {
    /// OIDC credentials
    pub credentials: Credentials,
    /// Public key request
    pub public_key_request: PublicKeyRequest,
}

/// OIDC credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    /// OIDC identity token
    pub oidc_identity_token: String,
}

/// Public key request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyRequest {
    /// Public key
    pub public_key: PublicKeyData,
    /// Proof of possession (signature)
    pub proof_of_possession: SignatureBytes,
}

/// Public key data for API requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyData {
    /// Algorithm (ECDSA, RSA, ED25519) - optional when using PEM format
    pub algorithm: String,
    /// PEM or DER-encoded key content
    pub content: String,
}

/// Signing certificate response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificate {
    /// Certificate chain
    #[serde(default)]
    pub signed_certificate_embedded_sct: Option<CertificateChain>,
    /// Certificate with detached SCT
    #[serde(default)]
    pub signed_certificate_detached_sct: Option<CertificateWithSCT>,
}

/// Certificate chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    /// Chain of certificates (PEM encoded)
    pub chain: ChainContent,
}

/// Chain content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainContent {
    /// Certificates in the chain
    pub certificates: Vec<String>,
}

/// Certificate with detached SCT
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateWithSCT {
    /// Certificate chain
    pub chain: ChainContent,
    /// Signed certificate timestamp
    pub signed_certificate_timestamp: String,
}

/// Trust bundle response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBundle {
    /// Certificate chains
    pub chains: Vec<CertificateChain>,
}

impl SigningCertificate {
    /// Get the leaf certificate (PEM encoded)
    pub fn leaf_certificate(&self) -> Option<&str> {
        if let Some(embedded) = &self.signed_certificate_embedded_sct {
            embedded.chain.certificates.first().map(|s| s.as_str())
        } else if let Some(detached) = &self.signed_certificate_detached_sct {
            detached.chain.certificates.first().map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Get all certificates in the chain
    pub fn certificate_chain(&self) -> Option<&[String]> {
        if let Some(embedded) = &self.signed_certificate_embedded_sct {
            Some(&embedded.chain.certificates)
        } else if let Some(detached) = &self.signed_certificate_detached_sct {
            Some(&detached.chain.certificates)
        } else {
            None
        }
    }
}
