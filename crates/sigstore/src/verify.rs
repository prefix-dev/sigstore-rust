//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

// Private submodules for verification logic
#[path = "verify_impl/mod.rs"]
mod verify_impl;

use crate::error::{Error, Result};
use base64::Engine;
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::parse_certificate_info;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_trust_root::TrustedRoot;

use sigstore_types::{Bundle, Sha256Hash, SignatureContent, Statement};

/// Policy for verifying signatures
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Expected identity (email or URI)
    pub identity: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Verify transparency log inclusion
    pub verify_tlog: bool,
    /// Verify timestamp
    pub verify_timestamp: bool,
    /// Verify certificate chain
    pub verify_certificate: bool,
    /// Skip artifact hash validation (for digest-only verification)
    pub skip_artifact_hash: bool,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            identity: None,
            issuer: None,
            verify_tlog: true,
            verify_timestamp: true,
            verify_certificate: true,
            skip_artifact_hash: false,
        }
    }
}

impl VerificationPolicy {
    /// Create a policy that requires a specific identity
    pub fn with_identity(identity: impl Into<String>) -> Self {
        Self {
            identity: Some(identity.into()),
            ..Default::default()
        }
    }

    /// Create a policy that requires a specific issuer
    pub fn with_issuer(issuer: impl Into<String>) -> Self {
        Self {
            issuer: Some(issuer.into()),
            ..Default::default()
        }
    }

    /// Require a specific identity
    pub fn require_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Require a specific issuer
    pub fn require_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Skip transparency log verification
    pub fn skip_tlog(mut self) -> Self {
        self.verify_tlog = false;
        self
    }

    /// Skip timestamp verification
    pub fn skip_timestamp(mut self) -> Self {
        self.verify_timestamp = false;
        self
    }

    /// Skip artifact hash validation (for digest-only verification)
    pub fn skip_artifact_hash(mut self) -> Self {
        self.skip_artifact_hash = true;
        self
    }
}

/// Result of verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub success: bool,
    /// Identity from the certificate
    pub identity: Option<String>,
    /// Issuer from the certificate
    pub issuer: Option<String>,
    /// Integrated time from transparency log
    pub integrated_time: Option<i64>,
    /// Any warnings during verification
    pub warnings: Vec<String>,
}

impl VerificationResult {
    /// Create a successful result
    pub fn success() -> Self {
        Self {
            success: true,
            identity: None,
            issuer: None,
            integrated_time: None,
            warnings: Vec::new(),
        }
    }

    /// Create a failed result
    pub fn failure() -> Self {
        Self {
            success: false,
            identity: None,
            issuer: None,
            integrated_time: None,
            warnings: Vec::new(),
        }
    }
}

/// A verifier for Sigstore signatures
pub struct Verifier {
    /// Trusted root containing verification material
    trusted_root: Option<TrustedRoot>,
}

impl Verifier {
    /// Create a new verifier with no trusted material
    pub fn new() -> Self {
        Self { trusted_root: None }
    }

    /// Create a verifier from a trusted root
    pub fn from_trusted_root(trusted_root: TrustedRoot) -> Self {
        let mut verifier = Self::new();
        verifier.trusted_root = Some(trusted_root);
        verifier
    }

    /// Create a verifier from a trusted root
    pub fn new_with_trusted_root(trusted_root: &TrustedRoot) -> Self {
        let mut verifier = Self::new();
        verifier.trusted_root = Some(trusted_root.clone());
        verifier
    }

    /// Verify an artifact against a bundle
    pub fn verify(
        &self,
        artifact: &[u8],
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();

        // 1. Validate bundle structure
        // Note: We don't require timestamps, but we do verify them if present
        let options = ValidationOptions {
            require_inclusion_proof: policy.verify_tlog,
            require_timestamp: false, // Don't require timestamps, but verify if present
        };

        validate_bundle_with_options(bundle, &options)
            .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

        // 2. Extract and parse certificate
        let cert_der =
            verify_impl::helpers::extract_certificate_der(&bundle.verification_material.content)?;
        let cert_info = parse_certificate_info(&cert_der)
            .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

        // Store identity in result
        result.identity = cert_info.identity.clone();

        // 3. Determine validation time from timestamps
        let signature_bytes = verify_impl::helpers::extract_signature_bytes(&bundle.content)?;
        let validation_time = verify_impl::helpers::determine_validation_time(
            bundle,
            &signature_bytes,
            self.trusted_root.as_ref(),
        )?;

        // 4. Validate certificate is within validity period
        verify_impl::helpers::validate_certificate_time(validation_time, &cert_info)?;

        // 5.5. Verify DSSE payload matches what's in Rekor (for intoto entries)
        if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
            for entry in &bundle.verification_material.tlog_entries {
                if entry.kind_version.kind == "intoto" {
                    // Parse the Rekor entry body using typed structures
                    let body = RekorEntryBody::from_base64_json(
                        &entry.canonicalized_body,
                        &entry.kind_version.kind,
                        &entry.kind_version.version,
                    )
                    .map_err(|e| {
                        Error::Verification(format!("failed to parse Rekor body: {}", e))
                    })?;

                    let (rekor_payload_b64, rekor_signatures) = match &body {
                        RekorEntryBody::IntotoV002(intoto_body) => (
                            &intoto_body.spec.content.envelope.payload,
                            &intoto_body.spec.content.envelope.signatures,
                        ),
                        _ => {
                            return Err(Error::Verification(
                                "expected Intoto v0.0.2 body, got different type".to_string(),
                            ))
                        }
                    };

                    // The Rekor entry has the payload double-base64-encoded, decode it once
                    let rekor_payload_bytes = base64::engine::general_purpose::STANDARD
                        .decode(rekor_payload_b64)
                        .map_err(|e| {
                            Error::Verification(format!("failed to decode Rekor payload: {}", e))
                        })?;

                    let rekor_payload = String::from_utf8(rekor_payload_bytes).map_err(|e| {
                        Error::Verification(format!("Rekor payload not valid UTF-8: {}", e))
                    })?;

                    // Compare with bundle payload
                    if envelope.payload != rekor_payload {
                        return Err(Error::Verification(
                            "DSSE payload in bundle does not match intoto Rekor entry".to_string(),
                        ));
                    }

                    // Also validate that the signatures match
                    // Check that at least one signature from the bundle matches Rekor
                    let mut found_match = false;
                    for bundle_sig in &envelope.signatures {
                        for rekor_sig in rekor_signatures {
                            // The Rekor signature is also double-base64-encoded, decode it once
                            let rekor_sig_decoded = base64::engine::general_purpose::STANDARD
                                .decode(&rekor_sig.sig)
                                .map_err(|e| {
                                    Error::Verification(format!(
                                        "failed to decode Rekor signature: {}",
                                        e
                                    ))
                                })?;

                            let rekor_sig_content =
                                String::from_utf8(rekor_sig_decoded).map_err(|e| {
                                    Error::Verification(format!(
                                        "Rekor signature not valid UTF-8: {}",
                                        e
                                    ))
                                })?;

                            if bundle_sig.sig == rekor_sig_content {
                                found_match = true;
                                break;
                            }
                        }
                        if found_match {
                            break;
                        }
                    }

                    if !found_match {
                        return Err(Error::Verification(
                            "DSSE signature in bundle does not match intoto Rekor entry"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // 6. Verify Rekor entries (DSSE, intoto, hashedrekord)
        verify_impl::verify_dsse_entries(bundle)?;
        verify_impl::verify_intoto_entries(bundle)?;
        verify_impl::verify_hashedrekord_entries(bundle, artifact, policy.skip_artifact_hash)?;

        // 7. Verify artifact hash matches (for DSSE with in-toto statements)
        if !policy.skip_artifact_hash {
            if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
                if envelope.payload_type == "application/vnd.in-toto+json" {
                    // Decode payload
                    let payload_bytes = base64::engine::general_purpose::STANDARD
                        .decode(&envelope.payload)
                        .map_err(|e| {
                            Error::Verification(format!("failed to decode payload: {}", e))
                        })?;

                    // Compute artifact hash
                    let artifact_hash = Sha256Hash::from_bytes(sigstore_crypto::sha256(artifact));
                    let artifact_hash_hex = artifact_hash.to_hex();

                    // Parse the in-toto statement using typed structs
                    let payload_str = String::from_utf8(payload_bytes).map_err(|e| {
                        Error::Verification(format!("payload is not valid UTF-8: {}", e))
                    })?;

                    let statement: Statement = serde_json::from_str(&payload_str).map_err(|e| {
                        Error::Verification(format!("failed to parse in-toto statement: {}", e))
                    })?;

                    // Check if artifact hash matches any subject
                    if !statement.subject.is_empty()
                        && !statement.matches_sha256(&artifact_hash_hex)
                    {
                        return Err(Error::Verification(
                            "artifact hash does not match any subject in attestation".to_string(),
                        ));
                    }
                }
            }
        }

        // 7. Extract and validate integrated time from tlog entries
        if policy.verify_tlog {
            let integrated_time = verify_impl::tlog::verify_tlog_entries(
                bundle,
                self.trusted_root.as_ref(),
                cert_info.not_before,
                cert_info.not_after,
            )?;

            if let Some(time) = integrated_time {
                result.integrated_time = Some(time);
            }
        }

        // 7. Check policy constraints
        if let Some(ref expected_identity) = policy.identity {
            if let Some(ref actual_identity) = result.identity {
                if actual_identity != expected_identity {
                    return Err(Error::Verification(format!(
                        "identity mismatch: expected {}, got {}",
                        expected_identity, actual_identity
                    )));
                }
            }
        }

        if let Some(ref expected_issuer) = policy.issuer {
            if let Some(ref actual_issuer) = result.issuer {
                if actual_issuer != expected_issuer {
                    return Err(Error::Verification(format!(
                        "issuer mismatch: expected {}, got {}",
                        expected_issuer, actual_issuer
                    )));
                }
            }
        }

        Ok(result)
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to verify an artifact
pub fn verify(
    artifact: &[u8],
    bundle: &Bundle,
    policy: &VerificationPolicy,
) -> Result<VerificationResult> {
    let verifier = Verifier::new();
    verifier.verify(artifact, bundle, policy)
}

/// Verify an artifact against a bundle using a trusted root
///
/// This is the recommended verification method as it uses the trusted root
/// for all cryptographic material (Rekor keys, Fulcio certs, TSA certs).
pub fn verify_with_trusted_root(
    artifact: &[u8],
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let verifier = Verifier::new_with_trusted_root(trusted_root);
    verifier.verify(artifact, bundle, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_policy_default() {
        let policy = VerificationPolicy::default();
        assert!(policy.verify_tlog);
        assert!(policy.verify_timestamp);
        assert!(policy.verify_certificate);
    }

    #[test]
    fn test_verification_policy_builder() {
        let policy = VerificationPolicy::default()
            .require_identity("test@example.com")
            .require_issuer("https://accounts.google.com")
            .skip_tlog();

        assert_eq!(policy.identity, Some("test@example.com".to_string()));
        assert_eq!(
            policy.issuer,
            Some("https://accounts.google.com".to_string())
        );
        assert!(!policy.verify_tlog);
    }

    #[test]
    fn test_verifier_creation() {
        let _verifier = Verifier::new();
        let _default = Verifier::default();
    }
}
