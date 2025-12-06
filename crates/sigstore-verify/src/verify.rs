//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

use crate::error::{Error, Result};
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::parse_certificate_info;
use sigstore_trust_root::TrustedRoot;

use sigstore_types::{Artifact, Bundle, Sha256Hash, SignatureContent, Statement};

/// Default clock skew tolerance in seconds (60 seconds = 1 minute)
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;

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
    /// Clock skew tolerance in seconds for time validation
    ///
    /// This allows for a tolerance when checking that integrated times
    /// are not in the future. Default is 60 seconds.
    pub clock_skew_seconds: i64,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            identity: None,
            issuer: None,
            verify_tlog: true,
            verify_timestamp: true,
            verify_certificate: true,
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
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

    /// Skip certificate chain verification
    ///
    /// WARNING: This is unsafe for production use. Only use for testing
    /// with bundles that don't chain to the trusted root.
    pub fn skip_certificate_chain(mut self) -> Self {
        self.verify_certificate = false;
        self
    }

    /// Set the clock skew tolerance in seconds
    ///
    /// This allows for a tolerance when checking that integrated times
    /// are not in the future. Default is 60 seconds.
    pub fn with_clock_skew_seconds(mut self, seconds: i64) -> Self {
        self.clock_skew_seconds = seconds;
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
    trusted_root: TrustedRoot,
}

impl Verifier {
    /// Create a new verifier with a trusted root
    ///
    /// The trusted root is required and contains all cryptographic material
    /// needed for verification (Fulcio CA certs, Rekor keys, TSA certs, etc.)
    pub fn new(trusted_root: &TrustedRoot) -> Self {
        Self {
            trusted_root: trusted_root.clone(),
        }
    }

    /// Verify an artifact against a bundle
    ///
    /// The artifact can be provided as raw bytes or as a pre-computed SHA-256 digest.
    /// When using a pre-computed digest, the raw bytes are not needed, which is useful
    /// for large files or when the digest is already known (e.g., from a registry).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_verify::{Verifier, VerificationPolicy};
    /// use sigstore_trust_root::TrustedRoot;
    /// use sigstore_types::{Artifact, Bundle, Sha256Hash};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let trusted_root = TrustedRoot::production()?;
    /// let verifier = Verifier::new(&trusted_root);
    /// let bundle: Bundle = todo!();
    /// let policy = VerificationPolicy::default();
    ///
    /// // Option 1: Verify with raw bytes
    /// let artifact_bytes = b"hello world";
    /// verifier.verify(artifact_bytes.as_slice(), &bundle, &policy)?;
    ///
    /// // Option 2: Verify with pre-computed digest (no raw bytes needed!)
    /// let digest = Sha256Hash::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")?;
    /// verifier.verify(digest, &bundle, &policy)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// In order to verify an artifact, we need to achieve the following:
    ///
    /// 0. Establish a time for the signature.
    /// 1. Verify that the signing certificate chains to the root of trust
    ///    and is valid at the time of signing.
    /// 2. Verify the signing certificate's SCT.
    /// 3. Verify that the signing certificate conforms to the Sigstore
    ///    X.509 profile as well as the passed-in `VerificationPolicy`.
    /// 4. Verify the inclusion proof and signed checkpoint for the log
    ///    entry.
    /// 5. Verify the inclusion promise for the log entry, if present.
    /// 6. Verify the timely insertion of the log entry against the validity
    ///    period for the signing certificate.
    /// 7. Verify the signature and input against the signing certificate's
    ///    public key.
    /// 8. Verify the transparency log entry's consistency against the other
    ///    materials, to prevent variants of CVE-2022-36056.
    pub fn verify<'a>(
        &self,
        artifact: impl Into<Artifact<'a>>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let artifact = artifact.into();
        let mut result = VerificationResult::success();

        // Validate bundle structure first
        let options = ValidationOptions {
            require_inclusion_proof: policy.verify_tlog,
            require_timestamp: false, // Don't require timestamps, but verify if present
        };
        validate_bundle_with_options(bundle, &options)
            .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

        // Extract certificate for verification
        let cert = crate::verify_impl::helpers::extract_certificate(
            &bundle.verification_material.content,
        )?;
        let cert_info = parse_certificate_info(cert.as_bytes())
            .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

        // Store identity and issuer in result
        result.identity = cert_info.identity.clone();
        result.issuer = cert_info.issuer.clone();

        // (0): Establish a time for the signature
        // First, establish verified times for the signature. This is required to
        // validate the certificate chain, so this step comes first.
        // These include TSA timestamps and (in the case of rekor v1 entries)
        // rekor log integrated time.
        let signature = crate::verify_impl::helpers::extract_signature(&bundle.content)?;
        let validation_time = crate::verify_impl::helpers::determine_validation_time(
            bundle,
            &signature,
            &self.trusted_root,
        )?;

        // (1): Verify that the signing certificate chains to the root of trust,
        //      is valid at the time of signing, and has CODE_SIGNING EKU.
        if policy.verify_certificate {
            crate::verify_impl::helpers::verify_certificate_chain(
                &bundle.verification_material.content,
                validation_time,
                &self.trusted_root,
            )?;

            // Also verify the certificate is within its validity period
            crate::verify_impl::helpers::validate_certificate_time(validation_time, &cert_info)?;

            // (2): Verify the signing certificate's SCT.
            crate::verify_impl::helpers::verify_sct(
                &bundle.verification_material.content,
                &self.trusted_root,
            )?;
        }

        // (3): Verify against the given `VerificationPolicy`.

        // Verify against policy constraints
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

        // (4): Verify the inclusion proof and signed checkpoint for the log entry.
        // (5): Verify the inclusion promise for the log entry, if present.
        // (6): Verify the timely insertion of the log entry against the validity
        //      period for the signing certificate.
        if policy.verify_tlog {
            let integrated_time = crate::verify_impl::tlog::verify_tlog_entries(
                bundle,
                &self.trusted_root,
                cert_info.not_before,
                cert_info.not_after,
                policy.clock_skew_seconds,
            )?;

            if let Some(time) = integrated_time {
                result.integrated_time = Some(time);
            }
        }

        // (7): Verify the signature and input against the signing certificate's
        //      public key.
        // For DSSE envelopes, verify using PAE (Pre-Authentication Encoding)
        if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
            let payload_bytes = envelope.decode_payload();

            // Compute the PAE that was signed
            let pae = sigstore_types::pae(&envelope.payload_type, &payload_bytes);

            // Verify at least one signature is cryptographically valid
            let mut any_sig_valid = false;
            for sig in &envelope.signatures {
                if sigstore_crypto::verify_signature(
                    &cert_info.public_key,
                    &pae,
                    &sig.sig,
                    cert_info.signing_scheme,
                )
                .is_ok()
                {
                    any_sig_valid = true;
                    break;
                }
            }

            if !any_sig_valid {
                return Err(Error::Verification(
                    "DSSE signature verification failed: no valid signatures found".to_string(),
                ));
            }

            // Verify artifact hash matches (for DSSE with in-toto statements)
            if envelope.payload_type == "application/vnd.in-toto+json" {
                let payload_bytes = envelope.payload.as_bytes();

                let artifact_hash = compute_artifact_digest(&artifact);
                let artifact_hash_hex = artifact_hash.to_hex();

                let payload_str = std::str::from_utf8(payload_bytes).map_err(|e| {
                    Error::Verification(format!("payload is not valid UTF-8: {}", e))
                })?;

                let statement: Statement = serde_json::from_str(payload_str).map_err(|e| {
                    Error::Verification(format!("failed to parse in-toto statement: {}", e))
                })?;

                if !statement.subject.is_empty() && !statement.matches_sha256(&artifact_hash_hex) {
                    return Err(Error::Verification(
                        "artifact hash does not match any subject in attestation".to_string(),
                    ));
                }
            }
        }

        // For MessageSignature bundles, verify the messageDigest matches the artifact
        if let SignatureContent::MessageSignature(msg_sig) = &bundle.content {
            if let Some(ref digest) = msg_sig.message_digest {
                let artifact_hash = compute_artifact_digest(&artifact);

                // Compare the digest in the bundle with the computed artifact hash
                if digest.digest.as_bytes() != artifact_hash.as_bytes() {
                    return Err(Error::Verification(
                        "message digest in bundle does not match artifact hash".to_string(),
                    ));
                }
            }
        }
        // Note: For hashedrekord (MessageSignature), the signature verification
        // is performed in step (8) by verify_hashedrekord_entries, which properly
        // handles prehashed signatures.

        // (8): Verify the transparency log entry's consistency against the other
        //      materials, to prevent variants of CVE-2022-36056.
        crate::verify_impl::verify_dsse_entries(bundle)?;
        crate::verify_impl::verify_intoto_entries(bundle)?;
        crate::verify_impl::verify_hashedrekord_entries(bundle, &artifact)?;

        Ok(result)
    }
}

/// Compute the SHA-256 digest from an artifact
fn compute_artifact_digest(artifact: &Artifact<'_>) -> Sha256Hash {
    match artifact {
        Artifact::Bytes(bytes) => sigstore_crypto::sha256(bytes),
        Artifact::Digest(hash) => *hash,
    }
}

/// Convenience function to verify an artifact against a bundle
///
/// This uses the trusted root for all cryptographic material
/// (Rekor keys, Fulcio certs, TSA certs).
///
/// The artifact can be provided as raw bytes or as a pre-computed SHA-256 digest:
/// - `verify(artifact_bytes, ...)` - pass raw bytes
/// - `verify(Sha256Hash::from_hex("...")?, ...)` - pass pre-computed digest
pub fn verify<'a>(
    artifact: impl Into<Artifact<'a>>,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let verifier = Verifier::new(trusted_root);
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
}
