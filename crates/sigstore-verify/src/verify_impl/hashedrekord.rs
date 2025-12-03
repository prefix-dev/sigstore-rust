//! HashedRekord entry validation
//!
//! This module handles validation of hashedrekord entries, including
//! artifact hash verification and certificate/signature matching.

use crate::error::{Error, Result};
use base64::Engine;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::proto::{Bundle, TransparencyLogEntry};
use sigstore_types::{Artifact, Sha256Hash, SignatureBytes};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Verify artifact hash matches what's in Rekor (for hashedrekord entries)
pub fn verify_hashedrekord_entries(bundle: &Bundle, artifact: &Artifact<'_>) -> Result<()> {
    let vm = match bundle.verification_material() {
        Some(vm) => vm,
        None => return Ok(()),
    };

    for entry in vm.tlog_entries() {
        let kind = entry.kind().unwrap_or("");
        if kind == "hashedrekord" {
            verify_hashedrekord_entry(&entry, bundle, artifact)?;
        }
    }
    Ok(())
}

/// Verify a single hashedrekord entry
fn verify_hashedrekord_entry(
    entry: &TransparencyLogEntry<'_>,
    bundle: &Bundle,
    artifact: &Artifact<'_>,
) -> Result<()> {
    // Parse the Rekor entry body (convert canonicalized body to base64 string)
    let kind = entry.kind().unwrap_or("hashedrekord");
    let version = entry.version().unwrap_or("0.0.1");
    let body_bytes = entry.canonicalized_body_bytes();
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(body_bytes);

    let body = RekorEntryBody::from_base64_json(&body_b64, kind, version)
        .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    // Compute artifact hash from artifact (bytes or pre-computed digest)
    let artifact_hash = compute_artifact_digest(artifact);

    // Validate artifact hash matches what's in Rekor
    match &body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: spec.data.hash.value (hex-encoded)
            let expected = Sha256Hash::from_hex(rekord.spec.data.hash.value.as_str())
                .map_err(|e| Error::Verification(format!("invalid hash in Rekor entry: {}", e)))?;
            validate_artifact_hash(&artifact_hash, &expected)?;
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.data.digest (Vec<u8>)
            let expected = Sha256Hash::try_from_slice(&rekord.spec.hashed_rekord_v002.data.digest)
                .map_err(|e| {
                    Error::Verification(format!("invalid digest in Rekor entry: {}", e))
                })?;
            validate_artifact_hash(&artifact_hash, &expected)?;
        }
        _ => {
            return Err(Error::Verification(format!(
                "expected HashedRekord body, got different type for version {}",
                version
            )));
        }
    };

    // Validate certificate matches
    validate_certificate_match(entry, &body, bundle)?;

    // Validate signature matches (for MessageSignature only)
    validate_signature_match(entry, &body, bundle)?;

    // Validate integrated time is within certificate validity (for v0.0.1)
    validate_integrated_time(entry, bundle)?;

    // Perform cryptographic signature verification
    // This verifies that the signature in the Rekor entry was created by the
    // certificate's private key over the artifact hash.
    // Uses verify_signature_prehashed with Digest::import_less_safe for proper
    // prehashed verification (avoiding double-hashing).
    verify_signature_cryptographically(entry, &body, bundle, artifact)?;

    Ok(())
}

/// Compute the SHA-256 digest from an artifact
fn compute_artifact_digest(artifact: &Artifact<'_>) -> Sha256Hash {
    match artifact {
        Artifact::Bytes(bytes) => sigstore_crypto::sha256(bytes),
        Artifact::Digest(hash) => *hash,
    }
}

/// Validate artifact hash matches expected hash
fn validate_artifact_hash(artifact_hash: &Sha256Hash, expected_hash: &Sha256Hash) -> Result<()> {
    if artifact_hash != expected_hash {
        return Err(Error::Verification(
            "artifact hash mismatch for hashedrekord entry".to_string(),
        ));
    }

    Ok(())
}

/// Validate that the certificate in Rekor matches the certificate in the bundle
fn validate_certificate_match(
    _entry: &TransparencyLogEntry<'_>,
    body: &RekorEntryBody,
    bundle: &Bundle,
) -> Result<()> {
    // Extract certificate DER from Rekor entry
    let rekor_cert_der_opt = match body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: parse PEM certificate from publicKey content
            let cert = rekord
                .spec
                .signature
                .public_key
                .to_certificate()
                .map_err(|e| Error::Verification(format!("{}", e)))?;
            Some(cert.as_bytes().to_vec())
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes (DerCertificate)
            rekord
                .spec
                .hashed_rekord_v002
                .signature
                .verifier
                .x509_certificate
                .as_ref()
                .map(|cert| cert.raw_bytes.as_bytes().to_vec())
        }
        _ => None,
    };

    if let Some(rekor_cert_der) = rekor_cert_der_opt {
        // Get the certificate from the bundle
        let bundle_cert = bundle.signing_certificate();

        if let Some(bundle_cert) = bundle_cert {
            // Bundle certificate is DerCertificate, get raw bytes
            let bundle_cert_der = bundle_cert.as_bytes();

            // Compare certificates
            if bundle_cert_der != rekor_cert_der {
                return Err(Error::Verification(
                    "certificate in bundle does not match certificate in Rekor entry".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate that the signature in the bundle matches the signature in Rekor
fn validate_signature_match(
    _entry: &TransparencyLogEntry<'_>,
    body: &RekorEntryBody,
    bundle: &Bundle,
) -> Result<()> {
    // Extract signature from Rekor entry (SignatureBytes)
    let rekor_sig = match body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: spec.signature.content (SignatureBytes)
            Some(&rekord.spec.signature.content)
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.signature.content (SignatureBytes)
            Some(&rekord.spec.hashed_rekord_v002.signature.content)
        }
        _ => None,
    };

    if let Some(rekor_sig) = rekor_sig {
        // Get the signature from the bundle (only for MessageSignature, not DSSE)
        if let Some(msg_sig) = bundle.message_signature() {
            let bundle_sig = msg_sig.signature();

            // Compare signatures (both are SignatureBytes)
            if bundle_sig.as_bytes() != rekor_sig.as_bytes() {
                return Err(Error::Verification(
                    "signature in bundle does not match signature in Rekor entry".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Perform cryptographic verification of the signature over the artifact
///
/// In Sigstore's hashedrekord format, the signature is created over the **artifact itself**,
/// not over the artifact's hash. The hash in the Rekor entry is used for lookup/deduplication.
///
/// Verification strategy:
/// - If we have the artifact bytes: verify signature over the artifact using `verify_signature`
/// - If we only have the digest:
///   - For SHA-256 schemes (P-256/SHA-256, RSA-PSS-SHA-256, etc.): Use prehashed verification
///     since Rekor stores SHA-256 hashes which match the signature's hash algorithm
///   - For SHA-384/512 schemes (P-384/SHA-384, etc.): Skip verification because Rekor's
///     SHA-256 hash doesn't match the signature's hash algorithm
///   - For Ed25519: Skip verification (doesn't support prehashed mode)
fn verify_signature_cryptographically(
    _entry: &TransparencyLogEntry<'_>,
    body: &RekorEntryBody,
    bundle: &Bundle,
    artifact: &Artifact<'_>,
) -> Result<()> {
    // Only verify for MessageSignature (not DSSE envelopes)
    if bundle.message_signature().is_some() {
        // Extract the signature from Rekor
        let signature_bytes = match body {
            RekorEntryBody::HashedRekordV001(rekord) => {
                SignatureBytes::new(rekord.spec.signature.content.as_bytes().to_vec())
            }
            RekorEntryBody::HashedRekordV002(rekord) => SignatureBytes::new(
                rekord
                    .spec
                    .hashed_rekord_v002
                    .signature
                    .content
                    .as_bytes()
                    .to_vec(),
            ),
            _ => return Ok(()),
        };

        // Get the certificate from the bundle
        let bundle_cert = bundle.signing_certificate();

        if let Some(bundle_cert) = bundle_cert {
            // Get certificate DER bytes directly
            let cert_der = bundle_cert.as_bytes();

            // Parse certificate to extract public key and algorithm
            let cert_info = sigstore_crypto::x509::parse_certificate_info(cert_der)?;

            match artifact {
                Artifact::Bytes(bytes) => {
                    // We have the artifact bytes - verify signature over them
                    sigstore_crypto::verification::verify_signature(
                        &cert_info.public_key,
                        bytes,
                        &signature_bytes,
                        cert_info.signing_scheme,
                    )
                    .map_err(|e| {
                        Error::Verification(format!(
                            "cryptographic signature verification failed: {}",
                            e
                        ))
                    })?;
                }
                Artifact::Digest(hash) => {
                    // We only have the digest - use prehashed verification if supported
                    if cert_info.signing_scheme.uses_sha256()
                        && cert_info.signing_scheme.supports_prehashed()
                    {
                        tracing::debug!(
                            "Using prehashed verification for {} with pre-computed digest",
                            cert_info.signing_scheme.name()
                        );

                        sigstore_crypto::verification::verify_signature_prehashed(
                            &cert_info.public_key,
                            hash,
                            &signature_bytes,
                            cert_info.signing_scheme,
                        )
                        .map_err(|e| {
                            Error::Verification(format!(
                                "cryptographic signature verification failed: {}",
                                e
                            ))
                        })?;
                    } else {
                        // Scheme doesn't use SHA-256 or doesn't support prehashed verification.
                        // We can't verify without the original artifact.
                        tracing::debug!(
                            "Skipping cryptographic signature verification for {} with digest-only - \
                             scheme uses different hash algorithm or doesn't support prehashed",
                            cert_info.signing_scheme.name()
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validate that integrated time is within certificate validity period
fn validate_integrated_time(entry: &TransparencyLogEntry<'_>, bundle: &Bundle) -> Result<()> {
    let bundle_cert = bundle.signing_certificate();

    if let Some(bundle_cert) = bundle_cert {
        let bundle_cert_der = bundle_cert.as_bytes();

        // Only validate integrated time for hashedrekord 0.0.1
        // For 0.0.2 (Rekor v2), integrated_time is not present
        let version = entry.version().unwrap_or("");
        let integrated_time = entry.integrated_time();

        if version == "0.0.1" && integrated_time > 0 {
            let cert = Certificate::from_der(bundle_cert_der).map_err(|e| {
                Error::Verification(format!(
                    "failed to parse certificate for time validation: {}",
                    e
                ))
            })?;

            // Convert certificate validity times to Unix timestamps
            use std::time::UNIX_EPOCH;
            let not_before_system = cert.tbs_certificate.validity.not_before.to_system_time();
            let not_after_system = cert.tbs_certificate.validity.not_after.to_system_time();

            let not_before = not_before_system
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    Error::Verification(format!("failed to convert notBefore to Unix time: {}", e))
                })?
                .as_secs() as i64;
            let not_after = not_after_system
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    Error::Verification(format!("failed to convert notAfter to Unix time: {}", e))
                })?
                .as_secs() as i64;

            if integrated_time < not_before || integrated_time > not_after {
                return Err(Error::Verification(format!(
                    "integrated time {} is outside certificate validity period ({} to {})",
                    integrated_time, not_before, not_after
                )));
            }
        }
    }

    Ok(())
}
