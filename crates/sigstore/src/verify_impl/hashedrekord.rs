//! HashedRekord entry validation
//!
//! This module handles validation of hashedrekord entries, including
//! artifact hash verification and certificate/signature matching.

use crate::error::{Error, Result};
use sigstore_crypto::x509;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, Sha256Hash, SignatureContent, TransparencyLogEntry};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Verify artifact hash matches what's in Rekor (for hashedrekord entries)
pub fn verify_hashedrekord_entries(
    bundle: &Bundle,
    artifact: &[u8],
    skip_artifact_hash: bool,
) -> Result<()> {
    for entry in &bundle.verification_material.tlog_entries {
        if entry.kind_version.kind == "hashedrekord" {
            verify_hashedrekord_entry(entry, bundle, artifact, skip_artifact_hash)?;
        }
    }
    Ok(())
}

/// Verify a single hashedrekord entry
fn verify_hashedrekord_entry(
    entry: &TransparencyLogEntry,
    bundle: &Bundle,
    artifact: &[u8],
    skip_artifact_hash: bool,
) -> Result<()> {
    // Parse the Rekor entry body (convert canonicalized body to base64 string)
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    // If we are skipping artifact hash verification, we can skip this part
    if !skip_artifact_hash {
        // Extract expected artifact hash and validate
        let artifact_hash_to_check =
            get_artifact_hash(artifact, &bundle.content, skip_artifact_hash)?;

        match &body {
            RekorEntryBody::HashedRekordV001(rekord) => {
                // v0.0.1: spec.data.hash.value (hex-encoded)
                let expected =
                    Sha256Hash::from_hex(rekord.spec.data.hash.value.as_str()).map_err(|e| {
                        Error::Verification(format!("invalid hash in Rekor entry: {}", e))
                    })?;
                validate_artifact_hash(&artifact_hash_to_check, &expected)?;
            }
            RekorEntryBody::HashedRekordV002(rekord) => {
                // v0.0.2: spec.hashedRekordV002.data.digest (Vec<u8>)
                let expected =
                    Sha256Hash::try_from_slice(&rekord.spec.hashed_rekord_v002.data.digest)
                        .map_err(|e| {
                            Error::Verification(format!("invalid digest in Rekor entry: {}", e))
                        })?;
                validate_artifact_hash(&artifact_hash_to_check, &expected)?;
            }
            _ => {
                return Err(Error::Verification(format!(
                    "expected HashedRekord body, got different type for version {}",
                    entry.kind_version.version
                )));
            }
        };
    }

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
    verify_signature_cryptographically(entry, &body, bundle, artifact, skip_artifact_hash)?;

    Ok(())
}

/// Get artifact hash - either compute from artifact or extract from bundle digest
fn get_artifact_hash(
    artifact: &[u8],
    content: &SignatureContent,
    skip_artifact_hash: bool,
) -> Result<Sha256Hash> {
    if !artifact.is_empty() {
        // We have the actual artifact, compute its hash
        Ok(Sha256Hash::from_bytes(sigstore_crypto::sha256(artifact)))
    } else if skip_artifact_hash {
        // DIGEST mode - extract hash from bundle's message signature
        if let SignatureContent::MessageSignature(sig) = content {
            if let Some(digest) = &sig.message_digest {
                // digest.digest is already a Sha256Hash
                Ok(digest.digest)
            } else {
                Err(Error::Verification(
                    "no message digest in bundle for DIGEST mode".to_string(),
                ))
            }
        } else {
            // For DSSE envelopes in DIGEST mode, we can't validate the hashedrekord
            // Return a dummy hash that won't match (validation will be skipped)
            Ok(Sha256Hash::from_bytes([0u8; 32]))
        }
    } else {
        Err(Error::Verification(
            "no artifact provided and not in DIGEST mode".to_string(),
        ))
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
    _entry: &TransparencyLogEntry,
    body: &RekorEntryBody,
    bundle: &Bundle,
) -> Result<()> {
    // Extract certificate DER from Rekor entry
    let rekor_cert_der_opt = match body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: spec.signature.publicKey.content is base64-encoded PEM (PemContent)
            // PemContent stores the PEM text as bytes
            let pem_bytes = rekord.spec.signature.public_key.content.as_bytes();

            let pem_str = String::from_utf8(pem_bytes.to_vec()).map_err(|e| {
                Error::Verification(format!("public key PEM not valid UTF-8: {}", e))
            })?;

            // Extract DER from PEM
            Some(x509::der_from_pem(&pem_str).map_err(|e| {
                Error::Verification(format!("failed to extract DER from PEM: {}", e))
            })?)
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
        let bundle_cert = match &bundle.verification_material.content {
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                certificates.first().map(|c| &c.raw_bytes)
            }
            VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
            _ => None,
        };

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
    _entry: &TransparencyLogEntry,
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
        if let SignatureContent::MessageSignature(sig) = &bundle.content {
            let bundle_sig = &sig.signature;

            // Compare signatures (both are SignatureBytes)
            if bundle_sig != rekor_sig {
                return Err(Error::Verification(
                    "signature in bundle does not match signature in Rekor entry".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Perform cryptographic verification of the signature over the artifact hash
fn verify_signature_cryptographically(
    _entry: &TransparencyLogEntry,
    body: &RekorEntryBody,
    bundle: &Bundle,
    _artifact: &[u8],
    _skip_artifact_hash: bool,
) -> Result<()> {
    // Only verify for MessageSignature (not DSSE envelopes)
    if let SignatureContent::MessageSignature(_) = &bundle.content {
        // Extract the signature from Rekor (as bytes)
        let signature_bytes = match body {
            RekorEntryBody::HashedRekordV001(rekord) => {
                rekord.spec.signature.content.as_bytes().to_vec()
            }
            RekorEntryBody::HashedRekordV002(rekord) => rekord
                .spec
                .hashed_rekord_v002
                .signature
                .content
                .as_bytes()
                .to_vec(),
            _ => return Ok(()),
        };

        // Extract the artifact hash from Rekor entry
        // The signature in a hashedrekord is over the hash of the artifact, not the artifact itself
        let artifact_hash_from_rekor = match body {
            RekorEntryBody::HashedRekordV001(rekord) => {
                // v0.0.1: spec.data.hash.value (hex-encoded)
                *Sha256Hash::from_hex(rekord.spec.data.hash.value.as_str())
                    .map_err(|e| {
                        Error::Verification(format!(
                            "invalid hash in Rekor entry for signature verification: {}",
                            e
                        ))
                    })?
                    .as_bytes()
            }
            RekorEntryBody::HashedRekordV002(rekord) => {
                // v0.0.2: spec.hashedRekordV002.data.digest (Vec<u8>)
                let hash = Sha256Hash::try_from_slice(&rekord.spec.hashed_rekord_v002.data.digest)
                    .map_err(|e| {
                        Error::Verification(format!(
                            "invalid digest in Rekor entry for signature verification: {}",
                            e
                        ))
                    })?;
                *hash.as_bytes()
            }
            _ => return Ok(()),
        };

        // Get the certificate from the bundle
        let bundle_cert = match &bundle.verification_material.content {
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                certificates.first().map(|c| &c.raw_bytes)
            }
            VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
            _ => None,
        };

        if let Some(bundle_cert) = bundle_cert {
            // Get certificate DER bytes directly
            let cert_der = bundle_cert.as_bytes();

            // Parse certificate to extract public key and algorithm
            let cert_info = sigstore_crypto::x509::parse_certificate_info(cert_der)?;

            // Verify the signature over the prehashed artifact
            sigstore_crypto::verification::verify_signature_prehashed(
                &cert_info.public_key_bytes,
                &artifact_hash_from_rekor,
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
    }

    Ok(())
}

/// Validate that integrated time is within certificate validity period
fn validate_integrated_time(entry: &TransparencyLogEntry, bundle: &Bundle) -> Result<()> {
    let bundle_cert = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            certificates.first().map(|c| &c.raw_bytes)
        }
        VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
        _ => None,
    };

    if let Some(bundle_cert) = bundle_cert {
        let bundle_cert_der = bundle_cert.as_bytes();

        // Only validate integrated time for hashedrekord 0.0.1
        // For 0.0.2 (Rekor v2), integrated_time is not present
        if entry.kind_version.version == "0.0.1" && !entry.integrated_time.is_empty() {
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

            let integrated_time = entry.integrated_time.parse::<i64>().map_err(|e| {
                Error::Verification(format!("failed to parse integrated time: {}", e))
            })?;

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
