//! HashedRekord entry validation
//!
//! This module handles validation of hashedrekord entries, including
//! artifact hash verification and certificate/signature matching.

use crate::error::{Error, Result};
use base64::Engine;
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
    // Parse the Rekor entry body
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body,
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
                let expected = Sha256Hash::from_hex(&rekord.spec.data.hash.value).map_err(|e| {
                    Error::Verification(format!("invalid hash in Rekor entry: {}", e))
                })?;
                validate_artifact_hash(&artifact_hash_to_check, &expected)?;
            }
            RekorEntryBody::HashedRekordV002(rekord) => {
                // v0.0.2: spec.hashedRekordV002.data.digest (base64-encoded)
                let expected =
                    Sha256Hash::from_base64(rekord.spec.hashed_rekord_v002.data.digest.as_str())
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
                // Decode the digest from the bundle (base64-encoded)
                Sha256Hash::from_base64(digest.digest.as_str()).map_err(|e| {
                    Error::Verification(format!("failed to decode message digest: {}", e))
                })
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
            // v0.0.1: spec.signature.publicKey.content is base64-encoded PEM string
            // Decode the base64 to get PEM text
            let pem_bytes = rekord
                .spec
                .signature
                .public_key
                .content
                .decode()
                .map_err(|e| {
                    Error::Verification(format!("failed to decode public key base64: {}", e))
                })?;

            let pem_str = String::from_utf8(pem_bytes).map_err(|e| {
                Error::Verification(format!("public key PEM not valid UTF-8: {}", e))
            })?;

            // Extract DER from PEM
            Some(x509::der_from_pem(&pem_str).map_err(|e| {
                Error::Verification(format!("failed to extract DER from PEM: {}", e))
            })?)
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes (Base64 DER)
            rekord
                .spec
                .hashed_rekord_v002
                .signature
                .verifier
                .x509_certificate
                .as_ref()
                .map(|cert| {
                    cert.raw_bytes.decode().map_err(|e| {
                        Error::Verification(format!("failed to decode Rekor certificate: {}", e))
                    })
                })
                .transpose()?
        }
        _ => None,
    };

    if let Some(rekor_cert_der) = rekor_cert_der_opt {
        // Get the certificate from the bundle
        let bundle_cert_b64 = match &bundle.verification_material.content {
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                certificates.first().map(|c| &c.raw_bytes)
            }
            VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
            _ => None,
        };

        if let Some(bundle_cert_b64) = bundle_cert_b64 {
            // Decode bundle certificate (still String for now, will update bundle types next)
            let bundle_cert_der = base64::engine::general_purpose::STANDARD
                .decode(bundle_cert_b64)
                .map_err(|e| {
                    Error::Verification(format!("failed to decode bundle certificate: {}", e))
                })?;

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
    // Extract signature from Rekor entry
    let rekor_sig_b64 = match body {
        RekorEntryBody::HashedRekordV001(rekord) => {
            // v0.0.1: spec.signature.content (base64)
            Some(&rekord.spec.signature.content)
        }
        RekorEntryBody::HashedRekordV002(rekord) => {
            // v0.0.2: spec.hashedRekordV002.signature.content (base64)
            Some(&rekord.spec.hashed_rekord_v002.signature.content)
        }
        _ => None,
    };

    if let Some(rekor_sig_b64) = rekor_sig_b64 {
        // Get the signature from the bundle (only for MessageSignature, not DSSE)
        if let SignatureContent::MessageSignature(sig) = &bundle.content {
            let bundle_sig_b64 = &sig.signature;

            // Compare signatures
            if bundle_sig_b64 != rekor_sig_b64 {
                return Err(Error::Verification(
                    "signature in bundle does not match signature in Rekor entry".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate that integrated time is within certificate validity period
fn validate_integrated_time(entry: &TransparencyLogEntry, bundle: &Bundle) -> Result<()> {
    let bundle_cert_b64 = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            certificates.first().map(|c| &c.raw_bytes)
        }
        VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
        _ => None,
    };

    if let Some(bundle_cert_b64) = bundle_cert_b64 {
        let bundle_cert_der = base64::engine::general_purpose::STANDARD
            .decode(bundle_cert_b64)
            .map_err(|e| {
                Error::Verification(format!(
                    "failed to decode bundle certificate for time validation: {}",
                    e
                ))
            })?;

        // Only validate integrated time for hashedrekord 0.0.1
        // For 0.0.2 (Rekor v2), integrated_time is not present
        if entry.kind_version.version == "0.0.1" && !entry.integrated_time.is_empty() {
            let cert = Certificate::from_der(&bundle_cert_der).map_err(|e| {
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
