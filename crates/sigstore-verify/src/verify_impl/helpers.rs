//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;
use rustls_pki_types::CertificateDer;
use sigstore_crypto::CertificateInfo;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, SignatureContent};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};

/// Extract and decode the signing certificate from verification material
pub fn extract_certificate_der(
    verification_material: &VerificationMaterialContent,
) -> Result<Vec<u8>> {
    match verification_material {
        VerificationMaterialContent::Certificate(cert) => Ok(cert.raw_bytes.as_bytes().to_vec()),
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            Ok(certificates[0].raw_bytes.as_bytes().to_vec())
        }
        VerificationMaterialContent::PublicKey { .. } => Err(Error::Verification(
            "public key verification not yet supported".to_string(),
        )),
    }
}

/// Extract signature bytes from bundle content (needed for TSA verification)
pub fn extract_signature_bytes(content: &SignatureContent) -> Result<Vec<u8>> {
    match content {
        SignatureContent::MessageSignature(msg_sig) => Ok(msg_sig.signature.as_bytes().to_vec()),
        SignatureContent::DsseEnvelope(envelope) => {
            if envelope.signatures.is_empty() {
                return Err(Error::Verification(
                    "no signatures in DSSE envelope".to_string(),
                ));
            }
            Ok(envelope.signatures[0].sig.as_bytes().to_vec())
        }
    }
}

/// Extract the integrated time from transparency log entries
/// Returns the earliest integrated time if multiple entries are present
pub fn extract_integrated_time(bundle: &Bundle) -> Result<Option<i64>> {
    let mut earliest_time: Option<i64> = None;

    for entry in &bundle.verification_material.tlog_entries {
        if !entry.integrated_time.is_empty() {
            if let Ok(time) = entry.integrated_time.parse::<i64>() {
                // Ignore 0 as it indicates invalid/missing time (e.g. from test instances)
                if time > 0 {
                    if let Some(earliest) = earliest_time {
                        if time < earliest {
                            earliest_time = Some(time);
                        }
                    } else {
                        earliest_time = Some(time);
                    }
                }
            }
        }
    }

    Ok(earliest_time)
}

/// Extract and verify TSA RFC 3161 timestamps
/// Returns the earliest verified timestamp if any are present
pub fn extract_tsa_timestamp(
    bundle: &Bundle,
    signature_bytes: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<Option<i64>> {
    use sigstore_tsa::{verify_timestamp_response, VerifyOpts as TsaVerifyOpts};

    // Check if bundle has TSA timestamps
    if bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
        .is_empty()
    {
        return Ok(None);
    }

    let mut earliest_timestamp: Option<i64> = None;
    let mut any_timestamp_verified = false;

    for ts in &bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
    {
        // Get the timestamp bytes
        let ts_bytes = ts.signed_timestamp.as_bytes();

        // Build verification options from trusted root
        let mut opts = TsaVerifyOpts::new();

        // Get TSA root certificates
        if let Ok(tsa_roots) = trusted_root.tsa_root_certs() {
            opts = opts.with_roots(tsa_roots);
        }

        // Get TSA intermediate certificates
        if let Ok(tsa_intermediates) = trusted_root.tsa_intermediate_certs() {
            opts = opts.with_intermediates(tsa_intermediates);
        }

        // Get TSA leaf certificate
        if let Ok(tsa_leaves) = trusted_root.tsa_leaf_certs() {
            if let Some(leaf) = tsa_leaves.first() {
                opts = opts.with_tsa_certificate(leaf.clone());
            }
        }

        // Get TSA validity period from trusted root
        if let Ok(tsa_certs) = trusted_root.tsa_certs_with_validity() {
            if let Some((_cert, Some(start), Some(end))) = tsa_certs.first() {
                opts = opts.with_tsa_validity(*start, *end);
            }
        }

        // Verify the timestamp response with full cryptographic validation
        let result = verify_timestamp_response(ts_bytes, signature_bytes, opts).map_err(|e| {
            Error::Verification(format!("TSA timestamp verification failed: {}", e))
        })?;

        let timestamp = result.time.timestamp();
        any_timestamp_verified = true;

        if let Some(earliest) = earliest_timestamp {
            if timestamp < earliest {
                earliest_timestamp = Some(timestamp);
            }
        } else {
            earliest_timestamp = Some(timestamp);
        }
    }

    // If we have a trusted root and timestamps were present but none verified, that's an error
    if !any_timestamp_verified
        && !bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .is_empty()
    {
        return Err(Error::Verification(
            "TSA timestamps present but none could be verified against trusted root".to_string(),
        ));
    }

    Ok(earliest_timestamp)
}

/// Determine validation time from timestamps
/// Priority order:
/// 1. TSA timestamp (RFC 3161) - most authoritative
/// 2. Integrated time from transparency log
/// 3. Current time - fallback
pub fn determine_validation_time(
    bundle: &Bundle,
    signature_bytes: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<i64> {
    if let Some(tsa_time) = extract_tsa_timestamp(bundle, signature_bytes, trusted_root)? {
        Ok(tsa_time)
    } else if let Some(integrated_time) = extract_integrated_time(bundle)? {
        Ok(integrated_time)
    } else {
        Ok(chrono::Utc::now().timestamp())
    }
}

/// Validate certificate is within validity period
pub fn validate_certificate_time(validation_time: i64, cert_info: &CertificateInfo) -> Result<()> {
    if validation_time < cert_info.not_before {
        return Err(Error::Verification(format!(
            "certificate not yet valid: validation time {} is before not_before {}",
            validation_time, cert_info.not_before
        )));
    }

    if validation_time > cert_info.not_after {
        return Err(Error::Verification(format!(
            "certificate has expired: validation time {} is after not_after {}",
            validation_time, cert_info.not_after
        )));
    }

    Ok(())
}

/// Verify the certificate chain to the Fulcio root of trust
///
/// This function verifies that the signing certificate chains to a trusted
/// Fulcio root certificate at the given verification time. It also verifies
/// that the certificate has the CODE_SIGNING extended key usage.
pub fn verify_certificate_chain(
    verification_material: &VerificationMaterialContent,
    validation_time: i64,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    // Extract the end-entity certificate and any intermediates from the bundle
    let (ee_cert_der, intermediate_ders) = match verification_material {
        VerificationMaterialContent::Certificate(cert) => {
            (cert.raw_bytes.as_bytes().to_vec(), Vec::new())
        }
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            let ee = certificates[0].raw_bytes.as_bytes().to_vec();
            let intermediates: Vec<Vec<u8>> = certificates[1..]
                .iter()
                .map(|c| c.raw_bytes.as_bytes().to_vec())
                .collect();
            (ee, intermediates)
        }
        VerificationMaterialContent::PublicKey { .. } => {
            return Err(Error::Verification(
                "public key verification not yet supported".to_string(),
            ));
        }
    };

    // Get Fulcio certificates from trusted root to use as trust anchors
    let fulcio_certs = trusted_root
        .fulcio_certs()
        .map_err(|e| Error::Verification(format!("failed to get Fulcio certs: {}", e)))?;

    if fulcio_certs.is_empty() {
        return Err(Error::Verification(
            "no Fulcio certificates in trusted root".to_string(),
        ));
    }

    // Build trust anchors from Fulcio root certificates
    let trust_anchors: Vec<_> = fulcio_certs
        .iter()
        .filter_map(|cert_der| {
            let cert = CertificateDer::from(&cert_der[..]);
            anchor_from_trusted_cert(&cert)
                .map(|anchor| anchor.to_owned())
                .ok()
        })
        .collect();

    if trust_anchors.is_empty() {
        return Err(Error::Verification(
            "failed to create trust anchors from Fulcio certificates".to_string(),
        ));
    }

    // Convert intermediate certificates to CertificateDer
    let intermediate_certs: Vec<CertificateDer<'static>> = intermediate_ders
        .into_iter()
        .map(|der| CertificateDer::from(der).into_owned())
        .collect();

    // Parse the end-entity certificate for webpki
    let ee_cert_der_ref = CertificateDer::from(ee_cert_der.as_slice());
    let end_entity_cert = EndEntityCert::try_from(&ee_cert_der_ref).map_err(|e| {
        Error::Verification(format!("failed to parse end-entity certificate: {}", e))
    })?;

    // Convert validation time to webpki UnixTime
    let verification_time = webpki::types::UnixTime::since_unix_epoch(
        std::time::Duration::from_secs(validation_time as u64),
    );

    // Verify the certificate chain with CODE_SIGNING EKU
    // This performs:
    // - Chain building from end-entity to trust anchor
    // - Signature verification at each step
    // - Time validity checking
    // - Extended Key Usage validation (CODE_SIGNING)
    end_entity_cert
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediate_certs,
            verification_time,
            KeyUsage::required(ID_KP_CODE_SIGNING.as_bytes()),
            None, // No revocation checking
            None, // No path verification callback
        )
        .map_err(|e| Error::Verification(format!("certificate chain validation failed: {}", e)))?;

    tracing::debug!("Certificate chain validated successfully with CODE_SIGNING EKU");

    Ok(())
}

/// Verify the Signed Certificate Timestamp (SCT) embedded in the certificate
///
/// SCTs provide proof that the certificate was submitted to a Certificate
/// Transparency log. This is a key part of Sigstore's security model.
///
/// This function uses the x509-cert crate's built-in SCT parsing and tls_codec
/// for proper RFC 6962 compliant verification.
pub fn verify_sct(
    verification_material: &VerificationMaterialContent,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    // Extract certificate for verification
    let cert_der = extract_certificate_der(verification_material)?;

    // Get issuer SPKI for calculating the issuer key hash
    let issuer_spki_der = get_issuer_spki(verification_material, &cert_der, trusted_root)?;

    // Delegate to the new sct module for verification
    super::sct::verify_sct(&cert_der, &issuer_spki_der, trusted_root)
}

/// Get the issuer's SubjectPublicKeyInfo DER bytes
///
/// This tries to find the issuer certificate in the verification material chain
/// or in the trusted root, and returns its SPKI for SCT verification.
fn get_issuer_spki(
    verification_material: &VerificationMaterialContent,
    cert_der: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<Vec<u8>> {
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

    // 1. Try to get from chain in verification material
    if let VerificationMaterialContent::X509CertificateChain { certificates } =
        verification_material
    {
        if certificates.len() > 1 {
            let issuer_der = certificates[1].raw_bytes.as_bytes();
            let issuer_cert = Certificate::from_der(issuer_der).map_err(|e| {
                Error::Verification(format!("failed to parse issuer certificate: {}", e))
            })?;
            return issuer_cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| Error::Verification(format!("failed to encode issuer SPKI: {}", e)));
        }
    }

    // 2. Try to find in trusted root
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;
    let issuer_name = cert.tbs_certificate.issuer;

    let fulcio_certs = trusted_root
        .fulcio_certs()
        .map_err(|e| Error::Verification(format!("failed to get Fulcio certs: {}", e)))?;

    for ca_der in fulcio_certs {
        if let Ok(ca_cert) = Certificate::from_der(&ca_der) {
            if ca_cert.tbs_certificate.subject == issuer_name {
                return ca_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|e| {
                        Error::Verification(format!("failed to encode issuer SPKI: {}", e))
                    });
            }
        }
    }

    Err(Error::Verification(
        "could not find issuer certificate for SCT verification".to_string(),
    ))
}
