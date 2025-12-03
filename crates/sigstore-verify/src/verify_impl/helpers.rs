//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;
use rustls_pki_types::{CertificateDer, UnixTime};
use sigstore_crypto::CertificateInfo;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, DerCertificate, DerPublicKey, SignatureBytes, SignatureContent};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};

/// Extract and decode the signing certificate from verification material
pub fn extract_certificate(
    verification_material: &VerificationMaterialContent,
) -> Result<DerCertificate> {
    match verification_material {
        VerificationMaterialContent::Certificate(cert) => Ok(cert.raw_bytes.clone()),
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            Ok(certificates[0].raw_bytes.clone())
        }
        VerificationMaterialContent::PublicKey { .. } => Err(Error::Verification(
            "public key verification not yet supported".to_string(),
        )),
    }
}

/// Extract signature from bundle content (needed for TSA verification)
pub fn extract_signature(content: &SignatureContent) -> Result<SignatureBytes> {
    match content {
        SignatureContent::MessageSignature(msg_sig) => Ok(msg_sig.signature.clone()),
        SignatureContent::DsseEnvelope(envelope) => {
            if envelope.signatures.is_empty() {
                return Err(Error::Verification(
                    "no signatures in DSSE envelope".to_string(),
                ));
            }
            Ok(envelope.signatures[0].sig.clone())
        }
    }
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

        // Get ALL TSA leaf certificates (there may be multiple TSAs)
        if let Ok(tsa_leaves) = trusted_root.tsa_leaf_certs() {
            opts = opts.with_tsa_certificates(tsa_leaves);
        }

        // Verify the timestamp response with full cryptographic validation
        let result = verify_timestamp_response(ts_bytes, signature_bytes, opts).map_err(|e| {
            Error::Verification(format!("TSA timestamp verification failed: {}", e))
        })?;

        // Check that the timestamp falls within the TSA's validity period from the trust root
        if !trusted_root.is_timestamp_within_tsa_validity(result.time) {
            return Err(Error::Verification(format!(
                "TSA timestamp {} is outside the trust root's TSA validity period",
                result.time
            )));
        }

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

/// Check if bundle contains V2 tlog entries (hashedrekord/dsse v0.0.2)
/// V2 entries have integrated_time=0 and require RFC3161 timestamps
pub fn has_v2_tlog_entries(bundle: &Bundle) -> bool {
    bundle
        .verification_material
        .tlog_entries
        .iter()
        .any(|entry| entry.kind_version.version == "0.0.2")
}

/// Extract integrated time from V1 tlog entries that have inclusion promises.
///
/// Per sigstore-python, integrated_time is only valid as a timestamp source when:
/// 1. The entry has an inclusion_promise (SET) that cryptographically binds it
/// 2. The entry is a V1 type (hashedrekord/dsse v0.0.1)
/// 3. The integrated_time is > 0
///
/// Returns the earliest valid integrated time if any are present.
fn extract_v1_integrated_time_with_promise(bundle: &Bundle) -> Option<i64> {
    let mut earliest_time: Option<i64> = None;

    for entry in &bundle.verification_material.tlog_entries {
        // Only V1 entries (0.0.1) with inclusion promises are valid timestamp sources
        let is_v1 = entry.kind_version.version == "0.0.1"
            && (entry.kind_version.kind == "hashedrekord" || entry.kind_version.kind == "dsse");

        if !is_v1 || entry.inclusion_promise.is_none() {
            continue;
        }

        let time = entry.integrated_time;
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

    earliest_time
}

/// Determine validation time from timestamps.
///
/// At least one verified timestamp source is REQUIRED. This matches sigstore-python's
/// behavior which enforces `VERIFIED_TIME_THRESHOLD = 1`.
///
/// Valid timestamp sources (in priority order):
/// 1. TSA timestamp (RFC 3161) - most authoritative
/// 2. Integrated time from V1 tlog entries with inclusion promises
///
/// Note: There is NO fallback to current time. If no verified timestamp is found,
/// verification fails.
pub fn determine_validation_time(
    bundle: &Bundle,
    signature: &SignatureBytes,
    trusted_root: &TrustedRoot,
) -> Result<i64> {
    // Try TSA timestamp first (most authoritative)
    if let Some(tsa_time) = extract_tsa_timestamp(bundle, signature.as_bytes(), trusted_root)? {
        return Ok(tsa_time);
    }

    // Try integrated time from V1 tlog entries with inclusion promises
    // Per sigstore-python: integrated_time only counts if accompanied by inclusion_promise
    if let Some(integrated_time) = extract_v1_integrated_time_with_promise(bundle) {
        return Ok(integrated_time);
    }

    // No verified timestamp found - fail verification
    // This matches sigstore-python's behavior: "not enough sources of verified time"
    let is_v2 = has_v2_tlog_entries(bundle);
    if is_v2 {
        Err(Error::Verification(
            "V2 bundle requires RFC3161 timestamp but none could be verified. \
             V2 tlog entries have integrated_time=0 by design. \
             Ensure TSA certificates are present in the trusted root."
                .to_string(),
        ))
    } else {
        Err(Error::Verification(
            "No verified timestamp found. V1 bundles require either an RFC3161 timestamp \
             or a tlog entry with both integrated_time > 0 and an inclusion_promise (SET)."
                .to_string(),
        ))
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
    let verification_time =
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(validation_time as u64));

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
            None, // No CRL/OCSP revocation checking (matches sigstore-python)
            None, // No custom path validation callback needed
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
    let cert = extract_certificate(verification_material)?;

    // Get issuer SPKI for calculating the issuer key hash
    let issuer_spki = get_issuer_spki(verification_material, &cert, trusted_root)?;

    // Delegate to the new sct module for verification
    super::sct::verify_sct(cert.as_bytes(), issuer_spki.as_bytes(), trusted_root)
}

/// Get the issuer's SubjectPublicKeyInfo DER bytes
///
/// This tries to find the issuer certificate in the verification material chain
/// or in the trusted root, and returns its SPKI for SCT verification.
fn get_issuer_spki(
    verification_material: &VerificationMaterialContent,
    cert: &DerCertificate,
    trusted_root: &TrustedRoot,
) -> Result<DerPublicKey> {
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
            let spki_der = issuer_cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| Error::Verification(format!("failed to encode issuer SPKI: {}", e)))?;
            return Ok(DerPublicKey::new(spki_der));
        }
    }

    // 2. Try to find in trusted root
    let parsed_cert = Certificate::from_der(cert.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;
    let issuer_name = parsed_cert.tbs_certificate.issuer;

    let fulcio_certs = trusted_root
        .fulcio_certs()
        .map_err(|e| Error::Verification(format!("failed to get Fulcio certs: {}", e)))?;

    for ca_der in fulcio_certs {
        if let Ok(ca_cert) = Certificate::from_der(&ca_der) {
            if ca_cert.tbs_certificate.subject == issuer_name {
                let spki_der = ca_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|e| {
                        Error::Verification(format!("failed to encode issuer SPKI: {}", e))
                    })?;
                return Ok(DerPublicKey::new(spki_der));
            }
        }
    }

    Err(Error::Verification(
        "could not find issuer certificate for SCT verification".to_string(),
    ))
}
