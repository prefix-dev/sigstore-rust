//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SECP_256_R_1, SECP_384_R_1};
use sigstore_crypto::CertificateInfo;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, SignatureContent};
use x509_cert::der::Encode;

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
/// Fulcio root certificate at the given verification time.
pub fn verify_certificate_chain(
    cert_der: &[u8],
    _validation_time: i64,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // Get Fulcio certificates from trusted root
    let fulcio_certs = trusted_root
        .fulcio_certs()
        .map_err(|e| Error::Verification(format!("failed to get Fulcio certs: {}", e)))?;

    if fulcio_certs.is_empty() {
        return Err(Error::Verification(
            "no Fulcio certificates in trusted root".to_string(),
        ));
    }

    // Parse the end-entity certificate
    let ee_cert = Certificate::from_der(cert_der).map_err(|e| {
        Error::Verification(format!("failed to parse end-entity certificate: {}", e))
    })?;

    // Get the issuer from the EE certificate
    let ee_issuer = &ee_cert.tbs_certificate.issuer;

    // Extract the original TBS DER bytes from the certificate
    // CRITICAL: We must use the original DER bytes, not re-serialize, because
    // re-serialization can produce different bytes even if semantically equivalent,
    // which will break signature verification.
    let tbs_der = extract_tbs_der(cert_der).map_err(|e| {
        Error::Verification(format!("failed to extract TBS certificate bytes: {}", e))
    })?;

    // Try to find a matching Fulcio root by comparing issuers
    let mut found_issuer = false;
    for fulcio_cert_der in &fulcio_certs {
        if let Ok(fulcio_cert) = Certificate::from_der(fulcio_cert_der) {
            let fulcio_subject = &fulcio_cert.tbs_certificate.subject;

            // Check if the EE certificate's issuer matches this Fulcio cert's subject
            if ee_issuer == fulcio_subject {
                // Verify the signature
                let Some(signature) = ee_cert.signature.as_bytes() else {
                    continue;
                };

                // Determine the signing scheme by combining:
                // 1. The curve from the issuer's public key (SPKI)
                // 2. The hash algorithm from the signature algorithm OID
                let sig_alg_oid = ee_cert.signature_algorithm.oid;

                // Get the curve from the issuer's public key
                let issuer_spki = &fulcio_cert.tbs_certificate.subject_public_key_info;
                let curve_oid = match extract_ec_curve_oid(issuer_spki) {
                    Ok(oid) => oid,
                    Err(_) => continue,
                };

                // Map (curve, hash) to SigningScheme using OID constants
                let scheme = if curve_oid == SECP_256_R_1 && sig_alg_oid == ECDSA_WITH_SHA_256 {
                    // P-256 with SHA-256
                    sigstore_crypto::SigningScheme::EcdsaP256Sha256
                } else if curve_oid == SECP_256_R_1 && sig_alg_oid == ECDSA_WITH_SHA_384 {
                    // P-256 with SHA-384 (non-standard but valid)
                    sigstore_crypto::SigningScheme::EcdsaP256Sha384
                } else if curve_oid == SECP_384_R_1 && sig_alg_oid == ECDSA_WITH_SHA_384 {
                    // P-384 with SHA-384
                    sigstore_crypto::SigningScheme::EcdsaP384Sha384
                } else {
                    tracing::warn!(
                        "Unknown curve/signature algorithm combination: curve={}, sig_alg={}",
                        curve_oid,
                        sig_alg_oid
                    );
                    continue;
                };

                let Some(issuer_pub_key) = issuer_spki.subject_public_key.as_bytes() else {
                    continue;
                };

                if sigstore_crypto::verify_signature(issuer_pub_key, &tbs_der, signature, scheme)
                    .is_ok()
                {
                    found_issuer = true;
                    break;
                }
            }
        }
    }

    if !found_issuer {
        return Err(Error::Verification(
            "certificate does not chain to any trusted Fulcio root".to_string(),
        ));
    }

    // Verify certificate validity period
    let cert_info = sigstore_crypto::parse_certificate_info(cert_der)?;
    validate_certificate_time(_validation_time, &cert_info)?;

    Ok(())
}

/// Extract the EC curve OID from a SubjectPublicKeyInfo
///
/// For EC keys, the algorithm parameters contain the curve OID
fn extract_ec_curve_oid(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<const_oid::ObjectIdentifier> {
    use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
    use const_oid::ObjectIdentifier;

    // For EC keys, the algorithm OID should be id-ecPublicKey (1.2.840.10045.2.1)
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(Error::Verification("Not an EC public key".to_string()));
    }

    // The parameters field contains the curve OID
    let Some(params) = &spki.algorithm.parameters else {
        return Err(Error::Verification(
            "EC public key missing curve parameters".to_string(),
        ));
    };

    // The AnyRef value() gives us the raw content bytes (without tag/length).
    // For an OID, this is the encoded OID bytes.
    // ObjectIdentifier::from_bytes expects raw OID bytes (without tag/length header).
    let curve_oid = ObjectIdentifier::from_bytes(params.value())
        .map_err(|e| Error::Verification(format!("failed to parse EC curve OID: {}", e)))?;

    Ok(curve_oid)
}

/// Extract the original TBS (To Be Signed) certificate DER bytes from a certificate
///
/// CRITICAL: This extracts the original DER bytes without re-parsing and re-serializing,
/// which is necessary for correct signature verification.
fn extract_tbs_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::der::{Decode, Reader, SliceReader};

    // A Certificate is a SEQUENCE containing:
    // 1. TBSCertificate (SEQUENCE)
    // 2. signatureAlgorithm (SEQUENCE)
    // 3. signatureValue (BIT STRING)
    //
    // We need to extract the raw bytes of the TBSCertificate element.

    let mut reader = SliceReader::new(cert_der)
        .map_err(|e| Error::Verification(format!("failed to create DER reader: {}", e)))?;

    // Decode the outer SEQUENCE header
    let outer_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Verification(format!("failed to decode certificate header: {}", e)))?;

    // The remaining bytes should be the certificate contents
    let cert_contents = reader
        .read_slice(outer_header.length)
        .map_err(|e| Error::Verification(format!("failed to read certificate contents: {}", e)))?;

    // Now decode the TBS header from the certificate contents
    let mut tbs_reader = SliceReader::new(cert_contents)
        .map_err(|e| Error::Verification(format!("failed to create TBS reader: {}", e)))?;

    let tbs_header = x509_cert::der::Header::decode(&mut tbs_reader)
        .map_err(|e| Error::Verification(format!("failed to decode TBS header: {}", e)))?;

    // Calculate the total length of the TBS including its header
    let header_len: usize = tbs_header
        .encoded_len()
        .map_err(|e| Error::Verification(format!("failed to encode TBS header length: {}", e)))?
        .try_into()
        .map_err(|_| Error::Verification("TBS header length too large".to_string()))?;

    let body_len: usize = tbs_header
        .length
        .try_into()
        .map_err(|_| Error::Verification("TBS body length too large".to_string()))?;

    let tbs_total_len = header_len
        .checked_add(body_len)
        .ok_or_else(|| Error::Verification("TBS length calculation overflow".to_string()))?;

    // Extract the TBS bytes (header + body)
    if tbs_total_len > cert_contents.len() {
        return Err(Error::Verification(
            "TBS length exceeds certificate contents".to_string(),
        ));
    }

    Ok(cert_contents[..tbs_total_len].to_vec())
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

/// Verify that the certificate conforms to the Sigstore X.509 profile
///
/// This checks:
/// - KeyUsage extension contains digitalSignature
/// - ExtendedKeyUsage extension contains codeSigning
pub fn verify_x509_profile(cert_der: &[u8]) -> Result<()> {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages};
    use x509_cert::Certificate;

    // OID constants for X.509 extensions
    use const_oid::db::rfc5280::{ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE};
    use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| Error::Verification("certificate has no extensions".to_string()))?;

    // Check KeyUsage extension (OID 2.5.29.15)
    let key_usage_ext = extensions
        .iter()
        .find(|ext| ext.extn_id == ID_CE_KEY_USAGE)
        .ok_or_else(|| {
            Error::Verification("certificate is missing KeyUsage extension".to_string())
        })?;

    let key_usage = KeyUsage::from_der(key_usage_ext.extn_value.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to parse KeyUsage extension: {}", e)))?;

    if !key_usage.0.contains(KeyUsages::DigitalSignature) {
        return Err(Error::Verification(
            "KeyUsage extension does not contain digitalSignature".to_string(),
        ));
    }

    // Check ExtendedKeyUsage extension (OID 2.5.29.37)
    let eku_ext = extensions
        .iter()
        .find(|ext| ext.extn_id == ID_CE_EXT_KEY_USAGE)
        .ok_or_else(|| {
            Error::Verification("certificate is missing ExtendedKeyUsage extension".to_string())
        })?;

    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes()).map_err(|e| {
        Error::Verification(format!("failed to parse ExtendedKeyUsage extension: {}", e))
    })?;

    // Check for code signing OID (1.3.6.1.5.5.7.3.3)
    if !eku.0.contains(&ID_KP_CODE_SIGNING) {
        return Err(Error::Verification(
            "ExtendedKeyUsage extension does not contain codeSigning".to_string(),
        ));
    }

    Ok(())
}
