//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SECP_256_R_1, SECP_384_R_1};
use sigstore_crypto::CertificateInfo;
use sigstore_trust_root::TrustedRoot;
use sigstore_tsa::parse_timestamp;
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
    trusted_root: Option<&TrustedRoot>,
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

        // If we have a trusted root, perform full verification
        if let Some(root) = trusted_root {
            // Build verification options from trusted root
            let mut opts = TsaVerifyOpts::new();

            // Get TSA root certificates
            if let Ok(tsa_roots) = root.tsa_root_certs() {
                opts = opts.with_roots(tsa_roots);
            }

            // Get TSA intermediate certificates
            if let Ok(tsa_intermediates) = root.tsa_intermediate_certs() {
                opts = opts.with_intermediates(tsa_intermediates);
            }

            // Get TSA leaf certificate
            if let Ok(tsa_leaves) = root.tsa_leaf_certs() {
                if let Some(leaf) = tsa_leaves.first() {
                    opts = opts.with_tsa_certificate(leaf.clone());
                }
            }

            // Get TSA validity period from trusted root
            if let Ok(tsa_certs) = root.tsa_certs_with_validity() {
                if let Some((_cert, Some(start), Some(end))) = tsa_certs.first() {
                    opts = opts.with_tsa_validity(*start, *end);
                }
            }

            // Verify the timestamp response with full cryptographic validation
            let result =
                verify_timestamp_response(&ts_bytes, signature_bytes, opts).map_err(|e| {
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
        } else {
            // No trusted root - fall back to just parsing (old behavior)
            match parse_timestamp(&ts_bytes) {
                Ok(timestamp) => {
                    if let Some(earliest) = earliest_timestamp {
                        if timestamp < earliest {
                            earliest_timestamp = Some(timestamp);
                        }
                    } else {
                        earliest_timestamp = Some(timestamp);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse TSA timestamp: {}", e);
                }
            }
        }
    }

    // If we have a trusted root and timestamps were present but none verified, that's an error
    if trusted_root.is_some()
        && !any_timestamp_verified
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
    trusted_root: Option<&TrustedRoot>,
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
    trusted_root: Option<&TrustedRoot>,
) -> Result<()> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // If no trusted root is provided, skip chain verification
    let Some(root) = trusted_root else {
        return Ok(());
    };

    // Get Fulcio certificates from trusted root
    let fulcio_certs = root
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
    trusted_root: Option<&TrustedRoot>,
) -> Result<()> {
    // If no trusted root is provided, skip SCT verification
    let Some(root) = trusted_root else {
        return Ok(());
    };

    // Extract certificate for verification
    let cert_der = extract_certificate_der(verification_material)?;

    // Get issuer SPKI for calculating the issuer key hash
    let issuer_spki_der = get_issuer_spki(verification_material, &cert_der, trusted_root)?;

    // Delegate to the new sct module for verification
    super::sct::verify_sct(&cert_der, &issuer_spki_der, root)
}

/// Get the issuer's SubjectPublicKeyInfo DER bytes
///
/// This tries to find the issuer certificate in the verification material chain
/// or in the trusted root, and returns its SPKI for SCT verification.
fn get_issuer_spki(
    verification_material: &VerificationMaterialContent,
    cert_der: &[u8],
    trusted_root: Option<&TrustedRoot>,
) -> Result<Vec<u8>> {
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

    // 1. Try to get from chain in verification material
    if let VerificationMaterialContent::X509CertificateChain { certificates } =
        verification_material
    {
        if certificates.len() > 1 {
            let issuer_der = certificates[1].raw_bytes.as_bytes();
            let issuer_cert = Certificate::from_der(&issuer_der).map_err(|e| {
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
    if let Some(root) = trusted_root {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;
        let issuer_name = cert.tbs_certificate.issuer;

        let fulcio_certs = root
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

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_crypto::der_from_pem;
    use sigstore_trust_root::TrustedRoot;

    // Test data from sigstore-python reference implementation
    const BOGUS_LEAF_PEM: &str = include_str!("../../test_data/x509/bogus-leaf.pem");
    const BOGUS_LEAF_INVALID_EKU_PEM: &str =
        include_str!("../../test_data/x509/bogus-leaf-invalid-eku.pem");
    const BOGUS_LEAF_MISSING_EKU_PEM: &str =
        include_str!("../../test_data/x509/bogus-leaf-missing-eku.pem");
    const BOGUS_LEAF_INVALID_KU_PEM: &str =
        include_str!("../../test_data/x509/bogus-leaf-invalid-ku.pem");
    const BOGUS_ROOT_PEM: &str = include_str!("../../test_data/x509/bogus-root.pem");

    #[test]
    fn test_verify_x509_profile_valid_leaf() {
        // Valid leaf certificate should pass X.509 profile validation
        let cert_der = der_from_pem(BOGUS_LEAF_PEM).expect("failed to parse PEM");
        let result = verify_x509_profile(&cert_der);
        assert!(
            result.is_ok(),
            "Valid leaf certificate should pass X.509 profile validation: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_x509_profile_invalid_eku() {
        // Certificate with invalid EKU (serverAuth instead of codeSigning)
        let cert_der = der_from_pem(BOGUS_LEAF_INVALID_EKU_PEM).expect("failed to parse PEM");
        let result = verify_x509_profile(&cert_der);
        assert!(
            result.is_err(),
            "Certificate with invalid EKU should fail validation"
        );
        let err = result.unwrap_err();
        assert!(
            format!("{:?}", err).contains("codeSigning"),
            "Error should mention codeSigning: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_x509_profile_missing_eku() {
        // Certificate missing EKU extension entirely
        let cert_der = der_from_pem(BOGUS_LEAF_MISSING_EKU_PEM).expect("failed to parse PEM");
        let result = verify_x509_profile(&cert_der);
        assert!(
            result.is_err(),
            "Certificate missing EKU should fail validation"
        );
        let err = result.unwrap_err();
        assert!(
            format!("{:?}", err).contains("ExtendedKeyUsage"),
            "Error should mention ExtendedKeyUsage: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_x509_profile_invalid_ku() {
        // Certificate with invalid KeyUsage (no bits set)
        let cert_der = der_from_pem(BOGUS_LEAF_INVALID_KU_PEM).expect("failed to parse PEM");
        let result = verify_x509_profile(&cert_der);
        assert!(
            result.is_err(),
            "Certificate with invalid KeyUsage should fail validation"
        );
        let err = result.unwrap_err();
        assert!(
            format!("{:?}", err).contains("digitalSignature"),
            "Error should mention digitalSignature: {:?}",
            err
        );
    }

    #[test]
    fn test_verify_x509_profile_root_cert() {
        // Root CA certificate - not a leaf, should fail EKU check
        let cert_der = der_from_pem(BOGUS_ROOT_PEM).expect("failed to parse PEM");
        let result = verify_x509_profile(&cert_der);
        // Root certs typically don't have codeSigning EKU
        assert!(
            result.is_err(),
            "Root CA certificate should fail leaf validation"
        );
    }

    #[test]
    fn test_certificate_parsing_extracts_san() {
        // Test that certificate parsing correctly extracts SAN identity
        let cert_der = der_from_pem(BOGUS_LEAF_PEM).expect("failed to parse PEM");
        let cert_info =
            sigstore_crypto::parse_certificate_info(&cert_der).expect("failed to parse cert");

        // The bogus-leaf.pem has a DNS SAN of bogus.example.com
        // (which shows as None since it's a DNS name, not email/URI)
        // This test verifies the parsing doesn't fail
        assert!(cert_info.not_before > 0);
        assert!(cert_info.not_after > cert_info.not_before);
    }

    #[test]
    fn test_certificate_time_validation() {
        let cert_der = der_from_pem(BOGUS_LEAF_PEM).expect("failed to parse PEM");
        let cert_info =
            sigstore_crypto::parse_certificate_info(&cert_der).expect("failed to parse cert");

        // Test with time within validity period
        let valid_time = cert_info.not_before + 1000;
        let result = validate_certificate_time(valid_time, &cert_info);
        assert!(result.is_ok(), "Should accept time within validity period");

        // Test with time before validity period
        let before_time = cert_info.not_before - 1;
        let result = validate_certificate_time(before_time, &cert_info);
        assert!(result.is_err(), "Should reject time before validity period");

        // Test with time after validity period
        let after_time = cert_info.not_after + 1;
        let result = validate_certificate_time(after_time, &cert_info);
        assert!(result.is_err(), "Should reject time after validity period");
    }

    #[test]
    fn test_verify_sct_with_conformance_data() {
        use x509_cert::der::{Decode, Encode, Header, Reader, SliceReader};
        // Certificate from sigstore-conformance/test/assets/bundle-verify/happy-path/bundle.sigstore.json
        // This certificate contains an embedded SCT
        let cert_base64 = "MIIIGTCCB5+gAwIBAgIUBPWs4OPN1kte0mUMGZrZ6ozMVRkwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjMwNzEyMTU1NjM1WhcNMjMwNzEyMTYwNjM1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVr33uVAPA1SpA5w/mmBF9ariW8E7oizIQKqiYfxwSb1zftqZZX045y3tPbRkIWe+t7MUYliQknQ954rDDEASnKOCBr4wgga6MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUx2TNZkruHC2aCdyIXscI8N/8q2owHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wgaUGA1UdEQEB/wSBmjCBl4aBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAfBgorBgEEAYO/MAECBBF3b3JrZmxvd19kaXNwYXRjaDA2BgorBgEEAYO/MAEDBChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MC0GCisGAQQBg78wAQQEH0V4dHJlbWVseSBkYW5nZXJvdXMgT0lEQyBiZWFjb24wSQYKKwYBBAGDvzABBQQ7c2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24wHQYKKwYBBAGDvzABBgQPcmVmcy9oZWFkcy9tYWluMDsGCisGAQQBg78wAQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTCBpgYKKwYBBAGDvzABCQSBlwyBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABCgQqDChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDBeBgorBgEEAYO/MAEMBFAMTmh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbjA4BgorBgEEAYO/MAENBCoMKGFmNzg1YjZkM2IwZmEwYzBhYTEzMDVmYWVlN2NlNjAzNmU4ZDkwYzQwHwYKKwYBBAGDvzABDgQRDA9yZWZzL2hlYWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk2MzI1OTY4OTcwNwYKKwYBBAGDvzABEAQpDCdodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UwGQYKKwYBBAGDvzABEQQLDAkxMzE4MDQ1NjMwgaYGCisGAQQBg78wARIEgZcMgZRodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24vLmdpdGh1Yi93b3JrZmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1vaWRjLWJlYWNvbi55bWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wARMEKgwoYWY3ODViNmQzYjBmYTBjMGFhMTMwNWZhZWU3Y2U2MDM2ZThkOTBjNDAhBgorBgEEAYO/MAEUBBMMEXdvcmtmbG93X2Rpc3BhdGNoMIGBBgorBgEEAYO/MAEVBHMMcWh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi9hY3Rpb25zL3J1bnMvNTUzMzc0MTQ5Ny9hdHRlbXB0cy8xMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGJStGTCwAABAMARzBFAiBCA4jZQP4CwMiWoeS7WMW46QkI4e7OsNH3yVhf5wdBvgIhAPJYxdsi9NqOXVZsEUtCup8m1m/2zG39FTGlgE0MorDFMAoGCCqGSM49BAMDA2gAMGUCMEYWRwI5QJeOwNCuV4tnZ0n5QNlUlP0BtX5V2ZTQLqcQbWtneC7tLptiYgr0Z62UDQIxAO6ItXAH+sbZcsbj08xr3GApM6hjvyTAl39pS3Y3sZwAz8lfQDHNL4eALEo1heAYVg==";

        use base64::Engine;
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(cert_base64)
            .expect("failed to decode cert");

        // --- Round-trip check ---
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        let re_encoded_tbs = cert.tbs_certificate.to_der().unwrap();

        let mut reader = SliceReader::new(&cert_der).unwrap();
        let outer_header = Header::decode(&mut reader).unwrap();
        let outer_body = reader.read_slice(outer_header.length).unwrap();

        // Now decode TBS header from outer_body
        let mut tbs_reader = SliceReader::new(outer_body).unwrap();
        let tbs_header = Header::decode(&mut tbs_reader).unwrap();
        let tbs_total_len = (tbs_header.encoded_len().unwrap() + tbs_header.length).unwrap();
        let tbs_total_len_usize: usize = tbs_total_len.try_into().unwrap();

        let original_tbs = &outer_body[..tbs_total_len_usize];

        if original_tbs != re_encoded_tbs {
            println!("TBS round-trip FAILED!");
            println!("Original len: {}", original_tbs.len());
            println!("Re-encoded len: {}", re_encoded_tbs.len());

            // Find first difference
            for (i, (a, b)) in original_tbs.iter().zip(re_encoded_tbs.iter()).enumerate() {
                if a != b {
                    println!(
                        "Difference at offset {}: original {:02x}, re-encoded {:02x}",
                        i, a, b
                    );
                    break;
                }
            }
        } else {
            println!("TBS round-trip SUCCEEDED!");
        }
        // ------------------------

        // Construct a trusted root with the CT log key that signed the SCT
        // Key ID: 3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o=
        // Public Key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==
        let trusted_root_json = r#"{
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [],
            "certificateAuthorities": [
                {
                  "subject": {
                    "organization": "sigstore.dev",
                    "commonName": "sigstore"
                  },
                  "uri": "https://fulcio.sigstore.dev",
                  "certChain": {
                    "certificates": [
                      {
                        "rawBytes": "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="
                      }
                    ]
                  },
                  "validFor": {
                    "start": "2021-03-07T03:20:29.000Z",
                    "end": "2022-12-31T23:59:59.999Z"
                  }
                },
                {
                  "subject": {
                    "organization": "sigstore.dev",
                    "commonName": "sigstore"
                  },
                  "uri": "https://fulcio.sigstore.dev",
                  "certChain": {
                    "certificates": [
                      {
                        "rawBytes": "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="
                      },
                      {
                        "rawBytes": "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"
                      }
                    ]
                  },
                  "validFor": {
                    "start": "2022-04-13T20:06:15.000Z"
                  }
                }
            ],
            "ctlogs": [{
                "baseUrl": "https://ctfe.sigstore.dev/2022",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==",
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                },
                "logId": {
                    "keyId": "3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o="
                }
            }],
            "timestampAuthorities": []
        }"#;

        let trusted_root =
            TrustedRoot::from_json(trusted_root_json).expect("failed to parse trusted root");

        // Verify the SCT
        use sigstore_types::bundle::CertificateContent;
        use sigstore_types::DerCertificate;
        let content = VerificationMaterialContent::Certificate(CertificateContent {
            raw_bytes: DerCertificate::from_base64(cert_base64).expect("valid base64"),
        });
        let result = verify_sct(&content, Some(&trusted_root));
        assert!(
            result.is_ok(),
            "SCT verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_sct_invalid_key() {
        let trusted_root_json =
            include_str!("../../test_data/invalid-ct-key_fail/trusted_root.json");
        let bundle_json = include_str!("../../test_data/invalid-ct-key_fail/bundle.sigstore.json");

        let trusted_root = TrustedRoot::from_json(trusted_root_json).unwrap();
        let bundle: Bundle = serde_json::from_str(bundle_json).unwrap();

        // This should fail because the SCT key ID is not in the trusted root
        let result = verify_sct(&bundle.verification_material.content, Some(&trusted_root));
        assert!(result.is_err());

        // Also verify that the certificate chain verification succeeds (since the chain itself is valid)
        let cert_der = extract_certificate_der(&bundle.verification_material.content).unwrap();
        // Use a time within the certificate validity period (2023-07-12 15:56:35 UTC to 2023-07-12 16:06:35 UTC)
        let valid_time = 1689177500;
        let result_chain = verify_certificate_chain(&cert_der, valid_time, Some(&trusted_root));
        assert!(
            result_chain.is_ok(),
            "Chain verification failed: {:?}",
            result_chain.err()
        );
    }

    #[test]
    fn test_verify_sct_signature_mismatch() {
        // Same certificate as the happy path test
        let cert_base64 = "MIIIGTCCB5+gAwIBAgIUBPWs4OPN1kte0mUMGZrZ6ozMVRkwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjMwNzEyMTU1NjM1WhcNMjMwNzEyMTYwNjM1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVr33uVAPA1SpA5w/mmBF9ariW8E7oizIQKqiYfxwSb1zftqZZX045y3tPbRkIWe+t7MUYliQknQ954rDDEASnKOCBr4wgga6MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUx2TNZkruHC2aCdyIXscI8N/8q2owHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wgaUGA1UdEQEB/wSBmjCBl4aBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAfBgorBgEEAYO/MAECBBF3b3JrZmxvd19kaXNwYXRjaDA2BgorBgEEAYO/MAEDBChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MC0GCisGAQQBg78wAQQEH0V4dHJlbWVseSBkYW5nZXJvdXMgT0lEQyBiZWFjb24wSQYKKwYBBAGDvzABBQQ7c2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24wHQYKKwYBBAGDvzABBgQPcmVmcy9oZWFkcy9tYWluMDsGCisGAQQBg78wAQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTCBpgYKKwYBBAGDvzABCQSBlwyBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABCgQqDChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDBeBgorBgEEAYO/MAEMBFAMTmh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbjA4BgorBgEEAYO/MAENBCoMKGFmNzg1YjZkM2IwZmEwYzBhYTEzMDVmYWVlN2NlNjAzNmU4ZDkwYzQwHwYKKwYBBAGDvzABDgQRDA9yZWZzL2hlYWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk2MzI1OTY4OTcwNwYKKwYBBAGDvzABEAQpDCdodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UwGQYKKwYBBAGDvzABEQQLDAkxMzE4MDQ1NjMwgaYGCisGAQQBg78wARIEgZcMgZRodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24vLmdpdGh1Yi93b3JrZmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1vaWRjLWJlYWNvbi55bWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wARMEKgwoYWY3ODViNmQzYjBmYTBjMGFhMTMwNWZhZWU3Y2U2MDM2ZThkOTBjNDAhBgorBgEEAYO/MAEUBBMMEXdvcmtmbG93X2Rpc3BhdGNoMIGBBgorBgEEAYO/MAEVBHMMcWh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi9hY3Rpb25zL3J1bnMvNTUzMzc0MTQ5Ny9hdHRlbXB0cy8xMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGJStGTCwAABAMARzBFAiBCA4jZQP4CwMiWoeS7WMW46QkI4e7OsNH3yVhf5wdBvgIhAPJYxdsi9NqOXVZsEUtCup8m1m/2zG39FTGlgE0MorDFMAoGCCqGSM49BAMDA2gAMGUCMEYWRwI5QJeOwNCuV4tnZ0n5QNlUlP0BtX5V2ZTQLqcQbWtneC7tLptiYgr0Z62UDQIxAO6ItXAH+sbZcsbj08xr3GApM6hjvyTAl39pS3Y3sZwAz8lfQDHNL4eALEo1heAYVg==";

        // Construct a trusted root with the CORRECT Key ID but WRONG Public Key
        // Key ID: 3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o= (Matches SCT)
        // Public Key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh99xuRi6slBFd8VUJoK/rLigy4bYeSYWO/fE6Br7r0D8NpMI94+A63LR/WvLxpUUGBpY8IJA3iU2telag5CRpA== (Different key)
        let trusted_root_json = r#"{
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [],
            "certificateAuthorities": [
                {
                  "subject": {
                    "organization": "sigstore.dev",
                    "commonName": "sigstore"
                  },
                  "uri": "https://fulcio.sigstore.dev",
                  "certChain": {
                    "certificates": [
                      {
                        "rawBytes": "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="
                      }
                    ]
                  },
                  "validFor": {
                    "start": "2021-03-07T03:20:29.000Z",
                    "end": "2022-12-31T23:59:59.999Z"
                  }
                },
                {
                  "subject": {
                    "organization": "sigstore.dev",
                    "commonName": "sigstore"
                  },
                  "uri": "https://fulcio.sigstore.dev",
                  "certChain": {
                    "certificates": [
                      {
                        "rawBytes": "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="
                      },
                      {
                        "rawBytes": "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"
                      }
                    ]
                  },
                  "validFor": {
                    "start": "2022-04-13T20:06:15.000Z"
                  }
                }
            ],
            "ctlogs": [{
                "baseUrl": "https://ctfe.sigstore.dev/2022",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh99xuRi6slBFd8VUJoK/rLigy4bYeSYWO/fE6Br7r0D8NpMI94+A63LR/WvLxpUUGBpY8IJA3iU2telag5CRpA==",
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                },
                "logId": {
                    "keyId": "3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4="
                }
            }],
            "timestampAuthorities": []
        }"#;

        let trusted_root =
            TrustedRoot::from_json(trusted_root_json).expect("failed to parse trusted root");

        // Verify the SCT
        use sigstore_types::bundle::CertificateContent;
        use sigstore_types::DerCertificate;
        let content = VerificationMaterialContent::Certificate(CertificateContent {
            raw_bytes: DerCertificate::from_base64(cert_base64).expect("valid base64"),
        });
        let result = verify_sct(&content, Some(&trusted_root));
        assert!(
            result.is_err(),
            "SCT verification should fail due to signature mismatch"
        );
    }
}
