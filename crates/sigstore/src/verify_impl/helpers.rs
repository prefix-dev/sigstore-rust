//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
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
        VerificationMaterialContent::Certificate(cert) => cert
            .raw_bytes
            .decode()
            .map_err(|e| Error::Verification(format!("failed to decode certificate: {}", e))),
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            certificates[0]
                .raw_bytes
                .decode()
                .map_err(|e| Error::Verification(format!("failed to decode certificate: {}", e)))
        }
        VerificationMaterialContent::PublicKey { .. } => Err(Error::Verification(
            "public key verification not yet supported".to_string(),
        )),
    }
}

/// Extract signature bytes from bundle content (needed for TSA verification)
pub fn extract_signature_bytes(content: &SignatureContent) -> Result<Vec<u8>> {
    match content {
        SignatureContent::MessageSignature(msg_sig) => msg_sig
            .signature
            .decode()
            .map_err(|e| Error::Verification(format!("failed to decode signature: {}", e))),
        SignatureContent::DsseEnvelope(envelope) => {
            if envelope.signatures.is_empty() {
                return Err(Error::Verification(
                    "no signatures in DSSE envelope".to_string(),
                ));
            }
            envelope.signatures[0]
                .sig
                .decode()
                .map_err(|e| Error::Verification(format!("failed to decode signature: {}", e)))
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
        // Decode the base64-encoded timestamp
        let ts_bytes = ts
            .signed_timestamp
            .decode()
            .map_err(|e| Error::Verification(format!("failed to decode TSA timestamp: {}", e)))?;

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
                    eprintln!("Warning: failed to parse TSA timestamp: {}", e);
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

                // Map (curve, hash) to SigningScheme
                let scheme = match (curve_oid.as_str(), sig_alg_oid) {
                    // P-256 with SHA-256
                    ("1.2.840.10045.3.1.7", oid) if oid == const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2") => {
                        sigstore_crypto::SigningScheme::EcdsaP256Sha256
                    }
                    // P-256 with SHA-384 (non-standard but valid)
                    // Some test/mock certificates may use this combination
                    ("1.2.840.10045.3.1.7", oid) if oid == const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3") => {
                        sigstore_crypto::SigningScheme::EcdsaP256Sha384
                    }
                    // P-384 with SHA-384
                    ("1.3.132.0.34", oid) if oid == const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3") => {
                        sigstore_crypto::SigningScheme::EcdsaP384Sha384
                    }
                    _ => continue,
                };

                let Some(issuer_pub_key) = issuer_spki.subject_public_key.as_bytes() else {
                    continue;
                };

                if sigstore_crypto::verify_signature(issuer_pub_key, &tbs_der, signature, scheme).is_ok() {
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
fn extract_ec_curve_oid(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<String> {
    use x509_cert::der::Decode;

    // For EC keys, the algorithm OID should be id-ecPublicKey (1.2.840.10045.2.1)
    let ec_public_key_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    if spki.algorithm.oid != ec_public_key_oid {
        return Err(Error::Verification("Not an EC public key".to_string()));
    }

    // The parameters field contains the curve OID
    let Some(params) = &spki.algorithm.parameters else {
        return Err(Error::Verification("EC public key missing curve parameters".to_string()));
    };

    // The parameters are an ANY type that encodes a complete DER-encoded OID
    // We can directly decode it as an ObjectIdentifier since ANY preserves the DER encoding
    let params_der = params.to_der()
        .map_err(|e| Error::Verification(format!("failed to encode parameters: {}", e)))?;

    let curve_oid = const_oid::ObjectIdentifier::from_der(&params_der)
        .map_err(|e| Error::Verification(format!("failed to decode curve OID: {}", e)))?;

    Ok(curve_oid.to_string())
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
    let cert_contents = reader.read_slice(outer_header.length)
        .map_err(|e| Error::Verification(format!("failed to read certificate contents: {}", e)))?;

    // Now decode the TBS header from the certificate contents
    let mut tbs_reader = SliceReader::new(cert_contents)
        .map_err(|e| Error::Verification(format!("failed to create TBS reader: {}", e)))?;

    let tbs_header = x509_cert::der::Header::decode(&mut tbs_reader)
        .map_err(|e| Error::Verification(format!("failed to decode TBS header: {}", e)))?;

    // Calculate the total length of the TBS including its header
    let header_len: usize = tbs_header.encoded_len()
        .map_err(|e| Error::Verification(format!("failed to encode TBS header length: {}", e)))?
        .try_into()
        .map_err(|_| Error::Verification("TBS header length too large".to_string()))?;

    let body_len: usize = tbs_header.length.try_into()
        .map_err(|_| Error::Verification("TBS body length too large".to_string()))?;

    let tbs_total_len = header_len.checked_add(body_len)
        .ok_or_else(|| Error::Verification("TBS length calculation overflow".to_string()))?;

    // Extract the TBS bytes (header + body)
    if tbs_total_len > cert_contents.len() {
        return Err(Error::Verification("TBS length exceeds certificate contents".to_string()));
    }

    Ok(cert_contents[..tbs_total_len].to_vec())
}

/// Verify the Signed Certificate Timestamp (SCT) embedded in the certificate
///
/// SCTs provide proof that the certificate was submitted to a Certificate
/// Transparency log. This is a key part of Sigstore's security model.
///
/// CRITICAL: Embedded SCTs sign the Pre-Certificate, not the final certificate.
/// We must reconstruct the Pre-Certificate TBS by removing the SCT extension.
pub fn verify_sct(
    verification_material: &VerificationMaterialContent,
    trusted_root: Option<&TrustedRoot>
) -> Result<()> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // If no trusted root is provided, skip SCT verification
    let Some(root) = trusted_root else {
        return Ok(());
    };

    // Extract certificate for verification
    let cert_der = extract_certificate_der(verification_material)?;

    // Parse the certificate to access extensions
    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    // Look for the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| Error::Verification("certificate has no extensions".to_string()))?;

    let Some(sct_extension) = extensions
        .iter()
        .find(|ext| ext.extn_id == const_oid::db::rfc6962::CT_PRECERT_SCTS)
    else {
        return Err(Error::Verification(
            "certificate is missing SCT extension (Signed Certificate Timestamp)".to_string(),
        ));
    };

    // Get CT log keys from trusted root with their IDs
    let ct_keys = root
        .ctfe_keys_with_ids()
        .map_err(|e| Error::Verification(format!("failed to get CT log keys: {}", e)))?;

    if ct_keys.is_empty() {
        return Err(Error::Verification(
            "no CT log keys in trusted root".to_string(),
        ));
    }

    // Parse the SCT list from the extension
    // The extension value is a DER OCTET STRING containing the TLS-encoded SCT list
    // We use OctetString::from_der to handle the ASN.1 OCTET STRING decoding safely
    use x509_cert::der::asn1::OctetString;
    let sct_list_octet = OctetString::from_der(sct_extension.extn_value.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to decode SCT extension octet string: {}", e)))?;
    let sct_list_bytes = sct_list_octet.as_bytes();

    // Prepare the Pre-Certificate TBS for verification
    // CRITICAL: Embedded SCTs sign the PreCert, not the final Cert.
    // We must remove the SCT extension to reconstruct what was signed.
    let precert_tbs_der = create_precert_tbs(&cert, sct_extension)?;

    // Get issuer key hash
    let issuer_key_hash = get_issuer_key_hash(&cert_der, verification_material, trusted_root)?;

    // Parse the TLS-encoded SCT list manually (2-byte length + SCTs)
    if sct_list_bytes.len() < 2 {
        return Err(Error::Verification("SCT list too short".to_string()));
    }

    let list_len = u16::from_be_bytes([sct_list_bytes[0], sct_list_bytes[1]]) as usize;
    if sct_list_bytes.len() < 2 + list_len {
        return Err(Error::Verification(format!(
            "SCT list length mismatch: header says {} bytes, have {} bytes total",
            list_len, sct_list_bytes.len() - 2
        )));
    }

    let scts_data = &sct_list_bytes[2..2 + list_len];

    // Iterate through individual SCTs
    let mut verified_any = false;
    let mut pos = 0;

    while pos < scts_data.len() {
        if pos + 2 > scts_data.len() {
            break;
        }

        let sct_len = u16::from_be_bytes([scts_data[pos], scts_data[pos + 1]]) as usize;
        pos += 2;

        if pos + sct_len > scts_data.len() {
            return Err(Error::Verification("SCT length overflow".to_string()));
        }

        let sct_bytes = &scts_data[pos..pos + sct_len];
        pos += sct_len;

        // Extract Log ID from SCT to find the correct key
        // SCT structure: Version (1) + LogID (32) + ...
        if sct_bytes.len() < 33 {
            continue;
        }
        let sct_log_id = &sct_bytes[1..33];

        // Find the matching key in trusted root
        if let Some((_, public_key)) = ct_keys.iter().find(|(id, _)| id == sct_log_id) {
            match verify_single_sct(sct_bytes, &precert_tbs_der, &issuer_key_hash, sct_log_id, public_key) {
                Ok(_) => {
                    verified_any = true;
                }
                Err(_e) => {
                    // Verification failed for this specific SCT against the matching key.
                    // We continue to see if other SCTs verify.
                }
            }
        } else {
            // Log ID not found in trusted root
            // This is common if the bundle contains SCTs from logs not in our trusted root
            // We just ignore them and hope another SCT verifies
        }

        if verified_any {
            break;
        }
    }

    if !verified_any {
        return Err(Error::Verification(
            "no valid SCT could be verified against trusted CT logs".to_string(),
        ));
    }

    Ok(())
}

/// Reconstructs the Pre-Certificate TBS data by removing the SCT extension
///
/// CRITICAL: The CT Log signs the Pre-Certificate, which is the certificate
/// without the SCT extension. We must remove it to reconstruct what was signed.
fn create_precert_tbs(
    cert: &x509_cert::Certificate,
    sct_ext_to_remove: &x509_cert::ext::Extension,
) -> Result<Vec<u8>> {
    let mut tbs = cert.tbs_certificate.clone();

    // Filter out the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)
    if let Some(exts) = tbs.extensions.as_mut() {
        let initial_len = exts.len();
        exts.retain(|ext| ext.extn_id != sct_ext_to_remove.extn_id);

        // Also remove the "Poison" extension if present (OID 1.3.6.1.4.1.11129.2.4.3)
        // This marks a precertificate, and the Log strips it before signing
        let poison_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.3");
        exts.retain(|ext| ext.extn_id != poison_oid);

        if exts.is_empty() && initial_len > 0 {
            tbs.extensions = None;
        }
    }

    tbs.to_der()
        .map_err(|e| Error::Verification(format!("failed to serialize precert TBS: {}", e)))
}

/// Verify a single SCT against the Pre-Certificate
///
/// This parses the raw SCT bytes and verifies the signature according to RFC 6962.
fn verify_single_sct(
    sct_bytes: &[u8],
    precert_tbs: &[u8],
    issuer_key_hash: &[u8],
    expected_log_id: &[u8],
    public_key: &[u8],
) -> Result<()> {
    use sigstore_crypto::{verify_signature, SigningScheme};

    // Parse SCT structure (RFC 6962 Section 3.2)
    // Minimum: 1 (version) + 32 (log_id) + 8 (timestamp) + 2 (extensions_len) = 43 bytes
    if sct_bytes.len() < 43 {
        return Err(Error::Verification("SCT too short".to_string()));
    }

    let version = sct_bytes[0];
    if version != 0 {
        return Err(Error::Verification(format!(
            "unsupported SCT version: {}",
            version
        )));
    }

    let log_id = &sct_bytes[1..33];
    if log_id != expected_log_id {
        return Err(Error::Verification("SCT log ID mismatch".to_string()));
    }

    let timestamp_bytes = &sct_bytes[33..41];
    // We don't strictly need to parse the timestamp for verification, but we can
    let _timestamp = u64::from_be_bytes([
        timestamp_bytes[0],
        timestamp_bytes[1],
        timestamp_bytes[2],
        timestamp_bytes[3],
        timestamp_bytes[4],
        timestamp_bytes[5],
        timestamp_bytes[6],
        timestamp_bytes[7],
    ]);

    let extensions_len = u16::from_be_bytes([sct_bytes[41], sct_bytes[42]]) as usize;
    if sct_bytes.len() < 43 + extensions_len {
        return Err(Error::Verification("SCT extensions overflow".to_string()));
    }

    let extensions = &sct_bytes[43..43 + extensions_len];

    // The signature starts after extensions
    let sig_start = 43 + extensions_len;
    if sct_bytes.len() < sig_start + 4 {
        return Err(Error::Verification("SCT signature missing".to_string()));
    }

    // Signature format: 1 byte hash algo + 1 byte sig algo + 2 bytes sig length + signature
    let hash_algo = sct_bytes[sig_start];
    let sig_algo = sct_bytes[sig_start + 1];
    let sig_len = u16::from_be_bytes([sct_bytes[sig_start + 2], sct_bytes[sig_start + 3]]) as usize;

    if sct_bytes.len() < sig_start + 4 + sig_len {
        return Err(Error::Verification("SCT signature length mismatch".to_string()));
    }

    let signature = &sct_bytes[sig_start + 4..sig_start + 4 + sig_len];

    // Construct the digitally signed data (RFC 6962 Section 3.2)
    // CRITICAL: For embedded SCTs, this is signed over the Pre-Certificate (entry_type = 1)
    let mut signed_data = Vec::new();

    // Version (1 byte) - always 0 for v1
    signed_data.push(version);

    // SignatureType (1 byte) - CertificateTimestamp (0)
    signed_data.push(0);

    // Timestamp (8 bytes, big-endian)
    signed_data.extend_from_slice(timestamp_bytes);

    // LogEntryType (2 bytes) - PrecertEntry (1) for embedded SCTs
    // CRITICAL FIX: This must be 1 (PrecertEntry), not 0 (X509Entry)
    signed_data.extend_from_slice(&[0, 1]);

    // PreCert structure:
    // issuer_key_hash (32 bytes)
    if issuer_key_hash.len() != 32 {
         return Err(Error::Verification("issuer key hash must be 32 bytes".to_string()));
    }
    signed_data.extend_from_slice(issuer_key_hash);

    // PrecertEntry: 3-byte length prefix + TBS certificate (without SCT extension)
    let tbs_len = precert_tbs.len();
    signed_data.push(((tbs_len >> 16) & 0xFF) as u8);
    signed_data.push(((tbs_len >> 8) & 0xFF) as u8);
    signed_data.push((tbs_len & 0xFF) as u8);
    signed_data.extend_from_slice(precert_tbs);

    // Extensions (2-byte length + data)
    signed_data.push(((extensions_len >> 8) & 0xFF) as u8);
    signed_data.push((extensions_len & 0xFF) as u8);
    signed_data.extend_from_slice(extensions);

    // Determine signing scheme based on hash and signature algorithms
    // RFC 5246 SignatureAndHashAlgorithm encoding:
    // hash (1 byte) | signature (1 byte)
    // For CT: hash=4 (SHA256), sig=3 (ECDSA) => 0x0403
    //        hash=5 (SHA384), sig=3 (ECDSA) => 0x0503
    let scheme = match (hash_algo, sig_algo) {
        (4, 3) => SigningScheme::EcdsaP256Sha256,  // SHA-256 with ECDSA
        (5, 3) => SigningScheme::EcdsaP384Sha384,  // SHA-384 with ECDSA
        _ => {
            return Err(Error::Verification(format!(
                "unsupported SCT algorithm combination: hash={}, sig={}",
                hash_algo, sig_algo
            )))
        }
    };

    // Verify the SCT signature
    let result = verify_signature(public_key, &signed_data, signature, scheme)
        .map_err(|e| Error::Verification(format!("SCT signature verification failed: {}", e)));
    
    if result.is_err() {
        println!("SCT signature verification failed.");
        println!("Log ID: {:x?}", log_id);
        // println!("Signed Data (hex): {:x?}", signed_data);
        // println!("Signature (hex): {:x?}", signature);
        // println!("Public Key (hex): {:x?}", public_key);
    }
    
    result
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
        .find(|ext| ext.extn_id.to_string() == "2.5.29.15")
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
        .find(|ext| ext.extn_id.to_string() == "2.5.29.37")
        .ok_or_else(|| {
            Error::Verification("certificate is missing ExtendedKeyUsage extension".to_string())
        })?;

    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes()).map_err(|e| {
        Error::Verification(format!("failed to parse ExtendedKeyUsage extension: {}", e))
    })?;

    // Check for code signing OID (1.3.6.1.5.5.7.3.3)
    let code_signing_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
    if !eku.0.iter().any(|oid| *oid == code_signing_oid) {
        return Err(Error::Verification(
            "ExtendedKeyUsage extension does not contain codeSigning".to_string(),
        ));
    }

    Ok(())
}

/// Calculate the SPKI (Subject Public Key Info) hash for a certificate
fn calculate_spki_hash(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;
    
    let cert = Certificate::from_der(cert_der).map_err(|e| {
        Error::Verification(format!("failed to parse certificate for SPKI hash: {}", e))
    })?;
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der().map_err(|e| {
        Error::Verification(format!("failed to serialize SPKI: {}", e))
    })?;
    Ok(sigstore_crypto::sha256(&spki_der).to_vec())
}

/// Get the issuer key hash for SCT verification
///
/// This attempts to find the issuer's public key hash using the verification material
/// and the trusted root.
fn get_issuer_key_hash(
    cert_der: &[u8],
    verification_material: &VerificationMaterialContent,
    trusted_root: Option<&TrustedRoot>
) -> Result<Vec<u8>> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // 1. Try to get from chain in verification material
    if let VerificationMaterialContent::X509CertificateChain { certificates } = verification_material {
        if certificates.len() > 1 {
            let issuer_der = certificates[1].raw_bytes.decode().map_err(|e| {
                Error::Verification(format!("failed to decode issuer certificate: {}", e))
            })?;
            return calculate_spki_hash(&issuer_der);
        }
    }
    
    // 2. Try to find in trusted root
    if let Some(root) = trusted_root {
        let cert = Certificate::from_der(cert_der).map_err(|e| {
            Error::Verification(format!("failed to parse certificate: {}", e))
        })?;
        let issuer_name = cert.tbs_certificate.issuer;
        
        let fulcio_certs = root.fulcio_certs().map_err(|e| {
            Error::Verification(format!("failed to get Fulcio certs: {}", e))
        })?;
        
        for ca_der in fulcio_certs {
            if let Ok(ca_cert) = Certificate::from_der(&ca_der) {
                if ca_cert.tbs_certificate.subject == issuer_name {
                    return calculate_spki_hash(&ca_der);
                }
            }
        }
    }
    
    Err(Error::Verification("could not find issuer certificate for SCT verification".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_trust_root::TrustedRoot;

    #[test]
    fn test_verify_sct_with_conformance_data() {
        use x509_cert::der::{Decode, Encode, Header, Reader, SliceReader};
        // Certificate from sigstore-conformance/test/assets/bundle-verify/happy-path/bundle.sigstore.json
        // This certificate contains an embedded SCT
        let cert_base64 = "MIIIGTCCB5+gAwIBAgIUBPWs4OPN1kte0mUMGZrZ6ozMVRkwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjMwNzEyMTU1NjM1WhcNMjMwNzEyMTYwNjM1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVr33uVAPA1SpA5w/mmBF9ariW8E7oizIQKqiYfxwSb1zftqZZX045y3tPbRkIWe+t7MUYliQknQ954rDDEASnKOCBr4wgga6MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUx2TNZkruHC2aCdyIXscI8N/8q2owHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wgaUGA1UdEQEB/wSBmjCBl4aBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAfBgorBgEEAYO/MAECBBF3b3JrZmxvd19kaXNwYXRjaDA2BgorBgEEAYO/MAEDBChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MC0GCisGAQQBg78wAQQEH0V4dHJlbWVseSBkYW5nZXJvdXMgT0lEQyBiZWFjb24wSQYKKwYBBAGDvzABBQQ7c2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24wHQYKKwYBBAGDvzABBgQPcmVmcy9oZWFkcy9tYWluMDsGCisGAQQBg78wAQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTCBpgYKKwYBBAGDvzABCQSBlwyBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABCgQqDChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDBeBgorBgEEAYO/MAEMBFAMTmh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbjA4BgorBgEEAYO/MAENBCoMKGFmNzg1YjZkM2IwZmEwYzBhYTEzMDVmYWVlN2NlNjAzNmU4ZDkwYzQwHwYKKwYBBAGDvzABDgQRDA9yZWZzL2hlYWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk2MzI1OTY4OTcwNwYKKwYBBAGDvzABEAQpDCdodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UwGQYKKwYBBAGDvzABEQQLDAkxMzE4MDQ1NjMwgaYGCisGAQQBg78wARIEgZcMgZRodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24vLmdpdGh1Yi93b3JrZmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1vaWRjLWJlYWNvbi55bWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wARMEKgwoYWY3ODViNmQzYjBmYTBjMGFhMTMwNWZhZWU3Y2U2MDM2ZThkOTBjNDAhBgorBgEEAYO/MAEUBBMMEXdvcmtmbG93X2Rpc3BhdGNoMIGBBgorBgEEAYO/MAEVBHMMcWh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi9hY3Rpb25zL3J1bnMvNTUzMzc0MTQ5Ny9hdHRlbXB0cy8xMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGJStGTCwAABAMARzBFAiBCA4jZQP4CwMiWoeS7WMW46QkI4e7OsNH3yVhf5wdBvgIhAPJYxdsi9NqOXVZsEUtCup8m1m/2zG39FTGlgE0MorDFMAoGCCqGSM49BAMDA2gAMGUCMEYWRwI5QJeOwNCuV4tnZ0n5QNlUlP0BtX5V2ZTQLqcQbWtneC7tLptiYgr0Z62UDQIxAO6ItXAH+sbZcsbj08xr3GApM6hjvyTAl39pS3Y3sZwAz8lfQDHNL4eALEo1heAYVg==";
        
        use base64::Engine;
        let cert_der = base64::engine::general_purpose::STANDARD.decode(cert_base64).expect("failed to decode cert");

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
                    println!("Difference at offset {}: original {:02x}, re-encoded {:02x}", i, a, b);
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

        let trusted_root = TrustedRoot::from_json(trusted_root_json).expect("failed to parse trusted root");

        // Verify the SCT
        use sigstore_types::bundle::CertificateContent;
        let content = VerificationMaterialContent::Certificate(CertificateContent {
            raw_bytes: cert_base64.to_string().into(),
        });
        let result = verify_sct(&content, Some(&trusted_root));
        assert!(result.is_ok(), "SCT verification failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_sct_invalid_key() {
        let trusted_root_json = include_str!("../../test_data/invalid-ct-key_fail/trusted_root.json");
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
        assert!(result_chain.is_ok(), "Chain verification failed: {:?}", result_chain.err());
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

        let trusted_root = TrustedRoot::from_json(trusted_root_json).expect("failed to parse trusted root");

        // Verify the SCT
        use sigstore_types::bundle::CertificateContent;
        let content = VerificationMaterialContent::Certificate(CertificateContent {
            raw_bytes: cert_base64.to_string().into(),
        });
        let result = verify_sct(&content, Some(&trusted_root));
        assert!(result.is_err(), "SCT verification should fail due to signature mismatch");
    }
}
