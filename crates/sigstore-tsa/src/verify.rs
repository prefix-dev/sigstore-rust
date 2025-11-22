//! RFC 3161 timestamp verification
//!
//! This module provides full verification of RFC 3161 timestamps including:
//! - CMS signature verification
//! - Certificate chain validation
//! - Message imprint validation
//! - TSA Extended Key Usage validation

use crate::asn1::{self, PkiStatus, TimeStampResp, TstInfo};
use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use rustls_pki_types::CertificateDer;
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};
use x509_cert::Certificate;

// TimeStamping Extended Key Usage OID (1.3.6.1.5.5.7.3.8)
const ID_KP_TIME_STAMPING: ObjectIdentifier = const_oid::db::rfc5280::ID_KP_TIME_STAMPING;

// OID for SignedData (1.2.840.113549.1.7.2)
const ID_SIGNED_DATA_STR: ObjectIdentifier = const_oid::db::rfc6268::ID_SIGNED_DATA;

// OID for message-digest attribute (1.2.840.113549.1.9.4)
const OID_MESSAGE_DIGEST: ObjectIdentifier = const_oid::db::rfc6268::ID_MESSAGE_DIGEST;

/// Verification options for RFC 3161 timestamps
#[derive(Debug, Clone)]
pub struct VerifyOpts<'a> {
    /// Root certificates for chain verification
    pub roots: Vec<CertificateDer<'a>>,

    /// Intermediate certificates for chain building
    pub intermediates: Vec<CertificateDer<'a>>,

    /// TSA certificate (optional if embedded in timestamp)
    pub tsa_certificate: Option<CertificateDer<'a>>,

    /// Validity period for the TSA certificate in the trusted root
    /// If provided, the timestamp must fall within this period
    pub tsa_valid_for: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

impl<'a> VerifyOpts<'a> {
    /// Create new verification options
    pub fn new() -> Self {
        Self {
            roots: Vec::new(),
            intermediates: Vec::new(),
            tsa_certificate: None,
            tsa_valid_for: None,
        }
    }

    /// Add a root certificate
    pub fn with_root(mut self, root: CertificateDer<'a>) -> Self {
        self.roots.push(root);
        self
    }

    /// Add multiple root certificates
    pub fn with_roots(mut self, roots: Vec<CertificateDer<'a>>) -> Self {
        self.roots = roots;
        self
    }

    /// Add an intermediate certificate
    pub fn with_intermediate(mut self, intermediate: CertificateDer<'a>) -> Self {
        self.intermediates.push(intermediate);
        self
    }

    /// Add multiple intermediate certificates
    pub fn with_intermediates(mut self, intermediates: Vec<CertificateDer<'a>>) -> Self {
        self.intermediates = intermediates;
        self
    }

    /// Set the TSA certificate
    pub fn with_tsa_certificate(mut self, cert: CertificateDer<'a>) -> Self {
        self.tsa_certificate = Some(cert);
        self
    }

    /// Set the TSA validity period
    pub fn with_tsa_validity(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.tsa_valid_for = Some((start, end));
        self
    }
}

impl Default for VerifyOpts<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of timestamp verification
#[derive(Debug, Clone)]
pub struct TimestampResult {
    /// The timestamp from the TSA
    pub time: DateTime<Utc>,
}

/// Verify an RFC 3161 timestamp token (ContentInfo).
///
/// This function:
/// 1. Parses the timestamp token (DER encoded ContentInfo)
/// 2. Extracts the TSTInfo to get the timestamp
/// 3. Verifies the message imprint (hash) matches the signature bytes
/// 4. Verifies the CMS signature using the embedded or provided TSA certificate
/// 5. Validates the TSA certificate chain to a trusted root
///
/// # Arguments
///
/// * `timestamp_token_bytes` - The RFC 3161 timestamp token bytes (DER encoded ContentInfo)
/// * `signature_bytes` - The signature that was timestamped
/// * `opts` - Verification options including trusted roots and validity period
///
/// # Returns
///
/// Returns `Ok(TimestampResult)` if verification succeeds, otherwise returns an error.
pub fn verify_timestamp_response(
    timestamp_token_bytes: &[u8],
    signature_bytes: &[u8],
    opts: VerifyOpts<'_>,
) -> Result<TimestampResult> {
    use cms::content_info::ContentInfo;
    use x509_cert::der::{Decode, Encode};

    tracing::debug!("Starting RFC 3161 timestamp verification");

    // Try to parse as TimeStampResp first, if that fails, try as ContentInfo
    let (content_info, token_bytes) = match TimeStampResp::from_der(timestamp_token_bytes) {
        Ok(resp) => {
            // Check status
            if resp.status.status != PkiStatus::Granted as u8
                && resp.status.status != PkiStatus::GrantedWithMods as u8
            {
                return Err(Error::ParseError(format!(
                    "Timestamp request not granted: {}",
                    resp.status.status
                )));
            }

            let token_any = resp.time_stamp_token.ok_or(Error::ParseError(
                "TimeStampResp missing timeStampToken".to_string(),
            ))?;
            // We need the DER bytes of the token for signature verification
            let bytes = token_any
                .to_der()
                .map_err(|e| Error::ParseError(format!("failed to re-encode token: {}", e)))?;

            // Parse ContentInfo from bytes
            let token = ContentInfo::from_der(&bytes).map_err(|e| {
                Error::ParseError(format!("failed to decode ContentInfo from token: {}", e))
            })?;

            (token, bytes)
        }
        Err(_) => {
            // Try as ContentInfo directly
            let token = ContentInfo::from_der(timestamp_token_bytes).map_err(|e| {
                Error::ParseError(format!("failed to decode TimeStampToken: {}", e))
            })?;
            (token, timestamp_token_bytes.to_vec())
        }
    };

    // Verify content type is SignedData
    if content_info.content_type != ID_SIGNED_DATA_STR {
        return Err(Error::ParseError(
            "ContentInfo content type is not SignedData".to_string(),
        ));
    }

    // Decode SignedData
    // content_info.content is Any, which contains the [0] EXPLICIT SignedData
    // We need to re-encode it to DER to parse it as SignedData?
    // No, content_info.content IS the SignedData (wrapped in explicit tag?)
    // cms::content_info::ContentInfo definition:
    // content: Any, -- [0] EXPLICIT

    // We can encode the content to DER, which gives us the bytes of the SignedData structure
    let signed_data_der = content_info
        .content
        .to_der()
        .map_err(|e| Error::ParseError(format!("failed to encode SignedData content: {}", e)))?;

    let signed_data = SignedData::from_der(&signed_data_der)
        .map_err(|e| Error::ParseError(format!("failed to decode SignedData: {}", e)))?;

    // Verify the content type inside SignedData is TSTInfo
    if signed_data.encap_content_info.econtent_type != asn1::OID_TST_INFO {
        return Err(Error::ParseError(
            "encap content type is not TSTInfo".to_string(),
        ));
    }

    // Extract the TSTInfo
    let tst_info = if let Some(content) = &signed_data.encap_content_info.econtent {
        // The content is an Any wrapping an OCTET STRING that contains the TSTInfo
        let tst_info_bytes = content.value();

        TstInfo::from_der(tst_info_bytes)
            .map_err(|e| Error::ParseError(format!("failed to decode TSTInfo: {}", e)))?
    } else {
        return Err(Error::NoTstInfo);
    };

    // Verify the message imprint (hash of the signature) matches
    verify_message_imprint(&tst_info, signature_bytes)?;

    // Extract the timestamp from TSTInfo
    let system_time = tst_info.gen_time.to_system_time();
    let unix_duration = system_time
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::ParseError("timestamp before epoch".to_string()))?;
    let timestamp =
        DateTime::from_timestamp(unix_duration.as_secs() as i64, unix_duration.subsec_nanos())
            .ok_or_else(|| Error::ParseError("invalid timestamp in TSTInfo".to_string()))?;

    tracing::debug!("Extracted timestamp: {}", timestamp);

    // Check that the timestamp is within the TSA validity period in the trusted root
    if let Some((start, end)) = opts.tsa_valid_for {
        if timestamp < start || timestamp > end {
            tracing::error!(
                "Timestamp {} is outside TSA validity period ({} to {})",
                timestamp,
                start,
                end
            );
            return Err(Error::OutsideValidityPeriod);
        }

        tracing::debug!(
            "Timestamp {} is within TSA validity period ({} to {})",
            timestamp,
            start,
            end
        );
    }

    // Verify the CMS signature
    let tst_info_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(Error::NoTstInfo)?
        .value();

    tracing::debug!("Starting CMS signature verification");
    // Note: verify_cms_signature expects timestamp_response_bytes to extract signed_attrs
    // But now we are passing timestamp_token_bytes (ContentInfo).
    // extract_signed_attrs_bytes needs to be updated to handle ContentInfo!
    let signer_cert = verify_cms_signature(&signed_data, tst_info_der, &token_bytes, &opts)?;
    tracing::debug!("CMS signature verification completed successfully");

    // Extract intermediate certificates from the SignedData for chain validation
    let embedded_certs = extract_certificates(&signed_data);

    // Validate certificate chain using webpki
    tracing::debug!("Starting TSA certificate chain validation");
    validate_tsa_certificate_chain(&signer_cert, timestamp, &opts, &embedded_certs)?;
    tracing::debug!("TSA certificate chain validation completed successfully");

    Ok(TimestampResult { time: timestamp })
}

/// Verify the message imprint matches the signature bytes
fn verify_message_imprint(tst_info: &TstInfo, signature_bytes: &[u8]) -> Result<()> {
    use aws_lc_rs::digest::{digest, SHA256, SHA384, SHA512};

    let message_imprint = &tst_info.message_imprint;
    let hash_alg_oid = message_imprint.hash_algorithm.algorithm.to_string();

    // Hash the signature bytes using the algorithm specified in the message imprint
    let computed_hash = match hash_alg_oid.as_str() {
        "2.16.840.1.101.3.4.2.1" => digest(&SHA256, signature_bytes), // SHA-256
        "2.16.840.1.101.3.4.2.2" => digest(&SHA384, signature_bytes), // SHA-384
        "2.16.840.1.101.3.4.2.3" => digest(&SHA512, signature_bytes), // SHA-512
        _ => {
            return Err(Error::ParseError(format!(
                "unsupported hash algorithm: {}",
                hash_alg_oid
            )))
        }
    };

    let expected_hash = message_imprint.hashed_message.as_bytes();

    if computed_hash.as_ref() != expected_hash {
        return Err(Error::HashMismatch {
            expected: hex::encode(expected_hash),
            actual: hex::encode(computed_hash),
        });
    }

    Ok(())
}

/// Verify the CMS signature and return the signer certificate
fn verify_cms_signature(
    signed_data: &SignedData,
    tst_info_der: &[u8],
    timestamp_response_bytes: &[u8],
    opts: &VerifyOpts,
) -> Result<Certificate> {
    // Get the first (and should be only) signer info
    let signer_info = signed_data
        .signer_infos
        .0
        .get(0)
        .ok_or_else(|| Error::SignatureVerificationError("no signer info found".to_string()))?;

    // Extract certificates from SignedData
    let certificates = extract_certificates(signed_data);

    // Add the provided TSA certificate if present
    let mut all_certs = certificates;
    if let Some(tsa_cert) = &opts.tsa_certificate {
        use x509_cert::der::Decode;
        if let Ok(cert) = Certificate::from_der(tsa_cert.as_ref()) {
            all_certs.push(cert);
        }
    }

    // Find the signer certificate
    let signer_cert = find_signer_certificate(&signer_info.sid, &all_certs)?;

    // Verify the message-digest attribute
    if let Some(signed_attrs) = &signer_info.signed_attrs {
        verify_message_digest_attribute(signed_attrs, tst_info_der)?;
    } else {
        return Err(Error::SignatureVerificationError(
            "no signed attributes found".to_string(),
        ));
    }

    // Extract signed_attrs bytes for signature verification
    let signed_attrs_bytes = extract_signed_attrs_bytes(timestamp_response_bytes)?;

    // Verify the signature using the signer certificate's public key
    // The signature field is a BitString, as_bytes() returns Option<&[u8]>
    let signature_bytes = signer_info.signature.as_bytes();

    // Get the digest algorithm OID from signer_info
    let digest_alg_oid = signer_info.digest_alg.oid.to_string();

    // Pass the unhashed signed_attrs_bytes - the verification function will hash it
    // using the appropriate algorithm based on BOTH the curve and digest algorithm
    verify_ecdsa_signature(
        signature_bytes,
        &signed_attrs_bytes,
        &signer_cert,
        &digest_alg_oid,
    )?;

    Ok(signer_cert)
}

/// Extract certificates from SignedData
fn extract_certificates(signed_data: &SignedData) -> Vec<Certificate> {
    let mut certificates = Vec::new();

    if let Some(cert_set) = &signed_data.certificates {
        for cert_choice in cert_set.0.iter() {
            match cert_choice {
                CertificateChoices::Certificate(cert) => {
                    certificates.push(cert.clone());
                }
                CertificateChoices::Other(_) => {
                    tracing::debug!("Skipping non-standard certificate format");
                }
            }
        }
    }

    certificates
}

/// Find the signer certificate that matches the SignerIdentifier
fn find_signer_certificate(
    signer_id: &SignerIdentifier,
    certificates: &[Certificate],
) -> Result<Certificate> {
    match signer_id {
        SignerIdentifier::IssuerAndSerialNumber(issuer_serial) => {
            // Match by issuer and serial number
            for cert in certificates {
                if cert.tbs_certificate.issuer == issuer_serial.issuer
                    && cert.tbs_certificate.serial_number == issuer_serial.serial_number
                {
                    return Ok(cert.clone());
                }
            }
            Err(Error::SignatureVerificationError(
                "no certificate matches issuer and serial number".to_string(),
            ))
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // Match by subject key identifier extension
            for cert in certificates {
                if let Some(extensions) = &cert.tbs_certificate.extensions {
                    for ext in extensions.iter() {
                        use x509_cert::der::Decode;
                        // OID for SubjectKeyIdentifier: 2.5.29.14
                        if ext.extn_id.to_string() == "2.5.29.14" {
                            if let Ok(cert_ski) =
                                x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                                    ext.extn_value.as_bytes(),
                                )
                            {
                                if &cert_ski == ski {
                                    return Ok(cert.clone());
                                }
                            }
                        }
                    }
                }
            }
            Err(Error::SignatureVerificationError(
                "no certificate matches subject key identifier".to_string(),
            ))
        }
    }
}

/// Verify the message-digest attribute in signed_attrs matches the TSTInfo content
fn verify_message_digest_attribute(
    signed_attrs: &x509_cert::attr::Attributes,
    tst_info_der: &[u8],
) -> Result<()> {
    use aws_lc_rs::digest::{digest, SHA256};
    use x509_cert::der::asn1::OctetStringRef;
    use x509_cert::der::{Decode, Encode};

    // Find the message-digest attribute
    let message_digest_attr = signed_attrs
        .iter()
        .find(|attr| attr.oid == OID_MESSAGE_DIGEST)
        .ok_or_else(|| {
            Error::SignatureVerificationError(
                "message-digest attribute not found in signed_attrs".to_string(),
            )
        })?;

    // The attribute values should contain exactly one OCTET STRING
    if message_digest_attr.values.len() != 1 {
        return Err(Error::SignatureVerificationError(
            "message-digest attribute should have exactly one value".to_string(),
        ));
    }

    // Decode the attribute value as OCTET STRING
    let message_digest_any = message_digest_attr.values.get(0).ok_or_else(|| {
        Error::SignatureVerificationError(
            "failed to get message-digest attribute value".to_string(),
        )
    })?;
    let message_digest_der = message_digest_any.to_der().map_err(|e| {
        Error::SignatureVerificationError(format!(
            "failed to encode message-digest attribute value: {}",
            e
        ))
    })?;
    let message_digest_octets = OctetStringRef::from_der(&message_digest_der).map_err(|e| {
        Error::SignatureVerificationError(format!(
            "failed to decode message-digest as OCTET STRING: {}",
            e
        ))
    })?;

    let message_digest = message_digest_octets.as_bytes();

    // Hash the TSTInfo content
    let content_hash = digest(&SHA256, tst_info_der);

    // Compare the hashes
    if content_hash.as_ref() != message_digest {
        return Err(Error::HashMismatch {
            expected: hex::encode(message_digest),
            actual: hex::encode(content_hash),
        });
    }

    Ok(())
}

/// Verify ECDSA signature using the certificate's public key and aws-lc-rs
/// The digest_alg_oid specifies which hash algorithm was used to sign (from SignerInfo)
fn verify_ecdsa_signature(
    signature: &[u8],
    message: &[u8],
    certificate: &Certificate,
    digest_alg_oid: &str,
) -> Result<()> {
    use aws_lc_rs::signature::{
        UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    };

    // Get the public key from the certificate
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let public_key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
        Error::SignatureVerificationError("invalid public key encoding".to_string())
    })?;

    // Determine the algorithm from the AlgorithmIdentifier
    let alg_oid = spki.algorithm.oid.to_string();

    match alg_oid.as_str() {
        "1.2.840.10045.2.1" => {
            // id-ecPublicKey - need to check the curve parameter
            if let Some(params) = &spki.algorithm.parameters {
                use x509_cert::der::asn1::ObjectIdentifier;

                // Decode the curve OID
                let curve_oid = params.decode_as::<ObjectIdentifier>().map_err(|e| {
                    Error::SignatureVerificationError(format!("failed to decode curve OID: {}", e))
                })?;

                // Match on BOTH curve and digest algorithm
                match (curve_oid.to_string().as_str(), digest_alg_oid) {
                    ("1.2.840.10045.3.1.7", "2.16.840.1.101.3.4.2.1") => {
                        // P-256 with SHA-256
                        let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_bytes);
                        key.verify(message, signature).map_err(|_| {
                            Error::SignatureVerificationError(
                                "P-256 SHA-256 signature verification failed".to_string(),
                            )
                        })?;
                    }
                    ("1.3.132.0.34", "2.16.840.1.101.3.4.2.1") => {
                        // P-384 with SHA-256
                        let key = UnparsedPublicKey::new(&ECDSA_P384_SHA256_ASN1, public_key_bytes);
                        key.verify(message, signature).map_err(|_| {
                            Error::SignatureVerificationError(
                                "P-384 SHA-256 signature verification failed".to_string(),
                            )
                        })?;
                    }
                    ("1.3.132.0.34", "2.16.840.1.101.3.4.2.2") => {
                        // P-384 with SHA-384
                        let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key_bytes);
                        key.verify(message, signature).map_err(|_| {
                            Error::SignatureVerificationError(
                                "P-384 SHA-384 signature verification failed".to_string(),
                            )
                        })?;
                    }
                    (curve, digest) => {
                        return Err(Error::SignatureVerificationError(format!(
                            "unsupported curve/digest combination: {} / {}",
                            curve, digest
                        )));
                    }
                }
            } else {
                return Err(Error::SignatureVerificationError(
                    "missing curve parameters for EC public key".to_string(),
                ));
            }
        }
        _ => {
            return Err(Error::SignatureVerificationError(format!(
                "unsupported signature algorithm: {}",
                alg_oid
            )));
        }
    }

    Ok(())
}

/// Validate the TSA certificate chain
fn validate_tsa_certificate_chain(
    signer_cert: &Certificate,
    timestamp: DateTime<Utc>,
    opts: &VerifyOpts,
    embedded_certs: &[Certificate],
) -> Result<()> {
    use rustls_pki_types::{CertificateDer, UnixTime};
    use x509_cert::der::Encode;

    // If no roots are provided, skip certificate chain validation
    if opts.roots.is_empty() {
        tracing::debug!("No trusted roots provided, skipping certificate chain validation");
        return Ok(());
    }

    // Convert the signer certificate to DER format for webpki
    let signer_cert_der = signer_cert.to_der().map_err(|e| {
        Error::CertificateValidationError(format!(
            "failed to encode signer certificate to DER: {}",
            e
        ))
    })?;

    let signer_cert_der = CertificateDer::from(signer_cert_der);
    let end_entity_cert = EndEntityCert::try_from(&signer_cert_der).map_err(|e| {
        Error::CertificateValidationError(format!("failed to parse end-entity certificate: {}", e))
    })?;

    // Build trust anchors from the provided roots
    let trust_anchors: Vec<_> = opts
        .roots
        .iter()
        .map(|cert| {
            anchor_from_trusted_cert(cert)
                .map(|anchor| anchor.to_owned())
                .map_err(|e| {
                    Error::CertificateValidationError(format!(
                        "failed to create trust anchor: {}",
                        e
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Convert embedded certificates to DER format for use as intermediates
    let mut intermediate_ders: Vec<CertificateDer<'static>> = Vec::new();

    for cert in embedded_certs {
        // Skip the signer certificate itself
        if cert == signer_cert {
            continue;
        }

        let cert_der = cert.to_der().map_err(|e| {
            Error::CertificateValidationError(format!(
                "failed to encode embedded certificate to DER: {}",
                e
            ))
        })?;
        intermediate_ders.push(CertificateDer::from(cert_der).into_owned());
    }

    // Add intermediates from opts
    intermediate_ders.extend(opts.intermediates.iter().map(|c| c.clone().into_owned()));

    tracing::debug!(
        "Using {} embedded intermediate cert(s) + {} provided intermediate cert(s)",
        embedded_certs.len().saturating_sub(1),
        opts.intermediates.len()
    );

    // Convert timestamp to UnixTime for webpki
    let verification_time =
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(timestamp.timestamp() as u64));

    tracing::debug!(
        "Verifying certificate chain at timestamp: {} (unix: {})",
        timestamp,
        timestamp.timestamp()
    );

    // Verify the certificate chain with TimeStamping EKU
    end_entity_cert
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediate_ders,
            verification_time,
            KeyUsage::required(ID_KP_TIME_STAMPING.as_bytes()),
            None, // No revocation checking
            None, // No path verification callback
        )
        .map_err(|e| {
            Error::CertificateValidationError(format!(
                "TSA certificate chain validation failed: {}",
                e
            ))
        })?;

    tracing::debug!("TSA certificate chain validated successfully");

    Ok(())
}

/// Extract the raw signed_attrs bytes from the timestamp DER encoding.
/// This function manually parses the DER structure to get the original bytes
/// without re-encoding, which is critical for signature verification.
///
/// The signed_attrs field is stored with context-specific tag 0xA0 in the SignerInfo,
/// but for signature verification it needs to be replaced with SET tag 0x31.
fn extract_signed_attrs_bytes(timestamp_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::der::{Decode as _, Reader, SliceReader};

    // We need to manually navigate through the DER structure to find signed_attrs
    // and extract its raw bytes, then replace the tag [0] with SET tag

    let mut reader = SliceReader::new(timestamp_der).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to create reader: {}", e))
    })?;

    // ContentInfo (SignedData wrapper)
    let _content_info_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to decode ContentInfo: {}", e))
    })?;

    // Skip OID
    let oid_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to decode OID header: {}", e))
    })?;
    reader
        .read_slice(oid_header.length)
        .map_err(|e| Error::SignatureVerificationError(format!("failed to skip OID: {}", e)))?;

    // [0] EXPLICIT tag
    let _explicit_tag = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to decode explicit tag: {}", e))
    })?;

    // SignedData SEQUENCE
    let _signed_data_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to decode SignedData: {}", e))
    })?;

    // Skip version, digestAlgorithms, encapContentInfo
    for _ in 0..3 {
        let header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
            Error::SignatureVerificationError(format!("failed to decode field: {}", e))
        })?;
        reader.read_slice(header.length).map_err(|e| {
            Error::SignatureVerificationError(format!("failed to skip field: {}", e))
        })?;
    }

    // Check for optional certificates [0]
    if let Some(byte) = reader.peek_byte() {
        if byte == 0xA0 {
            let cert_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
                Error::SignatureVerificationError(format!("failed to decode certificates: {}", e))
            })?;
            reader.read_slice(cert_header.length).map_err(|e| {
                Error::SignatureVerificationError(format!("failed to skip certificates: {}", e))
            })?;
        }
    }

    // Check for optional CRLs [1]
    if let Some(byte) = reader.peek_byte() {
        if byte == 0xA1 {
            let crl_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
                Error::SignatureVerificationError(format!("failed to decode CRLs: {}", e))
            })?;
            reader.read_slice(crl_header.length).map_err(|e| {
                Error::SignatureVerificationError(format!("failed to skip CRLs: {}", e))
            })?;
        }
    }

    // SignerInfos (SET OF)
    let _signer_infos_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to decode SignerInfos: {}", e))
    })?;

    // First SignerInfo (SEQUENCE)
    let _signer_info_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        Error::SignatureVerificationError(format!("failed to decode SignerInfo: {}", e))
    })?;

    // Skip version, sid, digestAlgorithm
    for _ in 0..3 {
        let header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
            Error::SignatureVerificationError(format!("failed to decode SignerInfo field: {}", e))
        })?;
        reader.read_slice(header.length).map_err(|e| {
            Error::SignatureVerificationError(format!("failed to skip SignerInfo field: {}", e))
        })?;
    }

    // signed_attrs [0] IMPLICIT
    if let Some(byte) = reader.peek_byte() {
        if byte == 0xA0 {
            let attrs_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
                Error::SignatureVerificationError(format!("failed to decode signed_attrs: {}", e))
            })?;

            let attrs_bytes = reader.read_slice(attrs_header.length).map_err(|e| {
                Error::SignatureVerificationError(format!("failed to read signed_attrs: {}", e))
            })?;

            // Create new bytes with SET tag (0x31) instead of [0] tag (0xA0)
            let mut result = Vec::new();
            result.push(0x31); // SET tag

            // Encode length
            let length = attrs_bytes.len();
            if length < 128 {
                result.push(length as u8);
            } else if length < 256 {
                result.push(0x81);
                result.push(length as u8);
            } else {
                result.push(0x82);
                result.push((length >> 8) as u8);
                result.push((length & 0xFF) as u8);
            }

            result.extend_from_slice(attrs_bytes);

            return Ok(result);
        }
    }

    Err(Error::SignatureVerificationError(
        "signed_attrs not found".to_string(),
    ))
}
