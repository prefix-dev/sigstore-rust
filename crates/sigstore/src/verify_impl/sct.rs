//! Certificate Transparency SCT (Signed Certificate Timestamp) verification
//!
//! This module provides types and functions for verifying SCTs embedded in certificates,
//! as defined by RFC 6962. SCTs provide proof that a certificate has been submitted to
//! a Certificate Transparency log.

use crate::error::{Error, Result};
use const_oid::db::rfc6962::CT_PRECERT_SCTS;
use sigstore_crypto::{verify_signature, SigningScheme};
use sigstore_trust_root::TrustedRoot;
use tls_codec::{SerializeBytes, TlsByteVecU16, TlsByteVecU24, TlsSerializeBytes, TlsSize};
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix::{sct::Version, SignedCertificateTimestamp, SignedCertificateTimestampList},
    Certificate,
};

// TLS SignatureAndHashAlgorithm constants (RFC 5246)
const ECDSA_SHA256: u16 = 0x0403;
const ECDSA_SHA384: u16 = 0x0503;
const RSA_PKCS1_SHA256: u16 = 0x0401;
const RSA_PKCS1_SHA384: u16 = 0x0501;
const RSA_PKCS1_SHA512: u16 = 0x0601;

/// SignatureType as defined in RFC 6962
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum SignatureType {
    CertificateTimestamp = 0,
    TreeHash = 1,
}

/// LogEntryType as defined in RFC 6962
#[derive(PartialEq, Debug)]
#[repr(u16)]
enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

/// PreCert structure for precertificate entries
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
struct PreCert {
    /// SHA-256 hash of the issuer's SubjectPublicKeyInfo
    issuer_key_hash: [u8; 32],
    /// The TBSCertificate with SCT extension removed
    tbs_certificate: TlsByteVecU24,
}

/// SignedEntry enum for different log entry types
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u16)]
enum SignedEntry {
    #[allow(unused)]
    #[tls_codec(discriminant = "LogEntryType::X509Entry")]
    X509Entry(TlsByteVecU24),
    #[tls_codec(discriminant = "LogEntryType::PrecertEntry")]
    PrecertEntry(PreCert),
}

/// The digitally-signed structure that is verified against the CT log's signature
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
pub struct DigitallySigned {
    version: Version,
    signature_type: SignatureType,
    timestamp: u64,
    signed_entry: SignedEntry,
    extensions: TlsByteVecU16,

    // These fields are not encoded in the TLS blob, but needed for verification
    #[tls_codec(skip)]
    log_id: [u8; 32],
    #[tls_codec(skip)]
    signature: Vec<u8>,
}

impl DigitallySigned {
    /// Create a DigitallySigned from an embedded SCT in a certificate
    pub fn from_embedded_sct(
        cert: &Certificate,
        sct: &SignedCertificateTimestamp,
        issuer_key_hash: [u8; 32],
    ) -> Result<Self> {
        // Reconstruct the precertificate TBS by removing the SCT extension
        let mut tbs_precert = cert.tbs_certificate.clone();
        tbs_precert.extensions = tbs_precert.extensions.map(|exts| {
            exts.iter()
                .filter(|ext| ext.extn_id != CT_PRECERT_SCTS)
                .cloned()
                .collect()
        });

        let mut tbs_precert_der = Vec::new();
        tbs_precert
            .encode_to_vec(&mut tbs_precert_der)
            .map_err(|e| Error::Verification(format!("failed to encode precert TBS: {}", e)))?;

        Ok(DigitallySigned {
            version: match sct.version {
                Version::V1 => Version::V1,
            },
            signature_type: SignatureType::CertificateTimestamp,
            timestamp: sct.timestamp,
            signed_entry: SignedEntry::PrecertEntry(PreCert {
                issuer_key_hash,
                tbs_certificate: tbs_precert_der.as_slice().into(),
            }),
            extensions: sct.extensions.clone(),
            log_id: sct.log_id.key_id,
            signature: sct.signature.signature.clone().into(),
        })
    }

    /// Verify this DigitallySigned against a public key from the CT log and SCT signature
    pub fn verify(&self, public_key: &[u8], sig_alg: u16, signature: &[u8]) -> Result<()> {
        // Serialize the signed data according to RFC 6962
        let signed_data = self
            .tls_serialize()
            .map_err(|e| Error::Verification(format!("failed to serialize SCT data: {}", e)))?;

        // Map the signature algorithm to a SigningScheme
        let scheme = match sig_alg {
            ECDSA_SHA256 => SigningScheme::EcdsaP256Sha256,
            ECDSA_SHA384 => SigningScheme::EcdsaP384Sha384,
            RSA_PKCS1_SHA256 => SigningScheme::RsaPkcs1Sha256,
            RSA_PKCS1_SHA384 => SigningScheme::RsaPkcs1Sha384,
            RSA_PKCS1_SHA512 => SigningScheme::RsaPkcs1Sha512,
            _ => {
                return Err(Error::Verification(format!(
                    "unsupported SCT signature algorithm: 0x{:04x}",
                    sig_alg
                )))
            }
        };

        verify_signature(public_key, &signed_data, signature, scheme)
            .map_err(|e| Error::Verification(format!("SCT signature verification failed: {}", e)))
    }
}

/// Extract the SCT from a certificate and prepare it for verification
pub fn extract_sct(
    cert: &Certificate,
    issuer_spki_der: &[u8],
) -> Result<(SignedCertificateTimestamp, [u8; 32])> {
    // Extract the SCT list extension from the certificate
    let scts: SignedCertificateTimestampList = match cert.tbs_certificate.get() {
        Ok(Some((_, ext))) => ext,
        _ => {
            return Err(Error::Verification(
                "certificate is missing SCT extension (Signed Certificate Timestamp)".to_string(),
            ))
        }
    };

    // Parse the SCT structures
    let timestamps = scts
        .parse_timestamps()
        .map_err(|e| Error::Verification(format!("failed to parse SCT list: {:?}", e)))?;

    // We expect exactly one SCT
    let sct = match timestamps.as_slice() {
        [single] => single
            .parse_timestamp()
            .map_err(|e| Error::Verification(format!("failed to parse SCT: {:?}", e)))?,
        [] => {
            return Err(Error::Verification(
                "no SCTs found in certificate".to_string(),
            ))
        }
        _ => {
            return Err(Error::Verification(
                "certificate contains multiple SCTs, expected exactly one".to_string(),
            ))
        }
    };

    // Calculate the issuer key hash (SHA-256 of issuer's SPKI)
    let issuer_key_hash = sigstore_crypto::sha256(issuer_spki_der);

    Ok((sct, issuer_key_hash))
}

/// Verify the Signed Certificate Timestamp (SCT) embedded in the certificate
///
/// This is the main entry point for SCT verification. It extracts the SCT from the
/// certificate, reconstructs the signed data, and verifies it against the trusted
/// CT log keys.
pub fn verify_sct(
    cert_der: &[u8],
    issuer_spki_der: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<()> {
    // Parse the certificate
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    // Extract the SCT and calculate issuer key hash
    let (sct, issuer_key_hash) = extract_sct(&cert, issuer_spki_der)?;

    // Get CT log keys from trusted root
    let ct_keys = trusted_root
        .ctfe_keys_with_ids()
        .map_err(|e| Error::Verification(format!("failed to get CT log keys: {}", e)))?;

    if ct_keys.is_empty() {
        return Err(Error::Verification(
            "no CT log keys in trusted root".to_string(),
        ));
    }

    // Find the matching CT log key by log ID
    let log_id = &sct.log_id.key_id;
    let (_, public_key) = ct_keys.iter().find(|(id, _)| id == log_id).ok_or_else(|| {
        Error::Verification(format!(
            "SCT log ID {:?} not found in trusted root CT logs",
            hex::encode(log_id)
        ))
    })?;

    // Construct the DigitallySigned structure
    let digitally_signed = DigitallySigned::from_embedded_sct(&cert, &sct, issuer_key_hash)?;

    // Extract signature algorithm and signature bytes for verification
    // Convert the SignatureAndHashAlgorithm to u16
    let sig_alg_bytes = sct.signature.algorithm.tls_serialize().map_err(|e| {
        Error::Verification(format!("failed to serialize signature algorithm: {}", e))
    })?;
    let sig_alg = u16::from_be_bytes([sig_alg_bytes[0], sig_alg_bytes[1]]);
    let signature = sct.signature.signature.as_slice();

    // Verify the signature
    digitally_signed.verify(public_key, sig_alg, signature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_trust_root::TrustedRoot;

    // Certificate from sigstore-conformance happy-path bundle
    const VALID_CERT_BASE64: &str = "MIIIGTCCB5+gAwIBAgIUBPWs4OPN1kte0mUMGZrZ6ozMVRkwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjMwNzEyMTU1NjM1WhcNMjMwNzEyMTYwNjM1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVr33uVAPA1SpA5w/mmBF9ariW8E7oizIQKqiYfxwSb1zftqZZX045y3tPbRkIWe+t7MUYliQknQ954rDDEASnKOCBr4wgga6MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUx2TNZkruHC2aCdyIXscI8N/8q2owHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wgaUGA1UdEQEB/wSBmjCBl4aBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAfBgorBgEEAYO/MAECBBF3b3JrZmxvd19kaXNwYXRjaDA2BgorBgEEAYO/MAEDBChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MC0GCisGAQQBg78wAQQEH0V4dHJlbWVseSBkYW5nZXJvdXMgT0lEQyBiZWFjb24wSQYKKwYBBAGDvzABBQQ7c2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24wHQYKKwYBBAGDvzABBgQPcmVmcy9oZWFkcy9tYWluMDsGCisGAQQBg78wAQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTCBpgYKKwYBBAGDvzABCQSBlwyBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABCgQqDChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDBeBgorBgEEAYO/MAEMBFAMTmh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbjA4BgorBgEEAYO/MAENBCoMKGFmNzg1YjZkM2IwZmEwYzBhYTEzMDVmYWVlN2NlNjAzNmU4ZDkwYzQwHwYKKwYBBAGDvzABDgQRDA9yZWZzL2hlYWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk2MzI1OTY4OTcwNwYKKwYBBAGDvzABEAQpDCdodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UwGQYKKwYBBAGDvzABEQQLDAkxMzE4MDQ1NjMwgaYGCisGAQQBg78wARIEgZcMgZRodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24vLmdpdGh1Yi93b3JrZmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1vaWRjLWJlYWNvbi55bWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wARMEKgwoYWY3ODViNmQzYjBmYTBjMGFhMTMwNWZhZWU3Y2U2MDM2ZThkOTBjNDAhBgorBgEEAYO/MAEUBBMMEXdvcmtmbG93X2Rpc3BhdGNoMIGBBgorBgEEAYO/MAEVBHMMcWh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi9hY3Rpb25zL3J1bnMvNTUzMzc0MTQ5Ny9hdHRlbXB0cy8xMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGJStGTCwAABAMARzBFAiBCA4jZQP4CwMiWoeS7WMW46QkI4e7OsNH3yVhf5wdBvgIhAPJYxdsi9NqOXVZsEUtCup8m1m/2zG39FTGlgE0MorDFMAoGCCqGSM49BAMDA2gAMGUCMEYWRwI5QJeOwNCuV4tnZ0n5QNlUlP0BtX5V2ZTQLqcQbWtneC7tLptiYgr0Z62UDQIxAO6ItXAH+sbZcsbj08xr3GApM6hjvyTAl39pS3Y3sZwAz8lfQDHNL4eALEo1heAYVg==";

    // Trusted root with correct CT log key
    const VALID_TRUSTED_ROOT_JSON: &str = r#"{
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [],
        "certificateAuthorities": [
            {
              "subject": {"organization": "sigstore.dev", "commonName": "sigstore"},
              "uri": "https://fulcio.sigstore.dev",
              "certChain": {
                "certificates": [{
                    "rawBytes": "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="
                }]
              },
              "validFor": {"start": "2022-04-13T20:06:15.000Z"}
            }
        ],
        "ctlogs": [{
            "baseUrl": "https://ctfe.sigstore.dev/2022",
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==",
                "keyDetails": "PKIX_ECDSA_P256_SHA_256"
            },
            "logId": {"keyId": "3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4="}
        }],
        "timestampAuthorities": []
    }"#;

    // Test data with invalid CT key
    const INVALID_CT_KEY_TRUSTED_ROOT: &str =
        include_str!("../../test_data/invalid-ct-key_fail/trusted_root.json");
    const INVALID_CT_KEY_BUNDLE: &str =
        include_str!("../../test_data/invalid-ct-key_fail/bundle.sigstore.json");

    fn decode_cert(base64_cert: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(base64_cert)
            .expect("failed to decode cert")
    }

    fn get_issuer_spki(trusted_root: &TrustedRoot) -> Vec<u8> {
        let fulcio_certs = trusted_root.fulcio_certs().unwrap();
        let issuer_cert = Certificate::from_der(&fulcio_certs[0]).unwrap();
        issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap()
    }

    #[test]
    fn test_verify_sct_with_conformance_data() {
        let cert_der = decode_cert(VALID_CERT_BASE64);
        let trusted_root = TrustedRoot::from_json(VALID_TRUSTED_ROOT_JSON).unwrap();
        let issuer_spki = get_issuer_spki(&trusted_root);

        let result = verify_sct(&cert_der, &issuer_spki, &trusted_root);
        assert!(
            result.is_ok(),
            "SCT verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_sct_with_wrong_ct_key() {
        // The bundle has a valid SCT, but the trusted root has a different CT key
        // This should fail because the SCT signature won't verify with the wrong key
        let bundle: serde_json::Value =
            serde_json::from_str(INVALID_CT_KEY_BUNDLE).expect("parse bundle");

        // Extract cert from bundle
        let cert_chain = &bundle["verificationMaterial"]["x509CertificateChain"]["certificates"];
        let cert_base64 = cert_chain[0]["rawBytes"].as_str().unwrap();
        let cert_der = decode_cert(cert_base64);

        // Parse the invalid trusted root (has wrong CT key)
        let trusted_root =
            TrustedRoot::from_json(INVALID_CT_KEY_TRUSTED_ROOT).expect("parse trusted root");
        let issuer_spki = get_issuer_spki(&trusted_root);

        let result = verify_sct(&cert_der, &issuer_spki, &trusted_root);
        // This should fail - the SCT log ID from the cert won't match any CT log
        // in the trusted root that has a different key
        assert!(
            result.is_err(),
            "SCT verification should fail with wrong CT key"
        );
    }

    #[test]
    fn test_verify_sct_no_ct_logs() {
        let cert_der = decode_cert(VALID_CERT_BASE64);

        // Trusted root with no CT logs
        let trusted_root_json = r#"{
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [],
            "certificateAuthorities": [
                {
                  "subject": {"organization": "sigstore.dev", "commonName": "sigstore"},
                  "uri": "https://fulcio.sigstore.dev",
                  "certChain": {
                    "certificates": [{
                        "rawBytes": "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="
                    }]
                  },
                  "validFor": {"start": "2022-04-13T20:06:15.000Z"}
                }
            ],
            "ctlogs": [],
            "timestampAuthorities": []
        }"#;

        let trusted_root = TrustedRoot::from_json(trusted_root_json).unwrap();
        let issuer_spki = get_issuer_spki(&trusted_root);

        let result = verify_sct(&cert_der, &issuer_spki, &trusted_root);
        assert!(
            result.is_err(),
            "SCT verification should fail with no CT logs"
        );

        let err_msg = format!("{:?}", result.err());
        assert!(
            err_msg.contains("no CT log keys"),
            "Error should mention no CT log keys: {}",
            err_msg
        );
    }

    #[test]
    fn test_verify_sct_log_id_not_found() {
        let cert_der = decode_cert(VALID_CERT_BASE64);

        // Trusted root with CT log that has a DIFFERENT public key
        // The log ID is computed as SHA-256(public_key), so a different key = different log ID
        // This uses a bogus ECDSA P-256 public key that won't match the SCT's log ID
        let trusted_root_json = r#"{
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [],
            "certificateAuthorities": [
                {
                  "subject": {"organization": "sigstore.dev", "commonName": "sigstore"},
                  "uri": "https://fulcio.sigstore.dev",
                  "certChain": {
                    "certificates": [{
                        "rawBytes": "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="
                    }]
                  },
                  "validFor": {"start": "2022-04-13T20:06:15.000Z"}
                }
            ],
            "ctlogs": [{
                "baseUrl": "https://ctfe.sigstore.dev/2022",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVr33uVAPA1SpA5w/mmBF9ariW8E7oizIQKqiYfxwSb1zftqZZX045y3tPbRkIWe+t7MUYliQknQ954rDDEASnA==",
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                },
                "logId": {"keyId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
            }],
            "timestampAuthorities": []
        }"#;

        let trusted_root = TrustedRoot::from_json(trusted_root_json).unwrap();
        let issuer_spki = get_issuer_spki(&trusted_root);

        let result = verify_sct(&cert_der, &issuer_spki, &trusted_root);
        assert!(
            result.is_err(),
            "SCT verification should fail when log ID not found"
        );

        let err_msg = format!("{:?}", result.err());
        assert!(
            err_msg.contains("not found in trusted root"),
            "Error should mention log ID not found: {}",
            err_msg
        );
    }

    #[test]
    fn test_extract_sct_missing_extension() {
        // Use bogus-leaf.pem which doesn't have the SCT extension
        let bogus_leaf_pem = include_str!("../../test_data/x509/bogus-leaf.pem");
        let cert_der = sigstore_crypto::der_from_pem(bogus_leaf_pem).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();

        // Some dummy issuer SPKI
        let dummy_issuer_spki = vec![1, 2, 3, 4];

        let result = extract_sct(&cert, &dummy_issuer_spki);
        assert!(result.is_err(), "Should fail when SCT extension is missing");

        let err_msg = format!("{:?}", result.err());
        assert!(
            err_msg.contains("missing SCT extension"),
            "Error should mention missing SCT extension: {}",
            err_msg
        );
    }

    #[test]
    fn test_signature_algorithm_mapping() {
        // Test that we correctly map TLS signature algorithms
        assert_eq!(ECDSA_SHA256, 0x0403);
        assert_eq!(ECDSA_SHA384, 0x0503);
        assert_eq!(RSA_PKCS1_SHA256, 0x0401);
        assert_eq!(RSA_PKCS1_SHA384, 0x0501);
        assert_eq!(RSA_PKCS1_SHA512, 0x0601);
    }
}
