//! ASN.1 types for RFC 3161 Time-Stamp Protocol
//!
//! This module defines the ASN.1 structures used in the Time-Stamp Protocol
//! as specified in RFC 3161.

use const_oid::ObjectIdentifier;
use der::{
    asn1::{BitString, GeneralizedTime, Int, OctetString},
    Decode, Encode, Sequence,
};
use rand::Rng;
use x509_cert::{ext::pkix::name::GeneralName, ext::Extensions};

/// OID for SHA-256: 2.16.840.1.101.3.4.2.1
pub const OID_SHA256: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_256;

/// OID for SHA-384: 2.16.840.1.101.3.4.2.2
pub const OID_SHA384: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_384;

/// OID for SHA-512: 2.16.840.1.101.3.4.2.3
pub const OID_SHA512: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_512;

/// OID for id-ct-TSTInfo: 1.2.840.113549.1.9.16.1.4
pub const OID_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Generates a random nonce suitable for RFC 3161 timestamp requests.
///
/// The nonce is generated as 8 random bytes and encoded as a positive INTEGER
/// according to DER rules:
/// - If the high bit is clear (0x00-0x7F), no padding is needed
/// - If the high bit is set (0x80-0xFF), prepend 0x00 to indicate positive
///
/// This ensures the nonce is always interpreted as a positive integer,
/// which is required by RFC 3161.
///
/// # Returns
///
/// A `Vec<u8>` containing 8-9 bytes suitable for passing to `Int::new()`.
pub fn generate_positive_nonce_bytes() -> Vec<u8> {
    let mut rng = rand::rng();
    let nonce_random: [u8; 8] = rng.random();

    // Only prepend 0x00 if the high bit is set (to avoid negative number)
    if nonce_random[0] & 0x80 != 0 {
        // High bit set, need 0x00 padding to indicate positive
        let mut padded = vec![0x00];
        padded.extend_from_slice(&nonce_random);
        padded
    } else {
        // High bit clear, no padding needed
        nonce_random.to_vec()
    }
}

/// Algorithm identifier with optional parameters
// TODO: use HashAlgorithm enum?
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID
    pub algorithm: ObjectIdentifier,
    /// Optional parameters (usually NULL for hash algorithms)
    #[asn1(optional = "true")]
    pub parameters: Option<der::Any>,
}

impl AlgorithmIdentifier {
    /// Create a SHA-256 algorithm identifier
    pub fn sha256() -> Self {
        Self {
            algorithm: OID_SHA256,
            parameters: None,
        }
    }

    /// Create a SHA-384 algorithm identifier
    pub fn sha384() -> Self {
        Self {
            algorithm: OID_SHA384,
            parameters: None,
        }
    }

    /// Create a SHA-512 algorithm identifier
    pub fn sha512() -> Self {
        Self {
            algorithm: OID_SHA512,
            parameters: None,
        }
    }
}

/// Message imprint containing hash algorithm and hashed message
/// RFC 3161 Section 2.4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    /// Hash algorithm used
    pub hash_algorithm: AlgorithmIdentifier,
    /// Hashed message
    pub hashed_message: OctetString,
}

impl MessageImprint {
    /// Create a new message imprint
    pub fn new(algorithm: AlgorithmIdentifier, digest: Vec<u8>) -> Self {
        Self {
            hash_algorithm: algorithm,
            hashed_message: OctetString::new(digest).expect("valid octet string"),
        }
    }
}

/// Time-stamp request
/// RFC 3161 Section 2.4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampReq {
    /// Version (must be 1)
    pub version: u8,
    /// Message imprint to be timestamped
    pub message_imprint: MessageImprint,
    /// Optional policy OID
    #[asn1(optional = "true")]
    pub req_policy: Option<ObjectIdentifier>,
    /// Optional nonce
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    /// Whether to include certificates in response
    #[asn1(default = "default_false")]
    pub cert_req: bool,
    // Extensions omitted for simplicity
}

fn default_false() -> bool {
    false
}

impl TimeStampReq {
    /// Create a new timestamp request with an automatically generated nonce
    pub fn new(message_imprint: MessageImprint) -> Self {
        // Generate a random nonce for replay protection
        let nonce_bytes = generate_positive_nonce_bytes();
        let nonce = Int::new(&nonce_bytes).expect("valid nonce");

        Self {
            version: 1,
            message_imprint,
            req_policy: None,
            nonce: Some(nonce),
            cert_req: true,
        }
    }

    /// Create a new timestamp request without a nonce (not recommended)
    pub fn new_without_nonce(message_imprint: MessageImprint) -> Self {
        Self {
            version: 1,
            message_imprint,
            req_policy: None,
            nonce: None,
            cert_req: true,
        }
    }

    /// Set the nonce manually (overrides auto-generated nonce)
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(Int::new(&nonce).expect("valid integer"));
        self
    }

    /// Set whether to request certificates
    pub fn with_cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = cert_req;
        self
    }

    /// Encode to DER
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        Encode::to_der(self)
    }
}

/// PKI status values
/// RFC 3161 Section 2.4.2
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PkiStatus {
    /// Granted
    Granted = 0,
    /// Granted with modifications
    GrantedWithMods = 1,
    /// Rejection
    Rejection = 2,
    /// Waiting
    Waiting = 3,
    /// Revocation warning
    RevocationWarning = 4,
    /// Revocation notification
    RevocationNotification = 5,
}

impl TryFrom<u8> for PkiStatus {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PkiStatus::Granted),
            1 => Ok(PkiStatus::GrantedWithMods),
            2 => Ok(PkiStatus::Rejection),
            3 => Ok(PkiStatus::Waiting),
            4 => Ok(PkiStatus::RevocationWarning),
            5 => Ok(PkiStatus::RevocationNotification),
            _ => Err(()),
        }
    }
}

/// PKI status info
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PkiStatusInfo {
    /// Status value
    pub status: u8,
    /// Optional failure info
    #[asn1(optional = "true")]
    pub fail_info: Option<BitString>,
}

impl PkiStatusInfo {
    /// Check if the status indicates success
    pub fn is_success(&self) -> bool {
        self.status == PkiStatus::Granted as u8 || self.status == PkiStatus::GrantedWithMods as u8
    }

    /// Get the status as an enum
    pub fn status_enum(&self) -> Option<PkiStatus> {
        PkiStatus::try_from(self.status).ok()
    }
}

/// Accuracy of the timestamp
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    /// Seconds
    #[asn1(optional = "true")]
    pub seconds: Option<u64>,
    /// Milliseconds (1-999)
    #[asn1(context_specific = "0", optional = "true")]
    pub millis: Option<u16>,
    /// Microseconds (1-999)
    #[asn1(context_specific = "1", optional = "true")]
    pub micros: Option<u16>,
}

/// TSTInfo - the actual timestamp token info
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    /// Version (must be 1)
    pub version: u8,
    /// Policy OID
    pub policy: ObjectIdentifier,
    /// Message imprint
    pub message_imprint: MessageImprint,
    /// Serial number
    pub serial_number: Int,
    /// Generation time
    pub gen_time: GeneralizedTime,
    /// Accuracy
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    /// Ordering
    #[asn1(default = "default_false")]
    pub ordering: bool,
    /// Nonce
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    /// TSA name
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub tsa: Option<GeneralName>,
    /// Extensions
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub extensions: Option<Extensions>,
}

impl TstInfo {
    /// Decode from DER bytes
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::from_der(bytes)
    }
}

/// Time-stamp response
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp {
    /// Status information
    pub status: PkiStatusInfo,
    /// Time-stamp token (CMS ContentInfo)
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<der::Any>,
}

impl TimeStampResp {
    /// Decode from DER bytes
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::from_der(bytes)
    }

    /// Check if the response indicates success
    pub fn is_success(&self) -> bool {
        self.status.is_success() && self.time_stamp_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_imprint_encode() {
        let digest = vec![0u8; 32]; // SHA-256 produces 32 bytes
        let imprint = MessageImprint::new(AlgorithmIdentifier::sha256(), digest);
        let der = Encode::to_der(&imprint).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_timestamp_req_encode() {
        let digest = vec![0u8; 32];
        let imprint = MessageImprint::new(AlgorithmIdentifier::sha256(), digest);
        let req = TimeStampReq::new(imprint);
        let der = req.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_timestamp_req_has_nonce() {
        let digest = vec![0u8; 32];
        let imprint = MessageImprint::new(AlgorithmIdentifier::sha256(), digest);
        let req = TimeStampReq::new(imprint);

        // Verify that the request has a nonce
        assert!(
            req.nonce.is_some(),
            "Nonce should be automatically generated"
        );
    }

    #[test]
    fn test_generate_positive_nonce_bytes() {
        // Generate multiple nonces to test both paths (high bit set and clear)
        for _ in 0..100 {
            let nonce_bytes = generate_positive_nonce_bytes();

            // Nonce should be 8 or 9 bytes
            assert!(
                nonce_bytes.len() == 8 || nonce_bytes.len() == 9,
                "Nonce length should be 8 or 9 bytes, got {}",
                nonce_bytes.len()
            );

            // If 9 bytes, first byte should be 0x00 and second byte should have high bit set
            if nonce_bytes.len() == 9 {
                assert_eq!(nonce_bytes[0], 0x00, "9-byte nonce should start with 0x00");
                assert!(
                    nonce_bytes[1] & 0x80 != 0,
                    "9-byte nonce should have high bit set in second byte"
                );
            } else {
                // If 8 bytes, first byte should not have high bit set
                assert!(
                    nonce_bytes[0] & 0x80 == 0,
                    "8-byte nonce should not have high bit set in first byte"
                );
            }

            // Verify it can be converted to Int
            let int_result = Int::new(&nonce_bytes);
            assert!(
                int_result.is_ok(),
                "Nonce bytes should be valid for Int::new()"
            );
        }
    }

    #[test]
    fn test_pki_status() {
        assert!(PkiStatus::try_from(0).is_ok());
        assert!(PkiStatus::try_from(5).is_ok());
        assert!(PkiStatus::try_from(6).is_err());
    }
}
