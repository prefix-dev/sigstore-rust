//! Dead Simple Signing Envelope (DSSE) types
//!
//! DSSE is a signature envelope format used for signing arbitrary payloads.
//! Specification: https://github.com/secure-systems-lab/dsse

use crate::encoding::{KeyId, PayloadBytes, SignatureBytes};
use serde::{Deserialize, Serialize};

/// A DSSE envelope containing a signed payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// Type URI of the payload
    pub payload_type: String,
    /// Payload bytes
    pub payload: PayloadBytes,
    /// Signatures over the PAE (Pre-Authentication Encoding)
    pub signatures: Vec<DsseSignature>,
}

/// A signature in a DSSE envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    /// Signature bytes
    pub sig: SignatureBytes,
    /// Key ID (optional hint for key lookup)
    #[serde(default)]
    pub keyid: KeyId,
}

impl DsseEnvelope {
    /// Create a new DSSE envelope
    pub fn new(
        payload_type: String,
        payload: PayloadBytes,
        signatures: Vec<DsseSignature>,
    ) -> Self {
        Self {
            payload_type,
            payload,
            signatures,
        }
    }

    /// Get the Pre-Authentication Encoding (PAE) string
    ///
    /// PAE is the string that gets signed in DSSE:
    /// `DSSEv1 <payload_type_len> <payload_type> <payload_len> <payload>`
    pub fn pae(&self) -> Vec<u8> {
        pae(&self.payload_type, self.payload.as_bytes())
    }

    /// Decode the payload bytes
    pub fn decode_payload(&self) -> Vec<u8> {
        self.payload.as_bytes().to_vec()
    }
}

/// Compute the Pre-Authentication Encoding (PAE)
///
/// Format: `DSSEv1 <len(type)> <type> <len(body)> <body>`
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // "DSSEv1" + space
    result.extend_from_slice(b"DSSEv1 ");

    // payload_type length + space
    result.extend_from_slice(format!("{} ", payload_type.len()).as_bytes());

    // payload_type + space
    result.extend_from_slice(payload_type.as_bytes());
    result.push(b' ');

    // payload length + space
    result.extend_from_slice(format!("{} ", payload.len()).as_bytes());

    // payload
    result.extend_from_slice(payload);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pae() {
        // Test vector from DSSE spec
        let pae_result = pae("application/example", b"hello world");
        let expected = b"DSSEv1 19 application/example 11 hello world";
        assert_eq!(pae_result, expected);
    }

    #[test]
    fn test_dsse_envelope_serde() {
        let envelope = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: PayloadBytes::from_bytes(b"{\"_type\":\"https://in-toto.io/Statement/v1\"}"),
            signatures: vec![DsseSignature {
                sig: SignatureBytes::from_bytes(b"\x30\x44\x02\x20"),
                keyid: KeyId::default(),
            }],
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: DsseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, parsed);
    }

    #[test]
    fn test_dsse_envelope_keyid_preservation() {
        // Test that empty string keyid is preserved during round-trip
        let json_with_empty_keyid = r#"{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[{"sig":"c2ln","keyid":""}]}"#;

        let envelope: DsseEnvelope = serde_json::from_str(json_with_empty_keyid).unwrap();
        assert_eq!(envelope.signatures[0].keyid, KeyId::default());

        let reserialized = serde_json::to_string(&envelope).unwrap();
        assert!(
            reserialized.contains(r#""keyid":"""#),
            "Empty keyid should be included in output"
        );

        // Test with non-empty keyid
        let json_with_keyid = r#"{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[{"sig":"c2ln","keyid":"test-key"}]}"#;
        let envelope_with_keyid: DsseEnvelope = serde_json::from_str(json_with_keyid).unwrap();
        let json_out = serde_json::to_string(&envelope_with_keyid).unwrap();
        assert!(
            json_out.contains(r#""keyid":"test-key""#),
            "Non-empty keyid should be included in output"
        );
    }
}
