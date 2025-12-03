//! Encoding helpers and concrete types for sigstore
//!
//! This module provides concrete types with semantic meaning that handle
//! encoding/decoding internally. Each type represents a specific kind of data
//! and serializes appropriately (usually as base64).
//!
//! The design philosophy is:
//! - Use concrete newtype wrappers with semantic meaning
//! - Types handle their own encoding/decoding via serde
//! - Clear type names prevent mixing up different kinds of data

use crate::error::{Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

// ============================================================================
// Serde helper modules (for use with raw Vec<u8> when needed)
// ============================================================================

/// Serde helper for base64 encoding/decoding of byte arrays
///
/// Use this with `#[serde(with = "base64_bytes")]` on `Vec<u8>` fields.
pub mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for optional base64 encoding/decoding
pub mod base64_bytes_option {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&STANDARD.encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => STANDARD
                .decode(s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Serde helper for hex encoding/decoding of byte arrays
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for i64 fields serialized as strings
///
/// JSON bundles use strings for large integers. This helper serializes
/// i64 values as strings and parses them back.
pub mod string_i64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<i64>()
            .map_err(|_| serde::de::Error::custom(format!("invalid integer: {}", s)))
    }
}

// ============================================================================
// Macro for creating base64-encoded newtype wrappers
// ============================================================================

macro_rules! base64_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Create from raw bytes
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            /// Create from a byte slice
            pub fn from_bytes(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }

            /// Create from base64-encoded string
            pub fn from_base64(s: &str) -> Result<Self> {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {}", e)))?;
                Ok(Self(bytes))
            }

            /// Encode as base64 string
            pub fn to_base64(&self) -> String {
                base64::engine::general_purpose::STANDARD.encode(&self.0)
            }

            /// Get the raw bytes
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Consume and return the inner bytes
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }

            /// Get the length in bytes
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Check if empty
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8]> for $name {
            fn from(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.to_base64())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.to_base64())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::from_base64(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

// ============================================================================
// Concrete Types for Different Kinds of Binary Data
// ============================================================================

base64_newtype!(
    /// DER-encoded X.509 certificate bytes
    ///
    /// This type represents a certificate in DER format (binary ASN.1).
    /// Serializes as base64 in JSON.
    ///
    /// # Example
    /// ```
    /// use sigstore_types::DerCertificate;
    ///
    /// // Parse from PEM (validates CERTIFICATE header)
    /// let pem = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----";
    /// let cert = DerCertificate::from_pem(pem).unwrap();
    ///
    /// // Convert back to PEM
    /// let pem_out = cert.to_pem();
    /// ```
    DerCertificate
);

impl DerCertificate {
    /// Parse from PEM-encoded certificate string.
    ///
    /// Validates that the PEM block has a `CERTIFICATE` header.
    /// Returns an error if the PEM is invalid or has the wrong type.
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let parsed = pem::parse(pem_str)
            .map_err(|e| Error::InvalidEncoding(format!("failed to parse PEM: {}", e)))?;

        if parsed.tag() != "CERTIFICATE" {
            return Err(Error::InvalidEncoding(format!(
                "expected CERTIFICATE PEM block, got {}",
                parsed.tag()
            )));
        }

        Ok(Self::new(parsed.contents().to_vec()))
    }

    /// Encode as PEM string with CERTIFICATE header.
    pub fn to_pem(&self) -> String {
        let pem_block = pem::Pem::new("CERTIFICATE", self.as_bytes());
        pem::encode(&pem_block)
    }
}

base64_newtype!(
    /// DER-encoded public key bytes (SubjectPublicKeyInfo format)
    ///
    /// This type represents a public key in DER format.
    /// Serializes as base64 in JSON.
    ///
    /// # Example
    /// ```
    /// use sigstore_types::DerPublicKey;
    ///
    /// // Parse from PEM (validates PUBLIC KEY header)
    /// let pem = "-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----";
    /// let key = DerPublicKey::from_pem(pem).unwrap();
    ///
    /// // Convert back to PEM
    /// let pem_out = key.to_pem();
    /// ```
    DerPublicKey
);

impl DerPublicKey {
    /// Parse from PEM-encoded public key string.
    ///
    /// Validates that the PEM block has a `PUBLIC KEY` header.
    /// Returns an error if the PEM is invalid or has the wrong type.
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let parsed = pem::parse(pem_str)
            .map_err(|e| Error::InvalidEncoding(format!("failed to parse PEM: {}", e)))?;

        if parsed.tag() != "PUBLIC KEY" {
            return Err(Error::InvalidEncoding(format!(
                "expected PUBLIC KEY PEM block, got {}",
                parsed.tag()
            )));
        }

        Ok(Self::new(parsed.contents().to_vec()))
    }

    /// Encode as PEM string with PUBLIC KEY header.
    pub fn to_pem(&self) -> String {
        let pem_block = pem::Pem::new("PUBLIC KEY", self.as_bytes());
        pem::encode(&pem_block)
    }
}

base64_newtype!(
    /// Cryptographic signature bytes
    ///
    /// This type represents raw signature bytes (format depends on algorithm).
    /// Serializes as base64 in JSON.
    SignatureBytes
);

base64_newtype!(
    /// DSSE payload bytes
    ///
    /// This type represents the payload content of a DSSE envelope.
    /// Serializes as base64 in JSON.
    PayloadBytes
);

base64_newtype!(
    /// Canonicalized Rekor entry body
    ///
    /// This type represents the canonicalized JSON body of a Rekor log entry.
    /// Serializes as base64 in JSON.
    CanonicalizedBody
);

base64_newtype!(
    /// Signed Entry Timestamp (SET) bytes
    ///
    /// This type represents a signed timestamp from the transparency log.
    /// Serializes as base64 in JSON.
    SignedTimestamp
);

base64_newtype!(
    /// RFC 3161 timestamp token bytes
    ///
    /// This type represents a DER-encoded RFC 3161 timestamp response.
    /// Serializes as base64 in JSON.
    TimestampToken
);

base64_newtype!(
    /// PEM-encoded content (double-encoded in base64)
    ///
    /// This type represents PEM text that gets base64-encoded for JSON.
    /// Used when APIs expect base64-encoded PEM strings.
    PemContent
);

// ============================================================================
// Identifier Types (String Wrappers for Semantic Clarity)
// ============================================================================

/// UUID for a Rekor log entry
///
/// This is the unique identifier for an entry in the transparency log.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryUuid(String);

impl EntryUuid {
    pub fn new(s: String) -> Self {
        EntryUuid(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for EntryUuid {
    fn from(s: String) -> Self {
        EntryUuid::new(s)
    }
}

impl AsRef<str> for EntryUuid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntryUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Transparency log index
///
/// Represents a log index in the transparency log. Per the protobuf spec,
/// this is an int64. For JSON serialization, we serialize as an integer but
/// accept both integers and strings for backwards compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogIndex(i64);

impl LogIndex {
    pub fn new(index: i64) -> Self {
        LogIndex(index)
    }

    pub fn value(&self) -> i64 {
        self.0
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.0 >= 0 {
            Some(self.0 as u64)
        } else {
            None
        }
    }
}

impl From<i64> for LogIndex {
    fn from(index: i64) -> Self {
        LogIndex::new(index)
    }
}

impl From<u64> for LogIndex {
    fn from(index: u64) -> Self {
        LogIndex::new(index as i64)
    }
}

impl std::fmt::Display for LogIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for LogIndex {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as string to match existing bundle format
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for LogIndex {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct LogIndexVisitor;

        impl<'de> Visitor<'de> for LogIndexVisitor {
            type Value = LogIndex;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer or string representing a log index")
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<LogIndex, E>
            where
                E: de::Error,
            {
                Ok(LogIndex::new(value))
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<LogIndex, E>
            where
                E: de::Error,
            {
                Ok(LogIndex::new(value as i64))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<LogIndex, E>
            where
                E: de::Error,
            {
                value
                    .parse::<i64>()
                    .map(LogIndex::new)
                    .map_err(|_| de::Error::custom(format!("invalid log index: {}", value)))
            }
        }

        deserializer.deserialize_any(LogIndexVisitor)
    }
}

/// Transparency log key ID
///
/// Base64-encoded identifier for a transparency log (typically SHA-256 of public key).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogKeyId(String);

impl LogKeyId {
    pub fn new(s: String) -> Self {
        LogKeyId(s)
    }

    /// Create from raw bytes (will be base64-encoded)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        LogKeyId(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// Decode to raw bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.0)
            .map_err(|e| Error::InvalidEncoding(format!("invalid base64 in log key id: {}", e)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for LogKeyId {
    fn from(s: String) -> Self {
        LogKeyId::new(s)
    }
}

impl AsRef<str> for LogKeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LogKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key ID for signature key identification
///
/// Optional hint used in DSSE to identify which key was used for signing.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(s: String) -> Self {
        KeyId(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        KeyId::new(s)
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================
// Key Hint Type (Fixed 4-byte Size)
// ============================================================================

/// Key hint for checkpoint signature identification (4 bytes)
///
/// The key hint is the first 4 bytes of SHA-256(public_key_der).
/// It is used in signed notes/checkpoints to match signatures to public keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyHint(#[serde(with = "base64_bytes_array4")] [u8; 4]);

impl KeyHint {
    /// Create a new key hint from a 4-byte array
    pub fn new(bytes: [u8; 4]) -> Self {
        KeyHint(bytes)
    }

    /// Create from a slice (must be exactly 4 bytes)
    pub fn try_from_slice(slice: &[u8]) -> crate::error::Result<Self> {
        if slice.len() != 4 {
            return Err(crate::error::Error::Validation(format!(
                "key hint must be exactly 4 bytes, got {}",
                slice.len()
            )));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(slice);
        Ok(KeyHint(arr))
    }

    /// Get the key hint as a byte slice
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Get the key hint as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 4]> for KeyHint {
    fn from(bytes: [u8; 4]) -> Self {
        KeyHint::new(bytes)
    }
}

impl AsRef<[u8]> for KeyHint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Serde helper for base64-encoded 4-byte arrays
mod base64_bytes_array4 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(&s)
            .map_err(|e| serde::de::Error::custom(format!("invalid base64: {}", e)))?;
        if bytes.len() != 4 {
            return Err(serde::de::Error::custom(format!(
                "expected 4 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ============================================================================
// SHA-256 Hash Type (Fixed Size)
// ============================================================================

/// SHA-256 hash digest (32 bytes)
///
/// Fixed-size hash with compile-time size guarantees.
/// Serializes as base64, deserializes from either hex (64 chars) or base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Sha256Hash(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidEncoding(format!(
                "SHA-256 hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Sha256Hash(arr))
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))?;
        Self::try_from_slice(&bytes)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {}", e)))?;
        Self::try_from_slice(&bytes)
    }

    /// Parse from hex or base64 string (auto-detect format)
    pub fn from_hex_or_base64(s: &str) -> Result<Self> {
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Self::from_hex(s);
        }
        Self::from_base64(s)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Sha256Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Sha256Hash(bytes)
    }
}

impl serde::Serialize for Sha256Hash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Hash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Sha256Hash::from_hex_or_base64(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// Hex-Encoded Log ID (for Rekor V1 API compatibility)
// ============================================================================

/// Hex-encoded transparency log ID
///
/// The Rekor V1 API returns log IDs as hex-encoded strings.
/// This type handles the hex encoding and can convert to base64 for bundles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexLogId(String);

impl HexLogId {
    pub fn new(s: String) -> Self {
        HexLogId(s)
    }

    /// Create from raw bytes (will be hex-encoded)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        HexLogId(hex::encode(bytes))
    }

    /// Decode to raw bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        hex::decode(&self.0).map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))
    }

    /// Convert to base64 encoding (for bundle format)
    pub fn to_base64(&self) -> Result<String> {
        let bytes = self.decode()?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for HexLogId {
    fn from(s: String) -> Self {
        HexLogId::new(s)
    }
}

impl AsRef<str> for HexLogId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HexLogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================
// Hex-Encoded Hash (for Rekor V1 API)
// ============================================================================

/// Hex-encoded hash value
///
/// Used in Rekor V1 API responses where hashes are hex-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexHash(String);

impl HexHash {
    pub fn new(s: String) -> Self {
        HexHash(s)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        HexHash(hex::encode(bytes))
    }

    pub fn decode(&self) -> Result<Vec<u8>> {
        hex::decode(&self.0).map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Convert to Sha256Hash (validates length)
    pub fn to_sha256(&self) -> Result<Sha256Hash> {
        Sha256Hash::from_hex(&self.0)
    }
}

impl From<String> for HexHash {
    fn from(s: String) -> Self {
        HexHash::new(s)
    }
}

impl AsRef<str> for HexHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HexHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_certificate_roundtrip() {
        let cert = DerCertificate::from_bytes(b"fake cert data");
        let json = serde_json::to_string(&cert).unwrap();
        let decoded: DerCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, decoded);
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let sig = SignatureBytes::from_bytes(b"fake signature");
        let json = serde_json::to_string(&sig).unwrap();
        let decoded: SignatureBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn test_sha256_hash() {
        let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash = Sha256Hash::from_hex(hash_hex).unwrap();
        assert_eq!(hash.to_hex(), hash_hex);

        // Can also deserialize from hex
        let json_hex = format!("\"{}\"", hash_hex);
        let from_hex: Sha256Hash = serde_json::from_str(&json_hex).unwrap();
        assert_eq!(hash, from_hex);
    }

    #[test]
    fn test_hex_log_id() {
        let bytes = vec![1, 2, 3, 4];
        let log_id = HexLogId::from_bytes(&bytes);
        assert_eq!(log_id.as_str(), "01020304");
        assert_eq!(log_id.decode().unwrap(), bytes);
        assert_eq!(log_id.to_base64().unwrap(), "AQIDBA==");
    }

    #[test]
    fn test_log_key_id() {
        let bytes = vec![1, 2, 3, 4];
        let key_id = LogKeyId::from_bytes(&bytes);
        assert_eq!(key_id.decode().unwrap(), bytes);
    }

    #[test]
    fn test_certificate_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----";
        let cert = DerCertificate::from_pem(pem).unwrap();
        assert_eq!(cert.as_bytes(), b"abcd");
    }

    #[test]
    fn test_certificate_from_pem_wrong_type() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----";
        let result = DerCertificate::from_pem(pem);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected CERTIFICATE"));
    }

    #[test]
    fn test_certificate_to_pem() {
        let cert = DerCertificate::from_bytes(b"abcd");
        let pem = cert.to_pem();
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));

        // Round-trip
        let cert2 = DerCertificate::from_pem(&pem).unwrap();
        assert_eq!(cert, cert2);
    }

    #[test]
    fn test_public_key_from_pem() {
        let pem = "-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----";
        let key = DerPublicKey::from_pem(pem).unwrap();
        assert_eq!(key.as_bytes(), b"abcd");
    }

    #[test]
    fn test_public_key_from_pem_wrong_type() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----";
        let result = DerPublicKey::from_pem(pem);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected PUBLIC KEY"));
    }

    #[test]
    fn test_public_key_to_pem() {
        let key = DerPublicKey::from_bytes(b"abcd");
        let pem = key.to_pem();
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));

        // Round-trip
        let key2 = DerPublicKey::from_pem(&pem).unwrap();
        assert_eq!(key, key2);
    }
}
