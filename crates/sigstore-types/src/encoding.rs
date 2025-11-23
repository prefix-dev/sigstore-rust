//! Type-safe encoding wrappers
//!
//! This module provides newtype wrappers around encoded data to prevent
//! encoding confusion and provide compile-time safety.
//!
//! The Base64 type uses phantom types to track what content it contains,
//! preventing mixing up certificates with signatures at compile time.

use crate::error::{Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

// ============================================================================
// Phantom type markers for Base64 content
// ============================================================================

/// Marker: DER-encoded certificate or key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Der;

/// Marker: Cryptographic signature bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature;

/// Marker: DSSE payload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Payload;

/// Marker: Hash digest
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash;

/// Marker: PEM text (base64-encoded PEM, double-encoded)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pem;

/// Marker: Canonicalized Rekor entry body
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Body;

/// Marker: Signed entry timestamp
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timestamp;

/// Marker: Unknown or unspecified content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unknown;

// ============================================================================
// Type-safe Base64 wrapper with phantom type
// ============================================================================

/// Base64-encoded data with compile-time content tracking
///
/// This type uses phantom types to track what the base64 encoding contains.
/// This prevents accidentally mixing up different types of encoded data.
///
/// # Examples
///
/// ```ignore
/// let cert: Base64<Der> = Base64::encode(cert_der_bytes);
/// let sig: Base64<Signature> = Base64::encode(signature_bytes);
///
/// // ✅ This compiles - same type
/// if cert == cert { }
///
/// // ❌ This doesn't compile - different types!
/// // if cert == sig { }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Base64<T = Unknown> {
    inner: String,
    #[serde(skip)]
    _phantom: PhantomData<T>,
}

impl<T> Base64<T> {
    /// Create a new Base64 wrapper from a string
    ///
    /// Note: This does not validate the base64 encoding.
    /// Use `decode()` to validate and extract bytes.
    pub fn new(s: String) -> Self {
        Base64 {
            inner: s,
            _phantom: PhantomData,
        }
    }

    /// Create a Base64 wrapper from raw bytes
    pub fn encode(bytes: &[u8]) -> Self {
        Base64 {
            inner: base64::engine::general_purpose::STANDARD.encode(bytes),
            _phantom: PhantomData,
        }
    }

    /// Decode the base64 string to bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.inner)
            .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {}", e)))
    }

    /// Get the underlying string slice
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Convert into the underlying String
    pub fn into_string(self) -> String {
        self.inner
    }

    /// Cast to a different content type (use with caution!)
    ///
    /// This is useful when you need to change the phantom type marker.
    /// The encoding itself is not changed, only the type marker.
    pub fn cast<U>(self) -> Base64<U> {
        Base64 {
            inner: self.inner,
            _phantom: PhantomData,
        }
    }
}

impl<T> From<String> for Base64<T> {
    fn from(s: String) -> Self {
        Base64::new(s)
    }
}

impl<T> AsRef<str> for Base64<T> {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl<T> AsRef<[u8]> for Base64<T> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl<T> std::fmt::Display for Base64<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

// PartialEq implementations
impl<T> PartialEq for Base64<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T> Eq for Base64<T> {}

impl<T> std::hash::Hash for Base64<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<T> PartialEq<str> for Base64<T> {
    fn eq(&self, other: &str) -> bool {
        self.inner == other
    }
}

impl<T> PartialEq<String> for Base64<T> {
    fn eq(&self, other: &String) -> bool {
        &self.inner == other
    }
}

impl<T> PartialEq<Base64<T>> for String {
    fn eq(&self, other: &Base64<T>) -> bool {
        self == &other.inner
    }
}

impl<T> PartialEq<Base64<T>> for &str {
    fn eq(&self, other: &Base64<T>) -> bool {
        *self == other.inner
    }
}

/// Hex-encoded data
///
/// This type represents data that is hex-encoded (lowercase).
/// It provides safe conversion to/from raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hex(String);

impl Hex {
    /// Create a new Hex wrapper from a string
    ///
    /// Note: This does not validate the hex encoding.
    /// Use `decode()` to validate and extract bytes.
    pub fn new(s: String) -> Self {
        Hex(s)
    }

    /// Create a Hex wrapper from raw bytes
    pub fn encode(bytes: &[u8]) -> Self {
        Hex(hex::encode(bytes))
    }

    /// Decode the hex string to bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        hex::decode(&self.0).map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))
    }

    /// Get the underlying string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the underlying String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for Hex {
    fn from(s: String) -> Self {
        Hex(s)
    }
}

impl AsRef<str> for Hex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ============================================================================
// Identifier Types
// ============================================================================

/// Transparency log index (numeric string)
///
/// This type represents a log index in the transparency log.
/// While stored as a string in JSON, it represents a numeric position.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogIndex(String);

impl LogIndex {
    /// Create a new LogIndex from a string
    pub fn new(s: String) -> Self {
        LogIndex(s)
    }

    /// Create a LogIndex from a u64
    pub fn from_u64(index: u64) -> Self {
        LogIndex(index.to_string())
    }

    /// Get the underlying string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the underlying String
    pub fn into_string(self) -> String {
        self.0
    }

    /// Parse as u64
    pub fn as_u64(&self) -> Result<u64> {
        self.0
            .parse()
            .map_err(|e| Error::InvalidEncoding(format!("invalid log index '{}': {}", self.0, e)))
    }
}

impl From<String> for LogIndex {
    fn from(s: String) -> Self {
        LogIndex::new(s)
    }
}

impl From<u64> for LogIndex {
    fn from(index: u64) -> Self {
        LogIndex::from_u64(index)
    }
}

impl AsRef<str> for LogIndex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LogIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Transparency log key ID (identifies a specific log)
///
/// This is typically a hash or other identifier for the transparency log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogKeyId(String);

impl LogKeyId {
    /// Create a new LogKeyId from a string
    pub fn new(s: String) -> Self {
        LogKeyId(s)
    }

    /// Get the underlying string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the underlying String
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

/// Key ID (for signature key identification)
///
/// This is an optional hint used in DSSE and other signature formats
/// to help identify which key was used for signing.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new KeyId from a string
    pub fn new(s: String) -> Self {
        KeyId(s)
    }

    /// Get the underlying string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the underlying String
    pub fn into_string(self) -> String {
        self.0
    }

    /// Check if the KeyId is empty
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

/// SHA-256 hash digest (32 bytes)
///
/// This type represents a SHA-256 hash with compile-time size guarantees.
/// It can be constructed from hex or base64 strings and converted back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Sha256Hash(bytes)
    }

    /// Try to create from a byte slice
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

    /// Parse from hex-encoded string
    pub fn from_hex(hex: &Hex) -> Result<Self> {
        let bytes = hex::decode(hex.as_str())
            .map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))?;
        Self::try_from_slice(&bytes)
    }

    /// Parse from base64-encoded string
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {}", e)))?;
        Self::try_from_slice(&bytes)
    }

    /// Parse from hex or base64 string (auto-detect format)
    ///
    /// Tries hex first (if length is 64 chars), then falls back to base64.
    /// This handles compatibility with different sigstore implementations.
    pub fn from_hex_or_base64(s: &str) -> Result<Self> {
        // Try hex if it looks like a hex string (64 chars, all hex digits)
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Self::from_hex(&Hex(s.to_string()));
        }
        // Otherwise try base64
        Self::from_base64(s)
    }

    /// Encode as hex string (lowercase)
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Encode as base64 string
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Decode from a Base64Hash wrapper
    ///
    /// Auto-detects hex vs base64 format for compatibility
    pub fn from_base64_ref(b64: &Base64Hash) -> Result<Self> {
        Self::from_hex_or_base64(b64.as_str())
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
        // Auto-detect hex or base64 format for compatibility
        Sha256Hash::from_hex_or_base64(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// Type aliases for common Base64 content types
// ============================================================================

/// Base64-encoded DER certificate or key
pub type Base64Der = Base64<Der>;

/// Base64-encoded cryptographic signature
pub type Base64Signature = Base64<Signature>;

/// Base64-encoded DSSE payload
pub type Base64Payload = Base64<Payload>;

/// Base64-encoded hash digest
pub type Base64Hash = Base64<Hash>;

/// Base64-encoded PEM text (double-encoded)
pub type Base64Pem = Base64<Pem>;

/// Base64-encoded canonicalized Rekor entry body
pub type Base64Body = Base64<Body>;

/// Base64-encoded signed entry timestamp
pub type Base64Timestamp = Base64<Timestamp>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello world";
        let encoded = Base64::<()>::encode(data);
        let decoded = encoded.decode().unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"hello world";
        let encoded = Hex::encode(data);
        let decoded = encoded.decode().unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_sha256_hex() {
        let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash = Sha256Hash::from_hex(&Hex(hash_hex.to_string())).unwrap();
        assert_eq!(hash.to_hex(), hash_hex);
    }

    #[test]
    fn test_sha256_base64() {
        let hash_bytes = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let hash = Sha256Hash::from_bytes(hash_bytes);
        let base64 = hash.to_base64();
        let decoded = Sha256Hash::from_base64(&base64).unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn test_sha256_conversion() {
        let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let from_hex = Sha256Hash::from_hex(&Hex(hash_hex.to_string())).unwrap();
        let from_base64 = Sha256Hash::from_base64(&from_hex.to_base64()).unwrap();
        assert_eq!(from_hex, from_base64);
    }
}
