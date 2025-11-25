//! Hash algorithm types and utilities

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Supported hash algorithms
///
/// This enum supports multiple serialization formats for compatibility:
/// - Sigstore bundle format: "SHA2_256", "SHA2_384", "SHA2_512"
/// - Rekor API format: "sha256", "sha384", "sha512"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA2-256
    Sha2256,
    /// SHA2-384
    Sha2384,
    /// SHA2-512
    Sha2512,
}

impl HashAlgorithm {
    /// Get the digest size in bytes for this algorithm
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha2256 => 32,
            HashAlgorithm::Sha2384 => 48,
            HashAlgorithm::Sha2512 => 64,
        }
    }

    /// Get the OID for this algorithm
    // TODO: Use a const_oid type here
    pub fn oid(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha2256 => "2.16.840.1.101.3.4.2.1",
            HashAlgorithm::Sha2384 => "2.16.840.1.101.3.4.2.2",
            HashAlgorithm::Sha2512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    /// Get the lowercase name (for Rekor API compatibility)
    pub fn as_lowercase(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha2256 => "sha256",
            HashAlgorithm::Sha2384 => "sha384",
            HashAlgorithm::Sha2512 => "sha512",
        }
    }

    /// Parse from string, supporting multiple formats
    pub fn from_str_flexible(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha256" | "sha2_256" | "sha-256" => Some(HashAlgorithm::Sha2256),
            "sha384" | "sha2_384" | "sha-384" => Some(HashAlgorithm::Sha2384),
            "sha512" | "sha2_512" | "sha-512" => Some(HashAlgorithm::Sha2512),
            _ => None,
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha2256 => write!(f, "SHA2_256"),
            HashAlgorithm::Sha2384 => write!(f, "SHA2_384"),
            HashAlgorithm::Sha2512 => write!(f, "SHA2_512"),
        }
    }
}

impl Serialize for HashAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize to the canonical Sigstore format
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        HashAlgorithm::from_str_flexible(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown hash algorithm: {}", s)))
    }
}

/// A hash output with its algorithm
/// TODO: This is unused?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOutput {
    /// The algorithm used to produce this hash
    pub algorithm: HashAlgorithm,
    /// The hash digest bytes
    pub digest: Vec<u8>,
}

impl HashOutput {
    /// Create a new hash output
    pub fn new(algorithm: HashAlgorithm, digest: Vec<u8>) -> Self {
        Self { algorithm, digest }
    }

    /// Get the digest as a hex string
    pub fn to_hex(&self) -> String {
        self.digest.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Message imprint combining algorithm and digest (for TSA)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageImprint {
    /// Hash algorithm used
    pub algorithm: HashAlgorithm,
    /// Hash digest (base64 encoded in JSON)
    #[serde(with = "crate::encoding::base64_bytes")]
    pub digest: Vec<u8>,
}

// Re-export base64_bytes from encoding module for backwards compatibility
pub use crate::encoding::base64_bytes;

/// Serde helper for lowercase hash algorithm serialization (for Rekor API)
///
/// Use this with `#[serde(with = "hash_algorithm_lowercase")]` on `HashAlgorithm`
/// fields that need to serialize as "sha256" instead of "SHA2_256".
pub mod hash_algorithm_lowercase {
    use super::HashAlgorithm;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(algo: &HashAlgorithm, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(algo.as_lowercase())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashAlgorithm, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        HashAlgorithm::from_str_flexible(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown hash algorithm: {}", s)))
    }
}
