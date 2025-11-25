//! Hash algorithm types and utilities

use serde::{Deserialize, Serialize};

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA2-256
    #[serde(rename = "SHA2_256")]
    Sha2256,
    /// SHA2-384
    #[serde(rename = "SHA2_384")]
    Sha2384,
    /// SHA2-512
    #[serde(rename = "SHA2_512")]
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
    #[serde(with = "crate::base64_bytes")]
    pub digest: Vec<u8>,
}

/// Serde helper for base64 encoding/decoding of byte arrays
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
