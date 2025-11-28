//! Artifact types for signing and verification
//!
//! This module provides types for representing artifacts to be signed or verified.
//! Artifacts can be provided as raw bytes or as pre-computed digests, allowing
//! for efficient handling of large files without loading them entirely into memory.

use crate::Sha256Hash;

/// An artifact to be signed or verified
///
/// This enum allows flexible input for signing and verification operations:
/// - `Bytes`: Raw artifact bytes (hash will be computed internally)
/// - `Digest`: Pre-computed SHA-256 digest (no raw bytes needed)
///
/// # Example
///
/// ```
/// use sigstore_types::{Artifact, Sha256Hash};
///
/// // From raw bytes
/// let artifact = Artifact::from(b"hello world".as_slice());
///
/// // From pre-computed digest
/// let digest = Sha256Hash::from_hex(
///     "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
/// ).unwrap();
/// let artifact = Artifact::from(digest);
/// ```
#[derive(Debug, Clone)]
pub enum Artifact<'a> {
    /// Raw artifact bytes (hash will be computed)
    Bytes(&'a [u8]),
    /// Pre-computed SHA-256 digest
    Digest(Sha256Hash),
}

impl<'a> Artifact<'a> {
    /// Create an artifact from raw bytes
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Artifact::Bytes(bytes)
    }

    /// Create an artifact from a pre-computed digest
    pub fn from_digest(digest: Sha256Hash) -> Self {
        Artifact::Digest(digest)
    }

    /// Check if this artifact has raw bytes available
    pub fn has_bytes(&self) -> bool {
        matches!(self, Artifact::Bytes(_))
    }

    /// Get the raw bytes if available
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Artifact::Bytes(bytes) => Some(bytes),
            Artifact::Digest(_) => None,
        }
    }

    /// Get the pre-computed digest if available
    pub fn pre_computed_digest(&self) -> Option<Sha256Hash> {
        match self {
            Artifact::Bytes(_) => None,
            Artifact::Digest(hash) => Some(*hash),
        }
    }
}

impl<'a> From<&'a [u8]> for Artifact<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Artifact::Bytes(bytes)
    }
}

impl<'a> From<&'a Vec<u8>> for Artifact<'a> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        Artifact::Bytes(bytes.as_slice())
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Artifact<'a> {
    fn from(bytes: &'a [u8; N]) -> Self {
        Artifact::Bytes(bytes.as_slice())
    }
}

impl From<Sha256Hash> for Artifact<'static> {
    fn from(hash: Sha256Hash) -> Self {
        Artifact::Digest(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_from_bytes() {
        let bytes = b"hello world";
        let artifact = Artifact::from(bytes.as_slice());
        assert!(artifact.has_bytes());
        assert_eq!(artifact.bytes(), Some(bytes.as_slice()));
    }

    #[test]
    fn test_artifact_from_digest() {
        let digest = Sha256Hash::from_hex(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .unwrap();
        let artifact = Artifact::from(digest);
        assert!(!artifact.has_bytes());
        assert_eq!(artifact.bytes(), None);
    }
}
