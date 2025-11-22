//! Merkle tree hashing utilities
//!
//! Implements RFC 6962 compliant Merkle tree hashing with:
//! - Domain separation via prefixes (0x00 for leaf, 0x01 for node)
//! - SHA-256 hash function

use sigstore_crypto::Sha256Hasher;
use sigstore_types::Sha256Hash;

/// Prefix for leaf nodes in RFC 6962 Merkle tree
pub const LEAF_HASH_PREFIX: u8 = 0x00;

/// Prefix for internal nodes in RFC 6962 Merkle tree
pub const NODE_HASH_PREFIX: u8 = 0x01;

/// Hash a leaf node
///
/// Returns: SHA256(0x00 || leaf_data)
pub fn hash_leaf(data: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256Hasher::new();
    hasher.update(&[LEAF_HASH_PREFIX]);
    hasher.update(data);
    Sha256Hash::from_bytes(hasher.finalize())
}

/// Hash two child nodes to create a parent node
///
/// Returns: SHA256(0x01 || left || right)
pub fn hash_children(left: &Sha256Hash, right: &Sha256Hash) -> Sha256Hash {
    let mut hasher = Sha256Hasher::new();
    hasher.update(&[NODE_HASH_PREFIX]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    Sha256Hash::from_bytes(hasher.finalize())
}

/// Calculate the number of trailing zeros in a number (LSB)
pub fn trailing_zeros(n: u64) -> u32 {
    if n == 0 {
        64
    } else {
        n.trailing_zeros()
    }
}

/// Calculate the position of the most significant bit
pub fn bit_length(n: u64) -> u32 {
    if n == 0 {
        0
    } else {
        64 - n.leading_zeros()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_leaf() {
        let data = b"test data";
        let hash = hash_leaf(data);

        // Verify it's 32 bytes
        assert_eq!(hash.as_bytes().len(), 32);

        // Verify it's different from raw SHA256
        let raw_hash = sigstore_crypto::sha256(data);
        assert_ne!(hash.as_bytes(), &raw_hash);
    }

    #[test]
    fn test_hash_children() {
        let left = Sha256Hash::from_bytes([0u8; 32]);
        let right = Sha256Hash::from_bytes([1u8; 32]);
        let hash = hash_children(&left, &right);

        assert_eq!(hash.as_bytes().len(), 32);

        // Verify order matters
        let hash_reversed = hash_children(&right, &left);
        assert_ne!(hash, hash_reversed);
    }

    #[test]
    fn test_trailing_zeros() {
        assert_eq!(trailing_zeros(0), 64);
        assert_eq!(trailing_zeros(1), 0);
        assert_eq!(trailing_zeros(2), 1);
        assert_eq!(trailing_zeros(4), 2);
        assert_eq!(trailing_zeros(8), 3);
        assert_eq!(trailing_zeros(6), 1); // 110 in binary
    }

    #[test]
    fn test_bit_length() {
        assert_eq!(bit_length(0), 0);
        assert_eq!(bit_length(1), 1);
        assert_eq!(bit_length(2), 2);
        assert_eq!(bit_length(3), 2);
        assert_eq!(bit_length(4), 3);
        assert_eq!(bit_length(255), 8);
        assert_eq!(bit_length(256), 9);
    }
}
