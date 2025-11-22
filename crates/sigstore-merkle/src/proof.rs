//! Merkle proof verification
//!
//! Implements inclusion proof and consistency proof verification as specified in RFC 6962.
//! The algorithm follows the reference implementations from sigstore-python and sigstore-go.

use crate::error::{Error, Result};
use crate::tree::{bit_length, hash_children, hash_leaf};
use sigstore_types::Sha256Hash;

/// Verify an inclusion proof for a leaf in a Merkle tree
///
/// # Arguments
/// * `leaf_hash` - The hash of the leaf entry
/// * `leaf_index` - Index of the leaf in the tree (0-based)
/// * `tree_size` - Total number of leaves in the tree
/// * `proof_hashes` - The hashes in the inclusion proof path
/// * `expected_root` - The expected root hash to verify against
///
/// # Returns
/// * `Ok(())` if the proof is valid
/// * `Err(...)` if the proof is invalid
pub fn verify_inclusion_proof(
    leaf_hash: &Sha256Hash,
    leaf_index: u64,
    tree_size: u64,
    proof_hashes: &[Sha256Hash],
    expected_root: &Sha256Hash,
) -> Result<()> {
    if tree_size == 0 {
        return Err(Error::InvalidTreeSize(
            "tree size cannot be zero".to_string(),
        ));
    }

    if leaf_index >= tree_size {
        return Err(Error::InvalidLeafIndex(format!(
            "leaf index {} >= tree size {}",
            leaf_index, tree_size
        )));
    }

    // Compute the root hash using the RFC 6962 algorithm
    // The proof hashes are processed from leaf to root
    let mut hash = *leaf_hash;
    let mut index = leaf_index;
    let mut last_node = tree_size - 1;

    for proof_hash in proof_hashes {
        // Determine hash order based on position in tree:
        // - If index is odd (right child), sibling is on left: hash(sibling, current)
        // - If index equals last_node (rightmost in incomplete subtree): hash(sibling, current)
        // - Otherwise (left child): hash(current, sibling)
        if index % 2 == 1 || index == last_node {
            hash = hash_children(proof_hash, &hash);
        } else {
            hash = hash_children(&hash, proof_hash);
        }
        index /= 2;
        last_node /= 2;
    }

    // Verify the calculated root matches expected
    if &hash != expected_root {
        return Err(Error::HashMismatch {
            expected: expected_root.to_hex(),
            actual: hash.to_hex(),
        });
    }

    Ok(())
}

/// Verify a consistency proof between two tree states
///
/// # Arguments
/// * `old_size` - Size of the older tree
/// * `new_size` - Size of the newer tree
/// * `proof_hashes` - The hashes in the consistency proof
/// * `old_root` - Root hash of the older tree
/// * `new_root` - Root hash of the newer tree
///
/// # Returns
/// * `Ok(())` if the proof is valid
/// * `Err(...)` if the proof is invalid
pub fn verify_consistency_proof(
    old_size: u64,
    new_size: u64,
    proof_hashes: &[Sha256Hash],
    old_root: &Sha256Hash,
    new_root: &Sha256Hash,
) -> Result<()> {
    if old_size == 0 {
        // Empty tree is consistent with any tree
        return Ok(());
    }

    if old_size > new_size {
        return Err(Error::InvalidTreeSize(format!(
            "old size {} > new size {}",
            old_size, new_size
        )));
    }

    if old_size == new_size {
        // Same size, roots must match
        if old_root != new_root {
            return Err(Error::HashMismatch {
                expected: old_root.to_hex(),
                actual: new_root.to_hex(),
            });
        }
        if !proof_hashes.is_empty() {
            return Err(Error::InvalidProof(
                "proof should be empty for same-size trees".to_string(),
            ));
        }
        return Ok(());
    }

    // Normal case: old_size > 0 and new_size > old_size
    if proof_hashes.is_empty() {
        return Err(Error::InvalidProof(
            "proof cannot be empty for different-size trees".to_string(),
        ));
    }

    // Find the largest power of 2 less than or equal to old_size
    let shift = old_size.trailing_zeros() as usize;
    let (inner, border) = decompose_inclusion_proof(old_size - 1, new_size)?;
    let inner = inner.saturating_sub(shift);

    // The proof includes the root hash for the sub-tree of size 2^shift,
    // unless old_size is exactly 2^shift
    let (seed, start) = if old_size == (1 << shift) {
        (old_root, 0)
    } else {
        if proof_hashes.is_empty() {
            return Err(Error::InvalidProof("insufficient proof hashes".to_string()));
        }
        (&proof_hashes[0], 1)
    };

    let expected_len = start + inner + border;
    if proof_hashes.len() != expected_len {
        return Err(Error::InvalidProof(format!(
            "expected {} proof hashes, got {}",
            expected_len,
            proof_hashes.len()
        )));
    }

    let proof = &proof_hashes[start..];
    let mask = (old_size - 1) >> shift;

    // Verify the old root is correct by chaining to the right
    let hash1 = chain_inner_right(seed, &proof[..inner], mask);
    let calc_old_root = chain_border_right(&hash1, &proof[inner..]);

    // Verify the new root is correct
    let hash2 = chain_inner(seed, &proof[..inner], mask);
    let calc_new_root = chain_border_right(&hash2, &proof[inner..]);

    // Verify both roots
    if &calc_old_root != old_root {
        return Err(Error::VerificationFailed(format!(
            "old root mismatch: expected {}, got {}",
            old_root.to_hex(),
            calc_old_root.to_hex()
        )));
    }

    if &calc_new_root != new_root {
        return Err(Error::VerificationFailed(format!(
            "new root mismatch: expected {}, got {}",
            new_root.to_hex(),
            calc_new_root.to_hex()
        )));
    }

    Ok(())
}

/// Decompose an inclusion proof into inner and border path lengths
///
/// Returns (inner_path_length, border_path_length)
fn decompose_inclusion_proof(index: u64, tree_size: u64) -> Result<(usize, usize)> {
    let inner = inner_proof_size(index, tree_size);
    let border = bit_length((index >> inner) as u64) as usize;
    Ok((inner, border))
}

/// Calculate the inner proof size for a given index and tree size
fn inner_proof_size(index: u64, tree_size: u64) -> usize {
    bit_length(index ^ (tree_size - 1)) as usize
}

/// Chain hashes along the inner proof path for new root verification
fn chain_inner(seed: &Sha256Hash, proof: &[Sha256Hash], index: u64) -> Sha256Hash {
    let mut hash = *seed;
    for (i, p) in proof.iter().enumerate() {
        if (index >> i) & 1 == 0 {
            hash = hash_children(&hash, p);
        } else {
            hash = hash_children(p, &hash);
        }
    }
    hash
}

/// Chain hashes along the inner proof path for old root verification
///
/// Only hashes when the index bit is 1 (we're coming from the left)
fn chain_inner_right(seed: &Sha256Hash, proof: &[Sha256Hash], index: u64) -> Sha256Hash {
    let mut hash = *seed;
    for (i, p) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            hash = hash_children(p, &hash);
        }
        // If bit is 0, we're on the right edge, so we don't hash
    }
    hash
}

/// Chain hashes along the right border (all proof hashes go on the left)
fn chain_border_right(seed: &Sha256Hash, proof: &[Sha256Hash]) -> Sha256Hash {
    let mut hash = *seed;
    for p in proof {
        hash = hash_children(p, &hash);
    }
    hash
}

/// Convenience function to verify inclusion from base64-encoded data
pub fn verify_inclusion_proof_base64(
    leaf_data: &[u8],
    leaf_index: u64,
    tree_size: u64,
    proof_hashes_b64: &[String],
    expected_root_b64: &str,
) -> Result<()> {
    let leaf_hash = hash_leaf(leaf_data);

    let proof_hashes: Vec<Sha256Hash> = proof_hashes_b64
        .iter()
        .map(|h| Sha256Hash::from_base64(h).map_err(|e| Error::InvalidProof(e.to_string())))
        .collect::<Result<Vec<_>>>()?;

    let expected_root = Sha256Hash::from_base64(expected_root_b64)
        .map_err(|e| Error::InvalidProof(e.to_string()))?;

    verify_inclusion_proof(
        &leaf_hash,
        leaf_index,
        tree_size,
        &proof_hashes,
        &expected_root,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompose_inclusion_proof() {
        // Test various tree sizes and indices
        // For tree_size=1, index=0: no proof needed
        let (inner, border) = decompose_inclusion_proof(0, 1).unwrap();
        assert_eq!(inner, 0);
        assert_eq!(border, 0);

        // For tree_size=2, index=0: 0 ^ 1 = 1, bit_length(1) = 1
        let (inner, border) = decompose_inclusion_proof(0, 2).unwrap();
        assert_eq!(inner, 1);
        assert_eq!(border, 0);

        // For tree_size=2, index=1: 1 ^ 1 = 0, bit_length(0) = 0
        // The border calculation: bit_length(1 >> 0) = bit_length(1) = 1
        // Wait, this doesn't match. Let me trace through:
        // inner = bit_length(1 ^ (2-1)) = bit_length(1 ^ 1) = bit_length(0) = 0
        // border = bit_length((1 >> 0) as u64) = bit_length(1) = 1
        // So we expect 0 inner hashes and 1 border hash = 1 total
        let (inner, border) = decompose_inclusion_proof(1, 2).unwrap();
        assert_eq!(inner, 0);
        assert_eq!(border, 1);
    }

    #[test]
    fn test_chain_border_right() {
        let seed = Sha256Hash::from_bytes([0u8; 32]);
        let empty: &[Sha256Hash] = &[];
        let result = chain_border_right(&seed, empty);
        assert_eq!(result, seed);

        let proof = [Sha256Hash::from_bytes([1u8; 32])];
        let result = chain_border_right(&seed, &proof);
        assert_ne!(result, seed);
    }

    #[test]
    fn test_verify_inclusion_proof_single_leaf() {
        // Tree with single leaf: root = hash_leaf(data)
        let data = b"test";
        let leaf_hash = hash_leaf(data);
        let proof: &[Sha256Hash] = &[];

        let result = verify_inclusion_proof(&leaf_hash, 0, 1, proof, &leaf_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_inclusion_proof_two_leaves() {
        // Tree with two leaves
        let data0 = b"leaf0";
        let data1 = b"leaf1";
        let hash0 = hash_leaf(data0);
        let hash1 = hash_leaf(data1);
        let root = hash_children(&hash0, &hash1);

        // Verify leaf 0
        let result = verify_inclusion_proof(&hash0, 0, 2, &[hash1], &root);
        assert!(result.is_ok());

        // Verify leaf 1
        let result = verify_inclusion_proof(&hash1, 1, 2, &[hash0], &root);
        assert!(result.is_ok());
    }
}
