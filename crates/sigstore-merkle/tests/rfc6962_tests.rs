//! RFC 6962 Merkle tree test suite
//!
//! Test vectors from transparency-dev/merkle for validating our implementation.
//! https://github.com/transparency-dev/merkle

use serde::Deserialize;
use sigstore_merkle::{hash_children, hash_leaf, verify_inclusion_proof};
use sigstore_types::Sha256Hash;
use std::fs;
use std::path::PathBuf;

/// Inclusion test case from transparency-dev
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionTestCase {
    leaf_idx: u64,
    tree_size: u64,
    root: String,
    leaf_hash: String,
    proof: Option<Vec<String>>,
    desc: String,
    want_err: bool,
}

/// Consistency test case from transparency-dev
#[derive(Debug, Deserialize)]
struct ConsistencyTestCase {
    size1: u64,
    size2: u64,
    root1: String,
    root2: String,
    proof: Option<Vec<String>>,
    desc: String,
    #[serde(rename = "wantErr")]
    want_err: bool,
}

/// Get the test data directory path
fn test_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data/merkle/testdata")
}

/// Helper function to decode base64 hash
fn decode_hash(s: &str) -> Sha256Hash {
    Sha256Hash::from_base64(s).expect("valid base64 SHA256 hash")
}

/// Load an inclusion test case from file
fn load_inclusion_test(subdir: &str, name: &str) -> InclusionTestCase {
    let path = test_data_dir().join("inclusion").join(subdir).join(name);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
}

/// Load a consistency test case from file
fn load_consistency_test(subdir: &str, name: &str) -> ConsistencyTestCase {
    let path = test_data_dir().join("consistency").join(subdir).join(name);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
}

/// Try to decode a base64 hash, returning None if it's not 32 bytes
fn try_decode_hash(s: &str) -> Option<Sha256Hash> {
    Sha256Hash::from_base64(s).ok()
}

/// Run an inclusion test case
fn run_inclusion_test(test: &InclusionTestCase) {
    // Try to decode hashes - some test cases have intentionally invalid hashes
    let root = try_decode_hash(&test.root);
    let leaf_hash = try_decode_hash(&test.leaf_hash);

    // If we can't decode the hashes, the test should expect an error
    let (root, leaf_hash) = match (root, leaf_hash) {
        (Some(r), Some(l)) => (r, l),
        _ => {
            // Invalid hash format - this should be an error case
            assert!(
                test.want_err,
                "Test '{}' has invalid hash but doesn't expect error",
                test.desc
            );
            return;
        }
    };

    let proof: Vec<Sha256Hash> = test
        .proof
        .as_ref()
        .map(|p| p.iter().map(|s| decode_hash(s)).collect())
        .unwrap_or_default();

    let result = verify_inclusion_proof(&leaf_hash, test.leaf_idx, test.tree_size, &proof, &root);

    if test.want_err {
        assert!(
            result.is_err(),
            "Test '{}' should fail but succeeded",
            test.desc
        );
    } else {
        assert!(
            result.is_ok(),
            "Test '{}' should succeed but failed: {:?}",
            test.desc,
            result.err()
        );
    }
}

/// Run a consistency test case
fn run_consistency_test(test: &ConsistencyTestCase) {
    let root1 = decode_hash(&test.root1);
    let root2 = decode_hash(&test.root2);
    let proof: Vec<Sha256Hash> = test
        .proof
        .as_ref()
        .map(|p| p.iter().map(|s| decode_hash(s)).collect())
        .unwrap_or_default();

    let result =
        sigstore_merkle::verify_consistency_proof(test.size1, test.size2, &proof, &root1, &root2);

    if test.want_err {
        assert!(
            result.is_err(),
            "Test '{}' should fail but succeeded",
            test.desc
        );
    } else {
        assert!(
            result.is_ok(),
            "Test '{}' should succeed but failed: {:?}",
            test.desc,
            result.err()
        );
    }
}

// ==== Inclusion Tests from transparency-dev ====

#[test]
fn test_inclusion_0_happy_path() {
    let test = load_inclusion_test("0", "happy-path.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_0_empty_root() {
    let test = load_inclusion_test("0", "empty-root.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_0_random_root() {
    let test = load_inclusion_test("0", "random-root.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_0_wrong_leaf() {
    let test = load_inclusion_test("0", "wrong-leaf.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_1_happy_path() {
    let test = load_inclusion_test("1", "happy-path.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_1_empty_root() {
    let test = load_inclusion_test("1", "empty-root.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_1_inserted_component() {
    let test = load_inclusion_test("1", "inserted-component.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_1_wrong_leaf() {
    let test = load_inclusion_test("1", "wrong-leaf.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_2_happy_path() {
    let test = load_inclusion_test("2", "happy-path.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_3_happy_path() {
    let test = load_inclusion_test("3", "happy-path.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_4_happy_path() {
    let test = load_inclusion_test("4", "happy-path.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_single_entry_empty_leaf() {
    let test = load_inclusion_test("single-entry", "empty-leaf.json");
    run_inclusion_test(&test);
}

#[test]
fn test_inclusion_single_entry_matching() {
    let test = load_inclusion_test("single-entry", "matching-root-and-leaf.json");
    run_inclusion_test(&test);
}

// ==== Consistency Tests from transparency-dev ====

#[test]
fn test_consistency_0_happy_path() {
    let test = load_consistency_test("0", "happy-path.json");
    run_consistency_test(&test);
}

#[test]
fn test_consistency_1_happy_path() {
    let test = load_consistency_test("1", "happy-path.json");
    run_consistency_test(&test);
}

#[test]
fn test_consistency_1_empty_proof() {
    let test = load_consistency_test("1", "empty-proof.json");
    run_consistency_test(&test);
}

#[test]
fn test_consistency_1_swapped_roots() {
    let test = load_consistency_test("1", "swapped-roots.json");
    run_consistency_test(&test);
}

#[test]
fn test_consistency_1_truncated_proof() {
    let test = load_consistency_test("1", "truncated-proof.json");
    run_consistency_test(&test);
}

// ==== Additional programmatic tests ====

/// Test single leaf tree
#[test]
fn test_inclusion_single_leaf() {
    let data = b"single leaf";
    let leaf_hash = hash_leaf(data);

    // In a single leaf tree, the root is the leaf hash, and proof is empty
    let result = verify_inclusion_proof(&leaf_hash, 0, 1, &[], &leaf_hash);
    assert!(result.is_ok());
}

/// Test two leaf tree - left leaf
#[test]
fn test_inclusion_two_leaves_left() {
    let data0 = b"leaf 0";
    let data1 = b"leaf 1";
    let hash0 = hash_leaf(data0);
    let hash1 = hash_leaf(data1);
    let root = hash_children(&hash0, &hash1);

    // Verify leaf 0 with proof [hash1]
    let result = verify_inclusion_proof(&hash0, 0, 2, &[hash1], &root);
    assert!(
        result.is_ok(),
        "Left leaf verification failed: {:?}",
        result
    );
}

/// Test two leaf tree - right leaf
#[test]
fn test_inclusion_two_leaves_right() {
    let data0 = b"leaf 0";
    let data1 = b"leaf 1";
    let hash0 = hash_leaf(data0);
    let hash1 = hash_leaf(data1);
    let root = hash_children(&hash0, &hash1);

    // Verify leaf 1 with proof [hash0]
    let result = verify_inclusion_proof(&hash1, 1, 2, &[hash0], &root);
    assert!(
        result.is_ok(),
        "Right leaf verification failed: {:?}",
        result
    );
}

/// Test four leaf tree
#[test]
fn test_inclusion_four_leaves() {
    // Tree structure:
    //         root
    //        /    \
    //       h01   h23
    //      /  \   /  \
    //     l0  l1 l2  l3

    let leaf0 = hash_leaf(b"leaf 0");
    let leaf1 = hash_leaf(b"leaf 1");
    let leaf2 = hash_leaf(b"leaf 2");
    let leaf3 = hash_leaf(b"leaf 3");

    let h01 = hash_children(&leaf0, &leaf1);
    let h23 = hash_children(&leaf2, &leaf3);
    let root = hash_children(&h01, &h23);

    // Verify leaf 0: proof is [leaf1, h23]
    let result = verify_inclusion_proof(&leaf0, 0, 4, &[leaf1, h23], &root);
    assert!(result.is_ok(), "Leaf 0 verification failed: {:?}", result);

    // Verify leaf 1: proof is [leaf0, h23]
    let result = verify_inclusion_proof(&leaf1, 1, 4, &[leaf0, h23], &root);
    assert!(result.is_ok(), "Leaf 1 verification failed: {:?}", result);

    // Verify leaf 2: proof is [leaf3, h01]
    let result = verify_inclusion_proof(&leaf2, 2, 4, &[leaf3, h01], &root);
    assert!(result.is_ok(), "Leaf 2 verification failed: {:?}", result);

    // Verify leaf 3: proof is [leaf2, h01]
    let result = verify_inclusion_proof(&leaf3, 3, 4, &[leaf2, h01], &root);
    assert!(result.is_ok(), "Leaf 3 verification failed: {:?}", result);
}

/// Test error case: wrong root hash
#[test]
fn test_inclusion_wrong_root() {
    let leaf_hash = hash_leaf(b"test");
    let wrong_root = Sha256Hash::from_bytes([0u8; 32]);

    let result = verify_inclusion_proof(&leaf_hash, 0, 1, &[], &wrong_root);
    assert!(result.is_err(), "Should fail with wrong root");
}

/// Test error case: leaf index out of bounds
#[test]
fn test_inclusion_index_out_of_bounds() {
    let leaf_hash = hash_leaf(b"test");
    let root = leaf_hash;

    let result = verify_inclusion_proof(&leaf_hash, 1, 1, &[], &root);
    assert!(result.is_err(), "Should fail with index >= tree_size");
}

/// Test error case: zero tree size
#[test]
fn test_inclusion_zero_tree_size() {
    let leaf_hash = hash_leaf(b"test");

    let result = verify_inclusion_proof(&leaf_hash, 0, 0, &[], &leaf_hash);
    assert!(result.is_err(), "Should fail with zero tree size");
}

/// Test consistency proof: same size trees
#[test]
fn test_consistency_same_size() {
    let root = hash_leaf(b"test");

    let result = sigstore_merkle::verify_consistency_proof(1, 1, &[], &root, &root);
    assert!(
        result.is_ok(),
        "Same size consistency should succeed: {:?}",
        result
    );
}

/// Test consistency proof: empty old tree
#[test]
fn test_consistency_empty_old_tree() {
    let root = hash_leaf(b"test");
    let empty_root = Sha256Hash::from_bytes([0u8; 32]);

    // Empty tree is consistent with any tree
    let result = sigstore_merkle::verify_consistency_proof(0, 1, &[], &empty_root, &root);
    assert!(result.is_ok(), "Empty old tree should be consistent");
}

/// Test consistency error: old size > new size
#[test]
fn test_consistency_invalid_sizes() {
    let root = hash_leaf(b"test");

    let result = sigstore_merkle::verify_consistency_proof(2, 1, &[], &root, &root);
    assert!(result.is_err(), "Should fail when old_size > new_size");
}

/// Test hash_leaf produces correct RFC 6962 format
#[test]
fn test_hash_leaf_format() {
    // RFC 6962 leaf hash should be SHA256(0x00 || data)
    let data = b"test";
    let hash = hash_leaf(data);

    // Verify it's 32 bytes
    assert_eq!(hash.as_bytes().len(), 32);

    // Manually compute expected hash
    let mut raw_data = vec![0x00];
    raw_data.extend_from_slice(data);
    let expected = sigstore_crypto::sha256(&raw_data);

    assert_eq!(
        hash.as_bytes(),
        &expected,
        "hash_leaf should use 0x00 prefix"
    );
}

/// Test hash_children produces correct RFC 6962 format
#[test]
fn test_hash_children_format() {
    // RFC 6962 node hash should be SHA256(0x01 || left || right)
    let left = hash_leaf(b"left");
    let right = hash_leaf(b"right");
    let hash = hash_children(&left, &right);

    // Verify it's 32 bytes
    assert_eq!(hash.as_bytes().len(), 32);

    // Manually compute expected hash
    let mut raw_data = vec![0x01];
    raw_data.extend_from_slice(left.as_bytes());
    raw_data.extend_from_slice(right.as_bytes());
    let expected = sigstore_crypto::sha256(&raw_data);

    assert_eq!(
        hash.as_bytes(),
        &expected,
        "hash_children should use 0x01 prefix"
    );
}
