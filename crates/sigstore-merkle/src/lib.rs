//! RFC 6962 Merkle tree verification for Sigstore
//!
//! This crate implements Merkle tree operations as specified in RFC 6962,
//! including inclusion proof and consistency proof verification.

pub mod error;
pub mod proof;
pub mod tree;

pub use error::{Error, Result};
pub use proof::{verify_consistency_proof, verify_inclusion_proof};
pub use tree::{hash_children, hash_leaf, LEAF_HASH_PREFIX, NODE_HASH_PREFIX};
