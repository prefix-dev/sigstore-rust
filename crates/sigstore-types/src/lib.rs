//! Core types and data structures for Sigstore
//!
//! This crate provides the fundamental data structures used throughout the Sigstore
//! ecosystem, including bundle formats, transparency log entries, and trust roots.

pub mod bundle;
pub mod checkpoint;
pub mod dsse;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod intoto;

pub use bundle::{
    Bundle, BundleVersion, CheckpointData, InclusionPromise, InclusionProof, KindVersion, LogId,
    MediaType, MessageSignature, SignatureContent, TransparencyLogEntry, VerificationMaterial,
};
pub use checkpoint::{Checkpoint, CheckpointSignature};
pub use dsse::{pae, DsseEnvelope, DsseSignature};
pub use encoding::{
    Base64, Base64Body, Base64Der, Base64Hash, Base64Payload, Base64Pem, Base64Signature,
    Base64Timestamp, Body, Der, EntryUuid, Hash, Hex, HexLogId, KeyId, LogIndex, LogKeyId, Payload,
    Pem, Sha256Hash, Signature, Timestamp, Unknown,
};
pub use error::{Error, Result};
pub use hash::{HashAlgorithm, HashOutput, MessageImprint};
pub use intoto::{Digest, Statement, Subject};
