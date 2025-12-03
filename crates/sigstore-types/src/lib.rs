//! Core types and data structures for Sigstore
//!
//! This crate provides the fundamental data structures used throughout the Sigstore
//! ecosystem, including bundle formats, transparency log entries, and trust roots.

pub mod artifact;
pub mod bundle;
pub mod checkpoint;
pub mod dsse;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod intoto;

pub use artifact::Artifact;
pub use bundle::{
    Bundle, BundleVersion, CheckpointData, InclusionPromise, InclusionProof, KindVersion, LogId,
    MediaType, MessageDigest, MessageSignature, SignatureContent, TransparencyLogEntry,
    VerificationMaterial,
};
pub use checkpoint::{Checkpoint, CheckpointSignature};
pub use dsse::{pae, DsseEnvelope, DsseSignature};
pub use encoding::{
    base64_bytes, base64_bytes_option, hex_bytes, string_i64, CanonicalizedBody, DerCertificate,
    DerPublicKey, EntryUuid, HexHash, HexLogId, KeyHint, KeyId, LogIndex, LogKeyId, PayloadBytes,
    PemContent, Sha256Hash, SignatureBytes, SignedTimestamp, TimestampToken,
};
pub use error::{Error, Result};
pub use hash::HashAlgorithm;
pub use intoto::{Digest, Statement, Subject};
