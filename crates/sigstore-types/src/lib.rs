//! Core types and data structures for Sigstore
//!
//! This crate provides the fundamental data structures used throughout the Sigstore
//! ecosystem, including bundle formats, transparency log entries, and trust roots.
//!
//! ## Type-Safe Wrappers
//!
//! This crate uses type-safe wrappers for binary data to prevent encoding mistakes:
//!
//! - [`Sha256Hash`] - 32-byte hash with compile-time size guarantee
//! - [`DerCertificate`] - DER-encoded X.509 certificate
//! - [`SignatureBytes`] - Raw signature bytes
//! - [`LogKeyId`] - Base64-encoded log key identifier
//!
//! The bundle types in [`proto`] wrap the protobuf-generated types and provide
//! type-safe accessors that return these wrapper types.

pub mod artifact;
pub mod bundle;
pub mod checkpoint;
pub mod dsse;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod intoto;
pub mod proto;

pub use artifact::Artifact;
pub use bundle::{
    Bundle, BundleVersion, CheckpointData, InclusionPromise, InclusionProof, KindVersion, LogId,
    MediaType, MessageDigest, MessageSignature, SignatureContent, TransparencyLogEntry,
    VerificationMaterial,
};
pub use checkpoint::{Checkpoint, CheckpointSignature};
pub use dsse::{pae, DsseEnvelope, DsseSignature};
pub use encoding::{
    base64_bytes, base64_bytes_option, hex_bytes, CanonicalizedBody, DerCertificate, DerPublicKey,
    EntryUuid, HexHash, HexLogId, KeyHint, KeyId, LogIndex, LogKeyId, PayloadBytes, PemContent,
    Sha256Hash, SignatureBytes, SignedTimestamp, TimestampToken,
};
pub use error::{Error, Result};
pub use hash::HashAlgorithm;
pub use intoto::{Digest, Statement, Subject};
