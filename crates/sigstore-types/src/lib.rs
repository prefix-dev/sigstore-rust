//! Core types and data structures for Sigstore
//!
//! This crate provides the fundamental data structures used throughout the Sigstore
//! ecosystem, including bundle formats, transparency log entries, and trust roots.
//!
//! Bundle types are re-exported from the official Sigstore protobuf specs, with
//! extension traits providing convenient methods.

pub mod artifact;
pub mod bundle;
pub mod checkpoint;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod intoto;

// Note: dsse module removed - DSSE types now come from protobuf specs via bundle module

pub use artifact::Artifact;

// Re-export protobuf bundle types and extension traits
pub use bundle::{
    pae, Bundle, BundleContent, BundleExt, DsseEnvelope, DsseEnvelopeExt, DsseSignature,
    HashOutput, InclusionPromise, InclusionProof, InclusionProofExt, KindVersion, LogId, MediaType,
    MessageSignature, ProtoCheckpoint, ProtoHashAlgorithm, PublicKeyIdentifier,
    Rfc3161SignedTimestamp, TimestampVerificationData, TransparencyLogEntry,
    TransparencyLogEntryExt, VerificationMaterial, VerificationMaterialContent, X509Certificate,
    X509CertificateChain,
};

pub use checkpoint::{Checkpoint, CheckpointSignature};
pub use encoding::{
    base64_bytes, base64_bytes_option, hex_bytes, CanonicalizedBody, DerCertificate, DerPublicKey,
    EntryUuid, HexHash, HexLogId, KeyHint, KeyId, LogIndex, LogKeyId, PayloadBytes, PemContent,
    Sha256Hash, SignatureBytes, SignedTimestamp, TimestampToken,
};
pub use error::{Error, Result};
pub use hash::HashAlgorithm;
pub use intoto::{Digest, Statement, Subject};
