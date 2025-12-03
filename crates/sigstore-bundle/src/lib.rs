//! Bundle format handling for Sigstore
//!
//! This crate handles creation, parsing, and validation of Sigstore bundles
//! (versions 0.1, 0.2, and 0.3).

pub mod builder;
pub mod error;
pub mod validation;

pub use builder::{tlog_entry_from_log_entry, BundleV03, SignatureContent, VerificationMaterialV03};
pub use error::{Error, Result};
pub use validation::{validate_bundle, validate_bundle_with_options, ValidationOptions};

// Re-export proto types for convenience
pub use sigstore_types::proto::{
    Bundle, BundleBuilder, InclusionProofBuilder, MediaType, OwnedDsseEnvelope, TlogEntryBuilder,
};
