//! Sigstore signature verification
//!
//! This crate provides the main entry point for verifying Sigstore signatures.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_verify::{verify, VerificationPolicy};
//! use sigstore_trust_root::{TrustedRoot, TrustedRootExt};
//! use sigstore_types::{Bundle, BundleExt};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let trusted_root = TrustedRoot::production()?;
//! let bundle_json = std::fs::read_to_string("artifact.sigstore.json")?;
//! let bundle = Bundle::from_json(&bundle_json)?;
//! let artifact = std::fs::read("artifact.txt")?;
//!
//! let policy = VerificationPolicy::default()
//!     .require_identity("user@example.com")
//!     .require_issuer("https://accounts.google.com");
//!
//! let result = verify(&artifact, &bundle, &policy, &trusted_root)?;
//! assert!(result.success);
//! # Ok(())
//! # }
//! ```

pub mod error;
mod verify;

// Private submodules for verification logic
mod verify_impl;

// Re-export core types that users need
pub use sigstore_bundle as bundle;
pub use sigstore_crypto as crypto;
pub use sigstore_rekor as rekor;
pub use sigstore_trust_root as trust_root;
pub use sigstore_tsa as tsa;
pub use sigstore_types as types;

pub use error::{Error, Result};
pub use verify::{
    verify, VerificationPolicy, VerificationResult, Verifier, DEFAULT_CLOCK_SKEW_SECONDS,
};
