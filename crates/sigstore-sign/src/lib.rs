//! Sigstore signature creation
//!
//! This crate provides the main entry point for signing artifacts with Sigstore.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_sign::{SigningContext, SigningConfig};
//! use sigstore_oidc::IdentityToken;
//! use sigstore_types::BundleExt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let context = SigningContext::production();
//! let token = IdentityToken::new("your-identity-token".to_string());
//! let signer = context.signer(token);
//!
//! let artifact = b"hello world";
//! let bundle = signer.sign(artifact).await?;
//!
//! // Write bundle to file
//! std::fs::write("artifact.sigstore.json", bundle.to_json_pretty()?)?;
//! # Ok(())
//! # }
//! ```

pub mod error;
mod sign;

// Re-export core crates that users need
pub use sigstore_bundle as bundle;
pub use sigstore_crypto as crypto;
pub use sigstore_fulcio as fulcio;
pub use sigstore_oidc as oidc;
pub use sigstore_rekor as rekor;
pub use sigstore_tsa as tsa;
pub use sigstore_types as types;

pub use error::{Error, Result};
pub use sign::{
    sign_context, Attestation, AttestationSubject, Signer, SigningConfig, SigningContext,
};
