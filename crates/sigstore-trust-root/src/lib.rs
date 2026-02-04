//! Sigstore trusted root parsing and management
//!
//! This crate provides functionality to parse and manage Sigstore trusted root bundles
//! and signing configuration.
//!
//! ## Trusted Root
//!
//! The trusted root contains all the trust anchors needed for verification:
//! - Fulcio certificate authorities (for signing certificates)
//! - Rekor transparency log public keys (for log entry verification)
//! - Certificate Transparency log public keys (for CT verification)
//! - Timestamp authority certificates (for RFC 3161 timestamp verification)
//!
//! ## Signing Config
//!
//! The signing config specifies service endpoints for signing operations:
//! - Fulcio CA URLs for certificate issuance
//! - Rekor transparency log URLs (V1 and V2 endpoints)
//! - TSA URLs for RFC 3161 timestamp requests
//! - OIDC provider URLs for authentication
//!
//! # Features
//!
//! - `tuf` (default) - Enable TUF (The Update Framework) support for securely fetching
//!   trusted roots from Sigstore's TUF repository. This is the recommended way to use
//!   this crate for production as it ensures you always have up-to-date trust material.
//!
//! # Example (Recommended)
//!
//! Fetch the latest trusted root and signing config via TUF protocol:
//!
//! ```no_run
//! use sigstore_trust_root::{TrustedRoot, SigningConfig};
//!
//! # async fn example() -> Result<(), sigstore_trust_root::Error> {
//! // Fetch via TUF protocol (secure, up-to-date) - RECOMMENDED
//! let root = TrustedRoot::production().await?;
//! let config = SigningConfig::production().await?;
//!
//! // Get the best Rekor endpoint (highest available version)
//! if let Some(rekor) = config.get_rekor_url(None) {
//!     println!("Rekor URL: {} (v{})", rekor.url, rekor.major_api_version);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Example (Offline/Embedded)
//!
//! Use embedded data when offline or TUF is not available:
//!
//! ```
//! use sigstore_trust_root::{
//!     TrustedRoot, SigningConfig,
//!     SIGSTORE_PRODUCTION_TRUSTED_ROOT, SIGSTORE_PRODUCTION_SIGNING_CONFIG,
//! };
//!
//! // Use embedded data (may be stale, but works offline)
//! let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
//! let config = SigningConfig::from_json(SIGSTORE_PRODUCTION_SIGNING_CONFIG).unwrap();
//! ```
//!
//! # Example (Custom TUF Repository)
//!
//! Fetch from a custom TUF repository (e.g., for testing):
//!
//! ```ignore
//! use sigstore_trust_root::{TrustedRoot, TufConfig};
//!
//! # async fn example() -> Result<(), sigstore_trust_root::Error> {
//! let config = TufConfig::custom(
//!     "https://sigstore.github.io/root-signing/",
//!     include_bytes!("path/to/root.json"),
//! );
//! let root = TrustedRoot::from_tuf(config).await?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod signing_config;
pub mod trusted_root;

#[cfg(feature = "tuf")]
pub mod tuf;

pub use error::{Error, Result};
pub use signing_config::{
    ServiceConfiguration, ServiceEndpoint, ServiceSelector, ServiceValidityPeriod, SigningConfig,
    SIGNING_CONFIG_MEDIA_TYPE, SIGSTORE_PRODUCTION_SIGNING_CONFIG, SIGSTORE_STAGING_SIGNING_CONFIG,
    SUPPORTED_FULCIO_VERSIONS, SUPPORTED_REKOR_VERSIONS, SUPPORTED_TSA_VERSIONS,
};
pub use trusted_root::{
    CertificateAuthority, CertificateTransparencyLog, TimestampAuthority, TransparencyLog,
    TrustedRoot, ValidityPeriod, SIGSTORE_PRODUCTION_TRUSTED_ROOT, SIGSTORE_STAGING_TRUSTED_ROOT,
};

#[cfg(feature = "tuf")]
pub use tuf::{
    TufConfig, DEFAULT_TUF_URL, PRODUCTION_TUF_ROOT, SIGNING_CONFIG_TARGET, STAGING_TUF_ROOT,
    STAGING_TUF_URL, TRUSTED_ROOT_TARGET,
};
