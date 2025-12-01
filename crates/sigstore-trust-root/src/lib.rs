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
//! - `tuf` - Enable TUF (The Update Framework) support for securely fetching
//!   trusted roots from Sigstore's TUF repository. This adds async methods
//!   like [`TrustedRoot::from_tuf()`] and [`TrustedRoot::from_tuf_staging()`].
//!
//! # Example
//!
//! ```no_run
//! use sigstore_trust_root::{TrustedRoot, SigningConfig};
//!
//! // Load embedded production trusted root
//! let root = TrustedRoot::production().unwrap();
//!
//! // Load embedded production signing config
//! let config = SigningConfig::production().unwrap();
//!
//! // Get the best Rekor endpoint (highest available version)
//! if let Some(rekor) = config.get_rekor_url(None) {
//!     println!("Rekor URL: {} (v{})", rekor.url, rekor.major_api_version);
//! }
//! ```
//!
//! With the `tuf` feature enabled:
//!
//! ```ignore
//! use sigstore_trust_root::{TrustedRoot, SigningConfig};
//!
//! // Fetch via TUF protocol (secure, up-to-date)
//! let root = TrustedRoot::from_tuf().await?;
//! let config = SigningConfig::from_tuf().await?;
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
