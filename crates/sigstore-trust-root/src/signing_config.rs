//! Signing configuration for Sigstore instances
//!
//! This module provides functionality to parse and manage Sigstore signing configuration
//! which specifies the service endpoints for signing operations:
//! - Fulcio CA URLs for certificate issuance
//! - Rekor transparency log URLs for log entry submission
//! - TSA URLs for RFC 3161 timestamp requests
//! - OIDC provider URLs for authentication
//!
//! # Example
//!
//! ```no_run
//! use sigstore_trust_root::SigningConfig;
//!
//! # async fn example() -> Result<(), sigstore_trust_root::Error> {
//! // Fetch production signing config via TUF (recommended)
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
//! For offline use:
//!
//! ```
//! use sigstore_trust_root::{SigningConfig, SIGSTORE_PRODUCTION_SIGNING_CONFIG};
//!
//! // Load embedded config (may be stale)
//! let config = SigningConfig::from_json(SIGSTORE_PRODUCTION_SIGNING_CONFIG).unwrap();
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Embedded production signing config
pub const SIGSTORE_PRODUCTION_SIGNING_CONFIG: &str =
    include_str!("../repository/signing_config.json");

/// Embedded staging signing config
pub const SIGSTORE_STAGING_SIGNING_CONFIG: &str =
    include_str!("../repository/signing_config_staging.json");

/// Supported Rekor API versions
pub const SUPPORTED_REKOR_VERSIONS: &[u32] = &[1, 2];

/// Supported TSA API versions
pub const SUPPORTED_TSA_VERSIONS: &[u32] = &[1];

/// Supported Fulcio API versions
pub const SUPPORTED_FULCIO_VERSIONS: &[u32] = &[1];

/// Expected media type for signing config v0.2
pub const SIGNING_CONFIG_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.signingconfig.v0.2+json";

/// Validity period for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceValidityPeriod {
    /// Start time of validity
    pub start: DateTime<Utc>,
    /// End time of validity (optional, None means still valid)
    #[serde(default)]
    pub end: Option<DateTime<Utc>>,
}

impl ServiceValidityPeriod {
    /// Check if this period is currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        if now < self.start {
            return false;
        }
        if let Some(end) = self.end {
            if now >= end {
                return false;
            }
        }
        true
    }
}

/// A service endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpoint {
    /// URL of the service
    pub url: String,
    /// Major API version supported by this endpoint
    pub major_api_version: u32,
    /// Validity period for this endpoint
    pub valid_for: ServiceValidityPeriod,
    /// Operator of this service
    #[serde(default)]
    pub operator: Option<String>,
}

impl ServiceEndpoint {
    /// Check if this endpoint is currently valid
    pub fn is_valid(&self) -> bool {
        self.valid_for.is_valid()
    }
}

/// Service selector configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceSelector {
    /// Use any available service
    #[default]
    Any,
    /// Use exactly the specified number of services
    Exact,
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceConfiguration {
    /// How to select services
    #[serde(default)]
    pub selector: ServiceSelector,
    /// Number of services to use (for EXACT selector)
    #[serde(default)]
    pub count: Option<u32>,
}

/// Signing configuration for a Sigstore instance
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningConfig {
    /// Media type of this configuration
    pub media_type: String,
    /// Fulcio CA URLs
    #[serde(default)]
    pub ca_urls: Vec<ServiceEndpoint>,
    /// OIDC provider URLs
    #[serde(default)]
    pub oidc_urls: Vec<ServiceEndpoint>,
    /// Rekor transparency log URLs
    #[serde(default)]
    pub rekor_tlog_urls: Vec<ServiceEndpoint>,
    /// Timestamp authority URLs
    #[serde(default)]
    pub tsa_urls: Vec<ServiceEndpoint>,
    /// Rekor tlog configuration
    #[serde(default)]
    pub rekor_tlog_config: ServiceConfiguration,
    /// TSA configuration
    #[serde(default)]
    pub tsa_config: ServiceConfiguration,
}

impl SigningConfig {
    /// Parse signing config from JSON
    ///
    /// This parses a signing configuration from a JSON string. For offline use,
    /// you can pass the embedded constants directly:
    ///
    /// # Example
    ///
    /// ```
    /// use sigstore_trust_root::{SigningConfig, SIGSTORE_PRODUCTION_SIGNING_CONFIG};
    ///
    /// let config = SigningConfig::from_json(SIGSTORE_PRODUCTION_SIGNING_CONFIG).unwrap();
    /// if let Some(rekor) = config.get_rekor_url(None) {
    ///     println!("Rekor URL: {}", rekor.url);
    /// }
    /// ```
    ///
    /// For staging:
    ///
    /// ```
    /// use sigstore_trust_root::{SigningConfig, SIGSTORE_STAGING_SIGNING_CONFIG};
    ///
    /// let config = SigningConfig::from_json(SIGSTORE_STAGING_SIGNING_CONFIG).unwrap();
    /// ```
    pub fn from_json(json: &str) -> Result<Self> {
        let config: SigningConfig = serde_json::from_str(json)?;

        // Validate media type
        if config.media_type != SIGNING_CONFIG_MEDIA_TYPE {
            return Err(Error::UnsupportedMediaType(config.media_type));
        }

        Ok(config)
    }

    /// Parse signing config from a file
    pub fn from_file(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| Error::MissingField(format!("Failed to read file {}: {}", path, e)))?;
        Self::from_json(&json)
    }

    /// Get valid Rekor endpoints, optionally filtered by version
    ///
    /// If `force_version` is Some, only returns endpoints with that major version.
    /// Otherwise returns all valid endpoints for supported versions.
    ///
    /// Endpoints are sorted by version descending (highest first).
    pub fn get_rekor_urls(&self, force_version: Option<u32>) -> Vec<&ServiceEndpoint> {
        let mut endpoints: Vec<_> = self
            .rekor_tlog_urls
            .iter()
            .filter(|e| {
                // Must be valid
                if !e.is_valid() {
                    return false;
                }
                // Must be a supported version
                if !SUPPORTED_REKOR_VERSIONS.contains(&e.major_api_version) {
                    return false;
                }
                // If forcing a version, must match
                if let Some(v) = force_version {
                    return e.major_api_version == v;
                }
                true
            })
            .collect();

        // Sort by version descending (highest version first)
        endpoints.sort_by(|a, b| b.major_api_version.cmp(&a.major_api_version));
        endpoints
    }

    /// Get the best Rekor endpoint (highest version available)
    ///
    /// If `force_version` is Some, returns the first endpoint with that version.
    pub fn get_rekor_url(&self, force_version: Option<u32>) -> Option<&ServiceEndpoint> {
        self.get_rekor_urls(force_version).first().copied()
    }

    /// Get valid Fulcio endpoints
    pub fn get_fulcio_urls(&self) -> Vec<&ServiceEndpoint> {
        self.ca_urls
            .iter()
            .filter(|e| e.is_valid() && SUPPORTED_FULCIO_VERSIONS.contains(&e.major_api_version))
            .collect()
    }

    /// Get the best Fulcio endpoint
    pub fn get_fulcio_url(&self) -> Option<&ServiceEndpoint> {
        self.get_fulcio_urls().first().copied()
    }

    /// Get valid TSA endpoints
    pub fn get_tsa_urls(&self) -> Vec<&ServiceEndpoint> {
        self.tsa_urls
            .iter()
            .filter(|e| e.is_valid() && SUPPORTED_TSA_VERSIONS.contains(&e.major_api_version))
            .collect()
    }

    /// Get the best TSA endpoint
    pub fn get_tsa_url(&self) -> Option<&ServiceEndpoint> {
        self.get_tsa_urls().first().copied()
    }

    /// Get valid OIDC provider URLs
    pub fn get_oidc_urls(&self) -> Vec<&ServiceEndpoint> {
        self.oidc_urls.iter().filter(|e| e.is_valid()).collect()
    }

    /// Get the best OIDC provider URL
    pub fn get_oidc_url(&self) -> Option<&ServiceEndpoint> {
        self.get_oidc_urls().first().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_json_production() {
        let config = SigningConfig::from_json(SIGSTORE_PRODUCTION_SIGNING_CONFIG)
            .expect("Failed to parse production config");
        assert_eq!(config.media_type, SIGNING_CONFIG_MEDIA_TYPE);
        assert!(!config.ca_urls.is_empty());
        assert!(!config.rekor_tlog_urls.is_empty());
    }

    #[test]
    fn test_from_json_staging() {
        let config = SigningConfig::from_json(SIGSTORE_STAGING_SIGNING_CONFIG)
            .expect("Failed to parse staging config");
        assert_eq!(config.media_type, SIGNING_CONFIG_MEDIA_TYPE);
        assert!(!config.ca_urls.is_empty());
        assert!(!config.rekor_tlog_urls.is_empty());
    }

    #[test]
    fn test_get_rekor_url_highest_version() {
        let config = SigningConfig::from_json(SIGSTORE_STAGING_SIGNING_CONFIG)
            .expect("Failed to parse staging config");
        if let Some(rekor) = config.get_rekor_url(None) {
            // Staging should have V2 available
            println!("Best Rekor: {} v{}", rekor.url, rekor.major_api_version);
        }
    }

    #[test]
    fn test_get_rekor_url_force_version() {
        let config = SigningConfig::from_json(SIGSTORE_STAGING_SIGNING_CONFIG)
            .expect("Failed to parse staging config");

        // Force V1
        if let Some(rekor) = config.get_rekor_url(Some(1)) {
            assert_eq!(rekor.major_api_version, 1);
        }

        // Force V2
        if let Some(rekor) = config.get_rekor_url(Some(2)) {
            assert_eq!(rekor.major_api_version, 2);
        }
    }

    #[test]
    fn test_service_validity() {
        let valid_period = ServiceValidityPeriod {
            start: DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .into(),
            end: None,
        };
        assert!(valid_period.is_valid());

        let expired_period = ServiceValidityPeriod {
            start: DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .into(),
            end: Some(
                DateTime::parse_from_rfc3339("2021-01-01T00:00:00Z")
                    .unwrap()
                    .into(),
            ),
        };
        assert!(!expired_period.is_valid());
    }
}
