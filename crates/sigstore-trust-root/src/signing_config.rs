//! Signing configuration for Sigstore instances
//!
//! This module re-exports the official Sigstore protobuf types and provides
//! extension methods for selecting service endpoints.

use chrono::{DateTime, TimeZone, Utc};

use crate::{Error, Result};

// Re-export protobuf types
pub use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::{
    Service, ServiceConfiguration, ServiceSelector, SigningConfig,
};

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

/// Extension trait for Service with helper methods
pub trait ServiceExt {
    /// Check if this service is currently valid
    fn is_valid(&self) -> bool;

    /// Get the validity start time
    fn valid_from(&self) -> Option<DateTime<Utc>>;

    /// Get the validity end time
    fn valid_until(&self) -> Option<DateTime<Utc>>;
}

impl ServiceExt for Service {
    fn is_valid(&self) -> bool {
        let now = Utc::now();

        let Some(valid_for) = &self.valid_for else {
            return true;
        };

        // Check start time
        if let Some(start) = &valid_for.start {
            if let Some(start_dt) = Utc
                .timestamp_opt(start.seconds, start.nanos as u32)
                .single()
            {
                if now < start_dt {
                    return false;
                }
            }
        }

        // Check end time
        if let Some(end) = &valid_for.end {
            if let Some(end_dt) = Utc.timestamp_opt(end.seconds, end.nanos as u32).single() {
                if now >= end_dt {
                    return false;
                }
            }
        }

        true
    }

    fn valid_from(&self) -> Option<DateTime<Utc>> {
        self.valid_for.as_ref().and_then(|vf| {
            vf.start
                .as_ref()
                .and_then(|t| Utc.timestamp_opt(t.seconds, t.nanos as u32).single())
        })
    }

    fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.valid_for.as_ref().and_then(|vf| {
            vf.end
                .as_ref()
                .and_then(|t| Utc.timestamp_opt(t.seconds, t.nanos as u32).single())
        })
    }
}

/// Extension trait for SigningConfig with helper methods
pub trait SigningConfigExt {
    /// Parse signing config from JSON
    fn from_json(json: &str) -> Result<SigningConfig>;

    /// Parse signing config from a file
    fn from_file(path: &str) -> Result<SigningConfig>;

    /// Load the embedded production signing config
    fn production() -> Result<SigningConfig>;

    /// Load the embedded staging signing config
    fn staging() -> Result<SigningConfig>;

    /// Get valid Rekor endpoints, optionally filtered by version
    fn get_rekor_urls(&self, force_version: Option<u32>) -> Vec<&Service>;

    /// Get the best Rekor endpoint (highest version available)
    fn get_rekor_url(&self, force_version: Option<u32>) -> Option<&Service>;

    /// Get valid Fulcio endpoints
    fn get_fulcio_urls(&self) -> Vec<&Service>;

    /// Get the best Fulcio endpoint
    fn get_fulcio_url(&self) -> Option<&Service>;

    /// Get valid TSA endpoints
    fn get_tsa_urls(&self) -> Vec<&Service>;

    /// Get the best TSA endpoint
    fn get_tsa_url(&self) -> Option<&Service>;

    /// Get valid OIDC provider URLs
    fn get_oidc_urls(&self) -> Vec<&Service>;

    /// Get the best OIDC provider URL
    fn get_oidc_url(&self) -> Option<&Service>;
}

impl SigningConfigExt for SigningConfig {
    fn from_json(json: &str) -> Result<SigningConfig> {
        let config: SigningConfig = serde_json::from_str(json)?;

        // Validate media type
        if config.media_type != SIGNING_CONFIG_MEDIA_TYPE {
            return Err(Error::UnsupportedMediaType(config.media_type.clone()));
        }

        Ok(config)
    }

    fn from_file(path: &str) -> Result<SigningConfig> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| Error::MissingField(format!("Failed to read file {}: {}", path, e)))?;
        Self::from_json(&json)
    }

    fn production() -> Result<SigningConfig> {
        Self::from_json(SIGSTORE_PRODUCTION_SIGNING_CONFIG)
    }

    fn staging() -> Result<SigningConfig> {
        Self::from_json(SIGSTORE_STAGING_SIGNING_CONFIG)
    }

    fn get_rekor_urls(&self, force_version: Option<u32>) -> Vec<&Service> {
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

    fn get_rekor_url(&self, force_version: Option<u32>) -> Option<&Service> {
        self.get_rekor_urls(force_version).first().copied()
    }

    fn get_fulcio_urls(&self) -> Vec<&Service> {
        self.ca_urls
            .iter()
            .filter(|e| e.is_valid() && SUPPORTED_FULCIO_VERSIONS.contains(&e.major_api_version))
            .collect()
    }

    fn get_fulcio_url(&self) -> Option<&Service> {
        self.get_fulcio_urls().first().copied()
    }

    fn get_tsa_urls(&self) -> Vec<&Service> {
        self.tsa_urls
            .iter()
            .filter(|e| e.is_valid() && SUPPORTED_TSA_VERSIONS.contains(&e.major_api_version))
            .collect()
    }

    fn get_tsa_url(&self) -> Option<&Service> {
        self.get_tsa_urls().first().copied()
    }

    fn get_oidc_urls(&self) -> Vec<&Service> {
        self.oidc_urls.iter().filter(|e| e.is_valid()).collect()
    }

    fn get_oidc_url(&self) -> Option<&Service> {
        self.get_oidc_urls().first().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_production_signing_config() {
        let config = SigningConfig::production().expect("Failed to parse production config");
        assert_eq!(config.media_type, SIGNING_CONFIG_MEDIA_TYPE);
        assert!(!config.ca_urls.is_empty());
        assert!(!config.rekor_tlog_urls.is_empty());
    }

    #[test]
    fn test_parse_staging_signing_config() {
        let config = SigningConfig::staging().expect("Failed to parse staging config");
        assert_eq!(config.media_type, SIGNING_CONFIG_MEDIA_TYPE);
        assert!(!config.ca_urls.is_empty());
        assert!(!config.rekor_tlog_urls.is_empty());
    }

    #[test]
    fn test_get_rekor_url_highest_version() {
        let config = SigningConfig::staging().expect("Failed to parse staging config");
        if let Some(rekor) = config.get_rekor_url(None) {
            // Staging should have V2 available
            println!("Best Rekor: {} v{}", rekor.url, rekor.major_api_version);
        }
    }

    #[test]
    fn test_get_rekor_url_force_version() {
        let config = SigningConfig::staging().expect("Failed to parse staging config");

        // Force V1
        if let Some(rekor) = config.get_rekor_url(Some(1)) {
            assert_eq!(rekor.major_api_version, 1);
        }

        // Force V2
        if let Some(rekor) = config.get_rekor_url(Some(2)) {
            assert_eq!(rekor.major_api_version, 2);
        }
    }
}
