//! TUF client for fetching Sigstore trusted roots and signing configuration
//!
//! This module provides functionality to securely fetch trusted root configuration
//! and signing configuration from Sigstore's TUF repository using The Update Framework protocol.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_trust_root::{TrustedRoot, SigningConfig};
//!
//! # async fn example() -> Result<(), sigstore_trust_root::Error> {
//! // Fetch trusted root via TUF from production Sigstore
//! let root = TrustedRoot::from_tuf().await?;
//!
//! // Fetch signing config via TUF
//! let config = SigningConfig::from_tuf().await?;
//!
//! // Or from staging
//! let staging_root = TrustedRoot::from_tuf_staging().await?;
//! let staging_config = SigningConfig::from_tuf_staging().await?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;

use tough::{HttpTransport, IntoVec, RepositoryLoader, TargetName};
use url::Url;

use crate::{Error, Result, SigningConfig, TrustedRoot};

/// Default Sigstore production TUF repository URL
pub const DEFAULT_TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// Sigstore staging TUF repository URL
pub const STAGING_TUF_URL: &str = "https://tuf-repo-cdn.sigstage.dev";

/// Embedded root.json for production TUF instance (version 1, used to bootstrap trust)
pub const PRODUCTION_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_root.json");

/// Embedded root.json for staging TUF instance
pub const STAGING_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_staging_root.json");

/// TUF target name for trusted root
pub const TRUSTED_ROOT_TARGET: &str = "trusted_root.json";

/// TUF target name for signing configuration
pub const SIGNING_CONFIG_TARGET: &str = "signing_config.v0.2.json";

/// Configuration for TUF client
#[derive(Debug, Clone)]
pub struct TufConfig {
    /// Base URL for the TUF repository
    pub url: String,
    /// Path to local cache directory (optional)
    pub cache_dir: Option<PathBuf>,
    /// Whether to disable local caching
    pub disable_cache: bool,
    /// Whether to use offline mode (no network, use cached/embedded data)
    pub offline: bool,
}

impl Default for TufConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_TUF_URL.to_string(),
            cache_dir: None,
            disable_cache: false,
            offline: false,
        }
    }
}

impl TufConfig {
    /// Create configuration for production Sigstore instance
    pub fn production() -> Self {
        Self::default()
    }

    /// Create configuration for staging Sigstore instance
    pub fn staging() -> Self {
        Self {
            url: STAGING_TUF_URL.to_string(),
            ..Default::default()
        }
    }

    /// Set the cache directory
    pub fn with_cache_dir(mut self, path: PathBuf) -> Self {
        self.cache_dir = Some(path);
        self
    }

    /// Disable local caching
    pub fn without_cache(mut self) -> Self {
        self.disable_cache = true;
        self
    }

    /// Enable offline mode (skip network, use cached or embedded data)
    ///
    /// In offline mode:
    /// 1. First checks the local TUF cache for previously downloaded targets
    /// 2. Falls back to embedded data if cache is empty
    /// 3. No network requests are made
    ///
    /// **Warning**: Offline mode uses unverified cached data. The cached data
    /// was verified when originally downloaded, but freshness is not checked.
    pub fn offline(mut self) -> Self {
        self.offline = true;
        self
    }
}

/// Embedded production trusted root (same as SIGSTORE_PRODUCTION_TRUSTED_ROOT but as bytes)
const EMBEDDED_PRODUCTION_TRUSTED_ROOT: &[u8] = include_bytes!("trusted_root.json");

/// Embedded production signing config
const EMBEDDED_PRODUCTION_SIGNING_CONFIG: &[u8] =
    include_bytes!("../repository/signing_config.json");

/// Embedded staging trusted root (same as SIGSTORE_STAGING_TRUSTED_ROOT but as bytes)
const EMBEDDED_STAGING_TRUSTED_ROOT: &[u8] = include_bytes!("trusted_root_staging.json");

/// Embedded staging signing config
const EMBEDDED_STAGING_SIGNING_CONFIG: &[u8] =
    include_bytes!("../repository/signing_config_staging.json");

/// Internal TUF client for fetching targets
struct TufClient {
    config: TufConfig,
    root_json: &'static [u8],
    /// Embedded targets for offline fallback (target_name -> bytes)
    embedded_targets: &'static [(&'static str, &'static [u8])],
}

impl TufClient {
    /// Create a new client for production
    fn production() -> Self {
        Self {
            config: TufConfig::production(),
            root_json: PRODUCTION_TUF_ROOT,
            embedded_targets: &[
                (TRUSTED_ROOT_TARGET, EMBEDDED_PRODUCTION_TRUSTED_ROOT),
                (SIGNING_CONFIG_TARGET, EMBEDDED_PRODUCTION_SIGNING_CONFIG),
            ],
        }
    }

    /// Create a new client for staging
    fn staging() -> Self {
        Self {
            config: TufConfig::staging(),
            root_json: STAGING_TUF_ROOT,
            embedded_targets: &[
                (TRUSTED_ROOT_TARGET, EMBEDDED_STAGING_TRUSTED_ROOT),
                (SIGNING_CONFIG_TARGET, EMBEDDED_STAGING_SIGNING_CONFIG),
            ],
        }
    }

    /// Create a new client with custom configuration (no embedded fallback)
    fn new(config: TufConfig, root_json: &'static [u8]) -> Self {
        Self {
            config,
            root_json,
            embedded_targets: &[],
        }
    }

    /// Fetch a target file from the TUF repository
    ///
    /// In online mode: fetches via TUF protocol with verification
    /// In offline mode: returns cached data, falling back to embedded data
    async fn fetch_target(&self, target_name: &str) -> Result<Vec<u8>> {
        if self.config.offline {
            return self.fetch_target_offline(target_name).await;
        }

        // Online mode: use TUF protocol
        // Parse URLs
        let base_url = Url::parse(&self.config.url).map_err(|e| Error::Tuf(e.to_string()))?;
        let metadata_url = base_url.clone();
        let targets_url = base_url
            .join("targets/")
            .map_err(|e| Error::Tuf(e.to_string()))?;

        // Create repository loader with embedded root
        let root_bytes = self.root_json.to_vec();
        let mut loader = RepositoryLoader::new(&root_bytes, metadata_url, targets_url);

        // Use HTTP transport
        loader = loader.transport(HttpTransport::default());

        // Optionally set datastore for caching
        if !self.config.disable_cache {
            let cache_dir = self.get_cache_dir()?;
            tokio::fs::create_dir_all(&cache_dir)
                .await
                .map_err(|e| Error::Tuf(format!("Failed to create cache directory: {}", e)))?;
            loader = loader.datastore(cache_dir);
        }

        // Load the repository (fetches and verifies all metadata)
        let repo = loader
            .load()
            .await
            .map_err(|e| Error::Tuf(format!("TUF repository load failed: {}", e)))?;

        // Fetch the target
        let target = TargetName::new(target_name)
            .map_err(|e| Error::Tuf(format!("Invalid target name: {}", e)))?;
        let stream = repo
            .read_target(&target)
            .await
            .map_err(|e| Error::Tuf(format!("Failed to read target: {}", e)))?
            .ok_or_else(|| Error::Tuf(format!("Target not found: {}", target_name)))?;

        // Read all bytes from the stream
        let bytes = stream
            .into_vec()
            .await
            .map_err(|e| Error::Tuf(format!("Failed to read target contents: {}", e)))?;

        Ok(bytes)
    }

    /// Fetch target in offline mode (no network)
    ///
    /// Priority:
    /// 1. Check local TUF cache for previously downloaded target
    /// 2. Fall back to embedded data
    async fn fetch_target_offline(&self, target_name: &str) -> Result<Vec<u8>> {
        // Try to read from cache first
        if !self.config.disable_cache {
            if let Ok(cache_dir) = self.get_cache_dir() {
                let cached_path = cache_dir.join("targets").join(target_name);
                if let Ok(bytes) = tokio::fs::read(&cached_path).await {
                    return Ok(bytes);
                }
            }
        }

        // Fall back to embedded data
        for (name, data) in self.embedded_targets {
            if *name == target_name {
                return Ok(data.to_vec());
            }
        }

        Err(Error::Tuf(format!(
            "Target '{}' not found in cache or embedded data (offline mode)",
            target_name
        )))
    }

    /// Get the cache directory path
    fn get_cache_dir(&self) -> Result<PathBuf> {
        if let Some(ref dir) = self.config.cache_dir {
            return Ok(dir.clone());
        }

        // Use platform-specific cache directory
        let project_dirs = directories::ProjectDirs::from("dev", "sigstore", "sigstore-rust")
            .ok_or_else(|| Error::Tuf("Could not determine cache directory".into()))?;

        Ok(project_dirs.cache_dir().join("tuf"))
    }
}

impl TrustedRoot {
    /// Fetch the trusted root from Sigstore's production TUF repository
    ///
    /// This securely fetches the `trusted_root.json` using the TUF protocol,
    /// verifying all metadata signatures against the embedded root of trust.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::TrustedRoot;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let root = TrustedRoot::from_tuf().await?;
    /// println!("Loaded {} Rekor logs", root.tlogs.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf() -> Result<Self> {
        let client = TufClient::production();
        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in {}: {}", TRUSTED_ROOT_TARGET, e)))?;
        Self::from_json(&json)
    }

    /// Fetch the trusted root from Sigstore's staging TUF repository
    ///
    /// This is useful for testing against the staging Sigstore infrastructure.
    pub async fn from_tuf_staging() -> Result<Self> {
        let client = TufClient::staging();
        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in {}: {}", TRUSTED_ROOT_TARGET, e)))?;
        Self::from_json(&json)
    }

    /// Fetch the trusted root from a custom TUF repository
    ///
    /// # Arguments
    ///
    /// * `config` - TUF client configuration
    /// * `tuf_root` - The TUF root.json to use for bootstrapping trust
    pub async fn from_tuf_with_config(config: TufConfig, tuf_root: &'static [u8]) -> Result<Self> {
        let client = TufClient::new(config, tuf_root);
        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in {}: {}", TRUSTED_ROOT_TARGET, e)))?;
        Self::from_json(&json)
    }
}

impl SigningConfig {
    /// Fetch the signing configuration from Sigstore's production TUF repository
    ///
    /// This securely fetches the `signing_config.v0.2.json` using the TUF protocol,
    /// verifying all metadata signatures against the embedded root of trust.
    ///
    /// The signing config contains service endpoints for signing operations:
    /// - Fulcio CA URLs for certificate issuance
    /// - Rekor transparency log URLs (V1 and V2 endpoints)
    /// - TSA URLs for RFC 3161 timestamp requests
    /// - OIDC provider URLs for authentication
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::SigningConfig;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let config = SigningConfig::from_tuf().await?;
    /// if let Some(rekor) = config.get_rekor_url(None) {
    ///     println!("Rekor URL: {} (v{})", rekor.url, rekor.major_api_version);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf() -> Result<Self> {
        let client = TufClient::production();
        let bytes = client.fetch_target(SIGNING_CONFIG_TARGET).await?;
        let json = String::from_utf8(bytes).map_err(|e| {
            Error::Tuf(format!("Invalid UTF-8 in {}: {}", SIGNING_CONFIG_TARGET, e))
        })?;
        Self::from_json(&json)
    }

    /// Fetch the signing configuration from Sigstore's staging TUF repository
    ///
    /// This is useful for testing against the staging Sigstore infrastructure,
    /// which may have newer API versions (e.g., Rekor V2) available.
    pub async fn from_tuf_staging() -> Result<Self> {
        let client = TufClient::staging();
        let bytes = client.fetch_target(SIGNING_CONFIG_TARGET).await?;
        let json = String::from_utf8(bytes).map_err(|e| {
            Error::Tuf(format!("Invalid UTF-8 in {}: {}", SIGNING_CONFIG_TARGET, e))
        })?;
        Self::from_json(&json)
    }

    /// Fetch the signing configuration from a custom TUF repository
    ///
    /// # Arguments
    ///
    /// * `config` - TUF client configuration
    /// * `tuf_root` - The TUF root.json to use for bootstrapping trust
    pub async fn from_tuf_with_config(config: TufConfig, tuf_root: &'static [u8]) -> Result<Self> {
        let client = TufClient::new(config, tuf_root);
        let bytes = client.fetch_target(SIGNING_CONFIG_TARGET).await?;
        let json = String::from_utf8(bytes).map_err(|e| {
            Error::Tuf(format!("Invalid UTF-8 in {}: {}", SIGNING_CONFIG_TARGET, e))
        })?;
        Self::from_json(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuf_config_default() {
        let config = TufConfig::default();
        assert_eq!(config.url, DEFAULT_TUF_URL);
        assert!(config.cache_dir.is_none());
        assert!(!config.disable_cache);
        assert!(!config.offline);
    }

    #[test]
    fn test_tuf_config_staging() {
        let config = TufConfig::staging();
        assert_eq!(config.url, STAGING_TUF_URL);
    }

    #[test]
    fn test_tuf_config_builder() {
        let config = TufConfig::production()
            .with_cache_dir(PathBuf::from("/tmp/test"))
            .without_cache()
            .offline();
        assert!(config.disable_cache);
        assert!(config.offline);
        assert_eq!(config.cache_dir, Some(PathBuf::from("/tmp/test")));
    }

    #[test]
    fn test_embedded_tuf_roots_are_valid_json() {
        // Verify the embedded TUF roots are valid JSON
        let _: serde_json::Value =
            serde_json::from_slice(PRODUCTION_TUF_ROOT).expect("Invalid production TUF root");
        let _: serde_json::Value =
            serde_json::from_slice(STAGING_TUF_ROOT).expect("Invalid staging TUF root");
    }

    #[test]
    fn test_embedded_targets_are_valid() {
        // Verify embedded trusted roots can be parsed
        let _root: crate::TrustedRoot = serde_json::from_slice(EMBEDDED_PRODUCTION_TRUSTED_ROOT)
            .expect("Invalid production trusted root");
        let _root: crate::TrustedRoot = serde_json::from_slice(EMBEDDED_STAGING_TRUSTED_ROOT)
            .expect("Invalid staging trusted root");

        // Verify embedded signing configs can be parsed
        let _config: crate::SigningConfig =
            serde_json::from_slice(EMBEDDED_PRODUCTION_SIGNING_CONFIG)
                .expect("Invalid production signing config");
        let _config: crate::SigningConfig = serde_json::from_slice(EMBEDDED_STAGING_SIGNING_CONFIG)
            .expect("Invalid staging signing config");
    }

    #[tokio::test]
    async fn test_offline_mode_uses_embedded_data() {
        // Create a client in offline mode with cache disabled
        // This should fall back to embedded data
        let client = TufClient {
            config: TufConfig::production().offline().without_cache(),
            root_json: PRODUCTION_TUF_ROOT,
            embedded_targets: &[
                (TRUSTED_ROOT_TARGET, EMBEDDED_PRODUCTION_TRUSTED_ROOT),
                (SIGNING_CONFIG_TARGET, EMBEDDED_PRODUCTION_SIGNING_CONFIG),
            ],
        };

        // Should successfully return embedded trusted root
        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await.unwrap();
        assert!(!bytes.is_empty());
        let _root: crate::TrustedRoot = serde_json::from_slice(&bytes).unwrap();

        // Should successfully return embedded signing config
        let bytes = client.fetch_target(SIGNING_CONFIG_TARGET).await.unwrap();
        assert!(!bytes.is_empty());
        let _config: crate::SigningConfig = serde_json::from_slice(&bytes).unwrap();
    }

    #[tokio::test]
    async fn test_offline_mode_fails_for_unknown_target() {
        let client = TufClient {
            config: TufConfig::production().offline().without_cache(),
            root_json: PRODUCTION_TUF_ROOT,
            embedded_targets: &[], // No embedded data
        };

        // Should fail for unknown target
        let result = client.fetch_target("unknown.json").await;
        assert!(result.is_err());
    }
}
