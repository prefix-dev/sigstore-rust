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
//! // Fetch trusted root via TUF from production Sigstore (recommended)
//! let root = TrustedRoot::production().await?;
//!
//! // Fetch signing config via TUF
//! let config = SigningConfig::production().await?;
//!
//! // Or from staging
//! let staging_root = TrustedRoot::staging().await?;
//! let staging_config = SigningConfig::staging().await?;
//! # Ok(())
//! # }
//! ```
//!
//! For custom TUF repositories:
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

use std::path::{Path, PathBuf};

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

/// Convert a URL to a safe directory name for caching
///
/// This encodes special characters to create a filesystem-safe name while
/// remaining human-readable.
fn url_to_dirname(url: &str) -> String {
    let mut result = String::with_capacity(url.len() * 3);
    for c in url.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => result.push(c),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

/// Configuration for TUF client
#[derive(Debug, Clone)]
pub struct TufConfig {
    /// Base URL for the TUF repository
    pub url: String,
    /// Path to local cache directory (optional, derived from URL if not set)
    pub cache_dir: Option<PathBuf>,
    /// Whether to disable local caching
    pub disable_cache: bool,
    /// Whether to use offline mode (no network, use cached/embedded data)
    pub offline: bool,
    /// Custom TUF root.json for bootstrapping trust (None = use embedded for known URLs)
    root_json: Option<Vec<u8>>,
}

impl Default for TufConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_TUF_URL.to_string(),
            cache_dir: None,
            disable_cache: false,
            offline: false,
            root_json: None,
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

    /// Create configuration for a custom TUF repository
    ///
    /// # Arguments
    ///
    /// * `url` - Base URL of the TUF repository
    /// * `root_json` - Contents of root.json for bootstrapping trust
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // For the root-signing test repository
    /// let config = TufConfig::custom(
    ///     "https://sigstore.github.io/root-signing/",
    ///     include_bytes!("path/to/root.json"),
    /// );
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom(url: impl Into<String>, root_json: impl AsRef<[u8]>) -> Self {
        Self {
            url: url.into(),
            cache_dir: None,
            disable_cache: false,
            offline: false,
            root_json: Some(root_json.as_ref().to_vec()),
        }
    }

    /// Create configuration for a custom TUF repository, loading root.json from a file
    ///
    /// # Arguments
    ///
    /// * `url` - Base URL of the TUF repository
    /// * `root_path` - Path to the root.json file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = TufConfig::custom_from_file(
    ///     "https://sigstore.github.io/root-signing/",
    ///     "path/to/root.json",
    /// )?;
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom_from_file(
        url: impl Into<String>,
        root_path: impl AsRef<Path>,
    ) -> std::io::Result<Self> {
        let root_json = std::fs::read(root_path)?;
        Ok(Self::custom(url, root_json))
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

    /// Get the TUF root.json bytes for this configuration
    ///
    /// Returns the custom root if set, otherwise returns the embedded root
    /// for known URLs (production/staging).
    ///
    /// # Panics
    ///
    /// Panics if no root.json is available for the configured URL.
    fn get_root_json(&self) -> &[u8] {
        if let Some(ref root) = self.root_json {
            return root.as_slice();
        }

        // Fall back to embedded roots for known URLs
        if self.url == DEFAULT_TUF_URL || self.url.starts_with(DEFAULT_TUF_URL) {
            PRODUCTION_TUF_ROOT
        } else if self.url == STAGING_TUF_URL || self.url.starts_with(STAGING_TUF_URL) {
            STAGING_TUF_ROOT
        } else {
            panic!(
                "No root.json provided for custom URL: {}. Use TufConfig::custom() to provide one.",
                self.url
            )
        }
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
    /// Embedded targets for offline fallback (target_name -> bytes)
    embedded_targets: &'static [(&'static str, &'static [u8])],
}

impl TufClient {
    /// Create a new TUF client with the given configuration
    ///
    /// Embedded fallback targets are automatically configured for known URLs
    /// (production and staging).
    fn new(config: TufConfig) -> Self {
        // Determine embedded targets based on URL for offline fallback
        let embedded_targets: &'static [(&'static str, &'static [u8])] =
            if config.url == DEFAULT_TUF_URL || config.url.starts_with(DEFAULT_TUF_URL) {
                &[
                    (TRUSTED_ROOT_TARGET, EMBEDDED_PRODUCTION_TRUSTED_ROOT),
                    (SIGNING_CONFIG_TARGET, EMBEDDED_PRODUCTION_SIGNING_CONFIG),
                ]
            } else if config.url == STAGING_TUF_URL || config.url.starts_with(STAGING_TUF_URL) {
                &[
                    (TRUSTED_ROOT_TARGET, EMBEDDED_STAGING_TRUSTED_ROOT),
                    (SIGNING_CONFIG_TARGET, EMBEDDED_STAGING_SIGNING_CONFIG),
                ]
            } else {
                // Custom URLs have no embedded fallback
                &[]
            };

        Self {
            config,
            embedded_targets,
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

        // Create repository loader with root.json
        let root_bytes = self.config.get_root_json().to_vec();
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
    ///
    /// Returns URL-namespaced cache directory to prevent collisions between
    /// different TUF repositories.
    fn get_cache_dir(&self) -> Result<PathBuf> {
        if let Some(ref dir) = self.config.cache_dir {
            return Ok(dir.clone());
        }

        // Use platform-specific cache directory with URL namespace
        let project_dirs = directories::ProjectDirs::from("dev", "sigstore", "sigstore-rust")
            .ok_or_else(|| Error::Tuf("Could not determine cache directory".into()))?;

        // Create URL-namespaced subdirectory
        let namespace = url_to_dirname(&self.config.url);
        Ok(project_dirs.cache_dir().join("tuf").join(namespace))
    }
}

impl TrustedRoot {
    /// Fetch the trusted root from Sigstore's production TUF repository
    ///
    /// This is the **recommended** way to get the trusted root for production use.
    /// It securely fetches the latest `trusted_root.json` using the TUF protocol,
    /// verifying all metadata signatures against the embedded root of trust.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::TrustedRoot;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let root = TrustedRoot::production().await?;
    /// println!("Loaded {} Rekor logs", root.tlogs.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn production() -> Result<Self> {
        Self::from_tuf(TufConfig::production()).await
    }

    /// Fetch the trusted root from Sigstore's staging TUF repository
    ///
    /// This is useful for testing against the staging Sigstore infrastructure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::TrustedRoot;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let root = TrustedRoot::staging().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn staging() -> Result<Self> {
        Self::from_tuf(TufConfig::staging()).await
    }

    /// Fetch the trusted root from a TUF repository with custom configuration
    ///
    /// This method allows fetching from custom TUF repositories or configuring
    /// advanced options like cache directory, offline mode, etc.
    ///
    /// # Example: Custom TUF Repository
    ///
    /// ```ignore
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // For the root-signing test repository
    /// let config = TufConfig::custom(
    ///     "https://sigstore.github.io/root-signing/",
    ///     include_bytes!("path/to/root.json"),
    /// );
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Example: Offline Mode
    ///
    /// ```no_run
    /// use sigstore_trust_root::{TrustedRoot, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // Use cached/embedded data only (no network)
    /// let config = TufConfig::production().offline();
    /// let root = TrustedRoot::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf(config: TufConfig) -> Result<Self> {
        let client = TufClient::new(config);
        let bytes = client.fetch_target(TRUSTED_ROOT_TARGET).await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in {}: {}", TRUSTED_ROOT_TARGET, e)))?;
        Self::from_json(&json)
    }
}

impl SigningConfig {
    /// Fetch the signing configuration from Sigstore's production TUF repository
    ///
    /// This is the **recommended** way to get the signing config for production use.
    /// It securely fetches the latest `signing_config.v0.2.json` using the TUF protocol,
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
    /// let config = SigningConfig::production().await?;
    /// if let Some(rekor) = config.get_rekor_url(None) {
    ///     println!("Rekor URL: {} (v{})", rekor.url, rekor.major_api_version);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn production() -> Result<Self> {
        Self::from_tuf(TufConfig::production()).await
    }

    /// Fetch the signing configuration from Sigstore's staging TUF repository
    ///
    /// This is useful for testing against the staging Sigstore infrastructure,
    /// which may have newer API versions (e.g., Rekor V2) available.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::SigningConfig;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let config = SigningConfig::staging().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn staging() -> Result<Self> {
        Self::from_tuf(TufConfig::staging()).await
    }

    /// Fetch the signing configuration from a TUF repository with custom configuration
    ///
    /// This method allows fetching from custom TUF repositories or configuring
    /// advanced options like cache directory, offline mode, etc.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::{SigningConfig, TufConfig};
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// // Use offline mode with cached data
    /// let config = TufConfig::production().offline();
    /// let signing_config = SigningConfig::from_tuf(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf(config: TufConfig) -> Result<Self> {
        let client = TufClient::new(config);
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
    fn test_url_to_dirname() {
        assert_eq!(
            url_to_dirname("https://tuf-repo-cdn.sigstore.dev"),
            "https%3A%2F%2Ftuf-repo-cdn.sigstore.dev"
        );
        assert_eq!(
            url_to_dirname("https://sigstore.github.io/root-signing/"),
            "https%3A%2F%2Fsigstore.github.io%2Froot-signing%2F"
        );
        // Alphanumeric and safe chars should pass through
        assert_eq!(url_to_dirname("abc-123_test.json"), "abc-123_test.json");
    }

    #[test]
    fn test_tuf_config_default() {
        let config = TufConfig::default();
        assert_eq!(config.url, DEFAULT_TUF_URL);
        assert!(config.cache_dir.is_none());
        assert!(!config.disable_cache);
        assert!(!config.offline);
        assert!(config.root_json.is_none());
    }

    #[test]
    fn test_tuf_config_staging() {
        let config = TufConfig::staging();
        assert_eq!(config.url, STAGING_TUF_URL);
    }

    #[test]
    fn test_tuf_config_custom() {
        let root_json = b"test root json";
        let config = TufConfig::custom("https://custom.tuf/", root_json);
        assert_eq!(config.url, "https://custom.tuf/");
        assert_eq!(config.root_json, Some(root_json.to_vec()));
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
    fn test_tuf_config_get_root_json_production() {
        let config = TufConfig::production();
        assert_eq!(config.get_root_json(), PRODUCTION_TUF_ROOT);
    }

    #[test]
    fn test_tuf_config_get_root_json_staging() {
        let config = TufConfig::staging();
        assert_eq!(config.get_root_json(), STAGING_TUF_ROOT);
    }

    #[test]
    fn test_tuf_config_get_root_json_custom() {
        let root_json = b"custom root";
        let config = TufConfig::custom("https://custom.tuf/", root_json);
        assert_eq!(config.get_root_json(), root_json);
    }

    #[test]
    #[should_panic(expected = "No root.json provided for custom URL")]
    fn test_tuf_config_get_root_json_unknown_url_panics() {
        let config = TufConfig {
            url: "https://unknown.tuf/".to_string(),
            cache_dir: None,
            disable_cache: false,
            offline: false,
            root_json: None,
        };
        let _ = config.get_root_json();
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
        // Use offline mode with cache disabled - should fall back to embedded data
        let config = TufConfig::production().offline().without_cache();
        let client = TufClient::new(config);

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
        let config = TufConfig::production().offline().without_cache();
        let client = TufClient::new(config);

        // Should fail for unknown target
        let result = client.fetch_target("unknown.json").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_custom_url_offline_fails_without_cache() {
        // Custom URLs have no embedded fallback
        let config = TufConfig::custom("https://custom.tuf/", b"root")
            .offline()
            .without_cache();
        let client = TufClient::new(config);

        // Should fail since there's no embedded data for custom URLs
        let result = client.fetch_target(TRUSTED_ROOT_TARGET).await;
        assert!(result.is_err());
    }
}
