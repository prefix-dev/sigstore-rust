//! File system based cache implementation

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{default_cache_dir, CacheAdapter, CacheKey, Result};

/// Convert a URL to a safe directory name
///
/// This URL-encodes the URL to create a safe filesystem path, similar to
/// how sigstore-python handles TUF repository URLs.
///
/// # Example
/// ```ignore
/// url_to_dirname("https://sigstore.dev") // -> "https%3A%2F%2Fsigstore.dev"
/// ```
fn url_to_dirname(url: &str) -> String {
    // URL-encode the URL to make it safe for use as a directory name
    // We encode everything except alphanumerics and some safe chars
    let mut result = String::with_capacity(url.len() * 3);
    for c in url.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => {
                result.push(c);
            }
            _ => {
                // Percent-encode other characters
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

/// Metadata stored alongside cached values
#[derive(Debug, Serialize, Deserialize)]
struct CacheMetadata {
    /// When the cache entry was created
    created_at: DateTime<Utc>,
    /// When the cache entry expires
    expires_at: DateTime<Utc>,
}

/// File system based cache
///
/// Stores cached values as files on disk. Each cache key maps to a file,
/// with a companion metadata file tracking expiration.
///
/// # Directory Structure
///
/// ```text
/// cache_dir/
/// ├── rekor_public_key.cache
/// ├── rekor_public_key.meta
/// ├── fulcio_trust_bundle.cache
/// ├── fulcio_trust_bundle.meta
/// └── ...
/// ```
///
/// # Example
///
/// ```no_run
/// use sigstore_cache::{FileSystemCache, CacheAdapter, CacheKey};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), sigstore_cache::Error> {
/// // Use default location
/// let cache = FileSystemCache::default_location()?;
///
/// // Or specify custom directory
/// let cache = FileSystemCache::new("/tmp/my-sigstore-cache")?;
///
/// // Cache a value
/// cache.set(
///     CacheKey::RekorPublicKey,
///     b"public-key-data",
///     Duration::from_secs(86400)
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct FileSystemCache {
    /// Base directory for cache files
    cache_dir: PathBuf,
}

/// Sigstore production instance base URL
pub const SIGSTORE_PRODUCTION_URL: &str = "https://sigstore.dev";

/// Sigstore staging instance base URL
pub const SIGSTORE_STAGING_URL: &str = "https://sigstage.dev";

impl FileSystemCache {
    /// Create a new file system cache at the specified directory
    ///
    /// The directory will be created if it doesn't exist when writing.
    pub fn new(cache_dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
        })
    }

    /// Create a cache at the default platform-specific location
    ///
    /// See [`default_cache_dir`] for the exact locations.
    ///
    /// **Warning**: This cache is not namespaced by instance URL. If you use
    /// multiple Sigstore instances (e.g., production and staging), use
    /// [`FileSystemCache::for_instance`] instead to avoid cache collisions.
    pub fn default_location() -> Result<Self> {
        Self::new(default_cache_dir()?)
    }

    /// Create a cache namespaced to a specific Sigstore instance URL
    ///
    /// This creates a subdirectory based on the URL, preventing cache collisions
    /// when using multiple Sigstore instances (e.g., production vs staging).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_cache::FileSystemCache;
    ///
    /// # fn example() -> Result<(), sigstore_cache::Error> {
    /// // Cache for production instance
    /// let prod_cache = FileSystemCache::for_instance("https://sigstore.dev")?;
    ///
    /// // Cache for staging instance (separate directory)
    /// let staging_cache = FileSystemCache::for_instance("https://sigstage.dev")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn for_instance(base_url: &str) -> Result<Self> {
        let namespace = url_to_dirname(base_url);
        let path = default_cache_dir()?.join(namespace);
        Self::new(path)
    }

    /// Create a cache for the Sigstore production instance
    ///
    /// Equivalent to `FileSystemCache::for_instance("https://sigstore.dev")`.
    pub fn production() -> Result<Self> {
        Self::for_instance(SIGSTORE_PRODUCTION_URL)
    }

    /// Create a cache for the Sigstore staging instance
    ///
    /// Equivalent to `FileSystemCache::for_instance("https://sigstage.dev")`.
    pub fn staging() -> Result<Self> {
        Self::for_instance(SIGSTORE_STAGING_URL)
    }

    /// Get the path for a cache file
    fn cache_path(&self, key: CacheKey) -> PathBuf {
        self.cache_dir.join(format!("{}.cache", key.as_str()))
    }

    /// Get the path for a metadata file
    fn meta_path(&self, key: CacheKey) -> PathBuf {
        self.cache_dir.join(format!("{}.meta", key.as_str()))
    }

    /// Ensure the cache directory exists
    async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.cache_dir).await?;
        Ok(())
    }

    /// Read and validate metadata, returning None if expired or missing
    async fn read_valid_metadata(&self, key: CacheKey) -> Result<Option<CacheMetadata>> {
        let meta_path = self.meta_path(key);

        match fs::read_to_string(&meta_path).await {
            Ok(content) => {
                let metadata: CacheMetadata = serde_json::from_str(&content)?;
                if Utc::now() < metadata.expires_at {
                    Ok(Some(metadata))
                } else {
                    // Expired - clean up
                    let _ = self.remove(key).await;
                    Ok(None)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

impl CacheAdapter for FileSystemCache {
    fn get(
        &self,
        key: CacheKey,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>>> + Send + '_>> {
        Box::pin(async move {
            // Check if metadata exists and is valid
            if self.read_valid_metadata(key).await?.is_none() {
                return Ok(None);
            }

            // Read the cached data
            let cache_path = self.cache_path(key);
            match fs::read(&cache_path).await {
                Ok(data) => Ok(Some(data)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn set(
        &self,
        key: CacheKey,
        value: &[u8],
        ttl: Duration,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        let value = value.to_vec();
        Box::pin(async move {
            self.ensure_dir().await?;

            let now = Utc::now();
            let metadata = CacheMetadata {
                created_at: now,
                expires_at: now
                    + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::days(1)),
            };

            // Write metadata first (atomic-ish - if this fails, cache entry is invalid)
            let meta_path = self.meta_path(key);
            let meta_json = serde_json::to_string_pretty(&metadata)?;
            fs::write(&meta_path, meta_json).await?;

            // Write the actual data
            let cache_path = self.cache_path(key);
            fs::write(&cache_path, &value).await?;

            Ok(())
        })
    }

    fn remove(
        &self,
        key: CacheKey,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let cache_path = self.cache_path(key);
            let meta_path = self.meta_path(key);

            // Ignore errors - files might not exist
            let _ = fs::remove_file(&cache_path).await;
            let _ = fs::remove_file(&meta_path).await;

            Ok(())
        })
    }

    fn clear(&self) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            // Remove all .cache and .meta files in the cache directory
            let mut entries = match fs::read_dir(&self.cache_dir).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "cache" || ext == "meta" {
                        let _ = fs::remove_file(&path).await;
                    }
                }
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_filesystem_cache_roundtrip() {
        let temp_dir = std::env::temp_dir().join("sigstore-cache-test");
        let cache = FileSystemCache::new(&temp_dir).unwrap();

        // Clean up from previous runs
        let _ = cache.clear().await;

        let key = CacheKey::RekorPublicKey;
        let value = b"test-public-key-data";

        // Initially empty
        assert!(cache.get(key).await.unwrap().is_none());

        // Set and get
        cache
            .set(key, value, Duration::from_secs(3600))
            .await
            .unwrap();
        let retrieved = cache.get(key).await.unwrap().unwrap();
        assert_eq!(retrieved, value);

        // Remove
        cache.remove(key).await.unwrap();
        assert!(cache.get(key).await.unwrap().is_none());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_filesystem_cache_expiration() {
        let temp_dir = std::env::temp_dir().join("sigstore-cache-expiry-test");
        let cache = FileSystemCache::new(&temp_dir).unwrap();
        let _ = cache.clear().await;

        let key = CacheKey::FulcioConfiguration;
        let value = b"test-config";

        // Set with very short TTL (already expired)
        cache.set(key, value, Duration::from_secs(0)).await.unwrap();

        // Should be expired
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(cache.get(key).await.unwrap().is_none());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_url_to_dirname() {
        // Basic URL encoding
        assert_eq!(
            url_to_dirname("https://sigstore.dev"),
            "https%3A%2F%2Fsigstore.dev"
        );
        assert_eq!(
            url_to_dirname("https://sigstage.dev"),
            "https%3A%2F%2Fsigstage.dev"
        );

        // URLs with paths
        assert_eq!(
            url_to_dirname("https://example.com/path/to/resource"),
            "https%3A%2F%2Fexample.com%2Fpath%2Fto%2Fresource"
        );

        // URLs with ports
        assert_eq!(
            url_to_dirname("https://localhost:8080"),
            "https%3A%2F%2Flocalhost%3A8080"
        );

        // Safe characters should not be encoded
        assert_eq!(url_to_dirname("abc-123_test.txt"), "abc-123_test.txt");
    }

    #[test]
    fn test_production_and_staging_paths_differ() {
        let prod = FileSystemCache::production().unwrap();
        let staging = FileSystemCache::staging().unwrap();

        // Production and staging should have different cache directories
        assert_ne!(prod.cache_dir, staging.cache_dir);

        // Both should contain URL-encoded paths
        assert!(prod
            .cache_dir
            .to_string_lossy()
            .contains("https%3A%2F%2Fsigstore.dev"));
        assert!(staging
            .cache_dir
            .to_string_lossy()
            .contains("https%3A%2F%2Fsigstage.dev"));
    }
}
