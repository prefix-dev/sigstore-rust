//! Flexible caching support for Sigstore clients
//!
//! This crate provides a pluggable caching mechanism for Sigstore operations.
//! It allows users to choose between different caching strategies:
//!
//! - [`FileSystemCache`]: Persistent cache stored on disk (default location or custom)
//! - [`InMemoryCache`]: Fast in-process cache with TTL support
//! - [`NoCache`]: Disabled caching (for testing or when caching is not desired)
//!
//! # Example
//!
//! ```no_run
//! use sigstore_cache::{FileSystemCache, CacheAdapter, CacheKey};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), sigstore_cache::Error> {
//! // Use default cache location (~/.cache/sigstore-rust/)
//! let cache = FileSystemCache::default_location()?;
//!
//! // Or specify a custom directory
//! let cache = FileSystemCache::new("/tmp/my-cache")?;
//!
//! // Store a value with TTL
//! cache.set(CacheKey::RekorPublicKey, b"public-key-data", Duration::from_secs(86400)).await?;
//!
//! // Retrieve the value
//! if let Some(data) = cache.get(CacheKey::RekorPublicKey).await? {
//!     println!("Got cached data: {} bytes", data.len());
//! }
//! # Ok(())
//! # }
//! ```

mod error;
mod filesystem;
mod memory;
mod noop;

pub use error::{Error, Result};
pub use filesystem::{FileSystemCache, SIGSTORE_PRODUCTION_URL, SIGSTORE_STAGING_URL};
pub use memory::InMemoryCache;
pub use noop::NoCache;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Cache keys for different Sigstore resources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheKey {
    /// Rekor transparency log public key
    RekorPublicKey,
    /// Rekor log info (tree size, root hash)
    RekorLogInfo,
    /// Fulcio trust bundle (CA certificates)
    FulcioTrustBundle,
    /// Fulcio OIDC configuration
    FulcioConfiguration,
    /// Trusted root from TUF
    TrustedRoot,
}

impl CacheKey {
    /// Get the string representation used for file names
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheKey::RekorPublicKey => "rekor_public_key",
            CacheKey::RekorLogInfo => "rekor_log_info",
            CacheKey::FulcioTrustBundle => "fulcio_trust_bundle",
            CacheKey::FulcioConfiguration => "fulcio_configuration",
            CacheKey::TrustedRoot => "trusted_root",
        }
    }

    /// Get the recommended TTL for this cache key
    pub fn default_ttl(&self) -> Duration {
        match self {
            // Keys/certs rotate infrequently
            CacheKey::RekorPublicKey => Duration::from_secs(24 * 60 * 60), // 24 hours
            CacheKey::FulcioTrustBundle => Duration::from_secs(24 * 60 * 60), // 24 hours
            CacheKey::TrustedRoot => Duration::from_secs(24 * 60 * 60),    // 24 hours
            // OIDC config is very stable
            CacheKey::FulcioConfiguration => Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            // Log info changes more frequently
            CacheKey::RekorLogInfo => Duration::from_secs(60 * 60), // 1 hour
        }
    }
}

/// Trait for cache adapters
///
/// This trait defines the interface for caching operations. Implementations
/// can provide different storage backends (filesystem, memory, etc.) while
/// maintaining the same API.
pub trait CacheAdapter: Send + Sync {
    /// Get a cached value by key
    ///
    /// Returns `Ok(Some(data))` if the key exists and hasn't expired,
    /// `Ok(None)` if the key doesn't exist or has expired,
    /// or `Err(...)` on I/O or other errors.
    fn get(
        &self,
        key: CacheKey,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>>;

    /// Set a cached value with a TTL
    ///
    /// The value will be considered expired after `ttl` has elapsed.
    fn set(
        &self,
        key: CacheKey,
        value: &[u8],
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Remove a cached value
    fn remove(&self, key: CacheKey) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Clear all cached values
    fn clear(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// Extension trait providing convenience methods for caching
pub trait CacheAdapterExt: CacheAdapter {
    /// Get a cached value, or compute and cache it if not present
    fn get_or_set<'a, F, Fut>(
        &'a self,
        key: CacheKey,
        ttl: Duration,
        compute: F,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>
    where
        F: FnOnce() -> Fut + Send + 'a,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'a,
    {
        Box::pin(async move {
            // Try to get from cache first
            if let Some(cached) = self.get(key).await? {
                return Ok(cached);
            }

            // Compute the value
            let value = compute().await?;

            // Store in cache (ignore errors - caching is best-effort)
            let _ = self.set(key, &value, ttl).await;

            Ok(value)
        })
    }

    /// Get a cached value using the key's default TTL for caching
    fn get_or_set_default<'a, F, Fut>(
        &'a self,
        key: CacheKey,
        compute: F,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>
    where
        F: FnOnce() -> Fut + Send + 'a,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'a,
    {
        self.get_or_set(key, key.default_ttl(), compute)
    }
}

// Implement CacheAdapterExt for all CacheAdapter implementations
impl<T: CacheAdapter + ?Sized> CacheAdapterExt for T {}

// Also implement CacheAdapter for Arc<T> where T: CacheAdapter
impl<T: CacheAdapter + ?Sized> CacheAdapter for Arc<T> {
    fn get(
        &self,
        key: CacheKey,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>> {
        (**self).get(key)
    }

    fn set(
        &self,
        key: CacheKey,
        value: &[u8],
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        (**self).set(key, value, ttl)
    }

    fn remove(&self, key: CacheKey) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        (**self).remove(key)
    }

    fn clear(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        (**self).clear()
    }
}

// Implement CacheAdapter for Box<dyn CacheAdapter>
impl CacheAdapter for Box<dyn CacheAdapter> {
    fn get(
        &self,
        key: CacheKey,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>> {
        (**self).get(key)
    }

    fn set(
        &self,
        key: CacheKey,
        value: &[u8],
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        (**self).set(key, value, ttl)
    }

    fn remove(&self, key: CacheKey) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        (**self).remove(key)
    }

    fn clear(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        (**self).clear()
    }
}

/// Get the default cache directory for sigstore-rust
///
/// This returns the platform-specific cache directory:
/// - Linux: `~/.cache/sigstore-rust/`
/// - macOS: `~/Library/Caches/dev.sigstore.sigstore-rust/`
/// - Windows: `C:\Users\<User>\AppData\Local\sigstore\sigstore-rust\cache\`
pub fn default_cache_dir() -> Result<std::path::PathBuf> {
    let project_dirs = directories::ProjectDirs::from("dev", "sigstore", "sigstore-rust")
        .ok_or_else(|| Error::Io("Could not determine cache directory".into()))?;
    Ok(project_dirs.cache_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_as_str() {
        assert_eq!(CacheKey::RekorPublicKey.as_str(), "rekor_public_key");
        assert_eq!(CacheKey::FulcioTrustBundle.as_str(), "fulcio_trust_bundle");
    }

    #[test]
    fn test_cache_key_default_ttl() {
        // Just verify they return reasonable values
        assert!(CacheKey::RekorPublicKey.default_ttl().as_secs() > 0);
        assert!(CacheKey::FulcioConfiguration.default_ttl().as_secs() > 0);
    }
}
