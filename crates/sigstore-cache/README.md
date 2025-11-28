# sigstore-cache

Flexible caching support for [sigstore-rust](https://github.com/sigstore/sigstore-rust) clients.

## Overview

This crate provides a pluggable caching mechanism for Sigstore operations. It allows caching of frequently-accessed resources like public keys, trust bundles, and configuration data to reduce network requests and improve performance.

## Features

- **Pluggable adapters**: Choose between filesystem, in-memory, or custom cache backends
- **TTL support**: Automatic expiration of cached entries
- **Platform-aware**: Default cache locations follow OS conventions
- **Thread-safe**: All adapters are safe for concurrent use

## Cache Adapters

| Adapter | Description | Use Case |
|---------|-------------|----------|
| `FileSystemCache` | Persistent disk-based cache | Production use, offline support |
| `InMemoryCache` | Fast in-process cache with TTL | High-performance, single-session |
| `NoCache` | No-op cache (disabled) | Testing, when caching is not desired |

## Cached Resources

| Resource | Default TTL | Description |
|----------|-------------|-------------|
| Rekor Public Key | 24 hours | Transparency log signing key |
| Rekor Log Info | 1 hour | Log tree size and root hash |
| Fulcio Trust Bundle | 24 hours | CA certificates |
| Fulcio Configuration | 7 days | OIDC issuer configuration |

## Usage

```rust
use sigstore_cache::{FileSystemCache, InMemoryCache, CacheAdapter, CacheKey};
use std::time::Duration;

// Filesystem cache (persistent)
let cache = FileSystemCache::default_location()?;

// Or in-memory cache (fast, non-persistent)
let cache = InMemoryCache::new();

// Store and retrieve values
cache.set(CacheKey::RekorPublicKey, b"key-data", Duration::from_secs(86400)).await?;
if let Some(data) = cache.get(CacheKey::RekorPublicKey).await? {
    println!("Got cached data");
}
```

### With Sigstore Clients

Enable the `cache` feature on the client crates:

```rust
use sigstore_cache::FileSystemCache;
use sigstore_fulcio::FulcioClient;
use sigstore_rekor::RekorClient;

let cache = FileSystemCache::default_location()?;

let fulcio = FulcioClient::builder("https://fulcio.sigstore.dev")
    .with_cache(cache.clone())
    .build();

let rekor = RekorClient::builder("https://rekor.sigstore.dev")
    .with_cache(cache)
    .build();
```

## Cache Locations

`FileSystemCache` uses platform-specific directories with URL-namespaced subdirectories:

- **Linux**: `~/.cache/sigstore-rust/<url-encoded-instance>/`
- **macOS**: `~/Library/Caches/dev.sigstore.sigstore-rust/<url-encoded-instance>/`
- **Windows**: `C:\Users\<User>\AppData\Local\sigstore\sigstore-rust\cache\<url-encoded-instance>\`

### Instance-Specific Caching

To prevent cache collisions between different Sigstore instances (e.g., production vs staging), use instance-specific caches:

```rust
use sigstore_cache::FileSystemCache;

// Production cache (uses https://sigstore.dev namespace)
let prod_cache = FileSystemCache::production()?;

// Staging cache (uses https://sigstage.dev namespace)
let staging_cache = FileSystemCache::staging()?;

// Custom instance
let custom_cache = FileSystemCache::for_instance("https://my-sigstore.example.com")?;
```

Using `default_location()` without URL namespacing is still available but not recommended if you use multiple instances.

## Custom Adapters

Implement the `CacheAdapter` trait for custom backends:

```rust
use sigstore_cache::{CacheAdapter, CacheKey, Result};
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;

struct MyCache;

impl CacheAdapter for MyCache {
    fn get(&self, key: CacheKey) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>> {
        Box::pin(async { Ok(None) })
    }

    fn set(&self, key: CacheKey, value: &[u8], ttl: Duration) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    fn remove(&self, key: CacheKey) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    fn clear(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}
```

## Related Crates

Used by:

- [`sigstore-fulcio`](../sigstore-fulcio) - Caches configuration and trust bundles
- [`sigstore-rekor`](../sigstore-rekor) - Caches public keys and log info

## License

BSD-3-Clause
