# sigstore-trust-root

Sigstore trusted root management and parsing for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate handles parsing and management of Sigstore trusted root bundles. The trusted root contains all cryptographic trust anchors needed for verification: Fulcio CA certificates, Rekor public keys, CT log keys, and TSA certificates.

## Features

- **Trusted root parsing**: Load and parse `trusted_root.json` files
- **TUF support**: Secure fetching via The Update Framework (enabled by default)
- **Embedded roots**: Built-in production and staging trust anchors for offline use
- **Key extraction**: Extract public keys and certificates for verification
- **Validity periods**: Time-based key and certificate validity checking
- **Custom TUF repos**: Support for custom TUF repository URLs

## Trust Anchors

| Component | Purpose |
|-----------|---------|
| Certificate Authorities | Fulcio CA certificates for signing certificate validation |
| Transparency Logs | Rekor public keys for log entry verification |
| CT Logs | Certificate Transparency log keys for SCT verification |
| Timestamp Authorities | TSA certificates for RFC 3161 timestamp verification |

## Usage

```rust
use sigstore_trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};

// Fetch via TUF (recommended - ensures up-to-date trust material)
let root = TrustedRoot::production().await?;

// Use embedded data (for offline use)
let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)?;

// Load from file
let root = TrustedRoot::from_file("trusted_root.json")?;
```

### Custom TUF Repository

```rust
use sigstore_trust_root::{TrustedRoot, TufConfig};

// Fetch from a custom TUF repository (e.g., for testing)
let config = TufConfig::custom(
    "https://sigstore.github.io/root-signing/",
    include_bytes!("path/to/root.json"),
);
let root = TrustedRoot::from_tuf(config).await?;
```

## Cargo Features

- `tuf` (default) - Enable TUF-based secure fetching of trusted roots

To opt out of TUF support:

```toml
[dependencies]
sigstore-trust-root = { version = "0.1", default-features = false }
```

## Related Crates

Used by:

- [`sigstore-verify`](../sigstore-verify) - Provides trust anchors for verification
- [`sigstore-sign`](../sigstore-sign) - Provides service endpoints

## License

BSD-3-Clause
