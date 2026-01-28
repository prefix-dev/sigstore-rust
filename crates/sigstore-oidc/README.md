# sigstore-oidc

OpenID Connect identity provider for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate handles OIDC (OpenID Connect) authentication for Sigstore's keyless signing flow. It supports obtaining identity tokens from various OIDC providers, which are then used to request short-lived signing certificates from Fulcio.

## Features

- **Interactive browser authentication** (requires `interactive` feature): Opens browser automatically for seamless OAuth flow with local redirect server
- **OAuth 2.0 device flow**: Interactive authentication without extra dependencies
- **Ambient credentials**: Automatic detection of CI/CD environment tokens
- **Token parsing**: OIDC token validation and claim extraction
- **Multiple providers**: Support for various identity providers

## Cargo Features

- `interactive` - Enables browser-based authentication with auto-open and local redirect server. Adds the `open` dependency.

## Supported Environments

Ambient credential detection works in:

- GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_TOKEN`)
- GitLab CI (`SIGSTORE_ID_TOKEN`)
- Google Cloud (Workload Identity)
- Generic OIDC token files

## Usage

```rust
use sigstore_oidc::{get_ambient_token, is_ci_environment};

// In CI environments, use ambient credentials
if is_ci_environment() {
    let token = get_ambient_token().await?;
}
```

With the `interactive` feature enabled:

```rust
use sigstore_oidc::get_interactive_token;

// Opens browser automatically, receives callback on local server
let token = get_interactive_token().await?;
```

Without the `interactive` feature (device code flow):

```rust
use sigstore_oidc::get_identity_token;

// User manually enters code shown on screen
let token = get_identity_token(|response| {
    println!("Visit: {}", response.verification_uri);
    println!("Enter code: {}", response.user_code);
}).await?;
```

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Obtains identity tokens for keyless signing
- [`sigstore-fulcio`](../sigstore-fulcio) - Uses tokens to request certificates

## License

BSD-3-Clause
