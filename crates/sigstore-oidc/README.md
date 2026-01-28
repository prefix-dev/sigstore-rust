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

## Ambient credential detection

Ambient OIDC credentials are detected in CI systems like GitHub: See [ambient-id](https://github.com/astral-sh/ambient-id) for a list of supported environments, and details for their use.

## Usage

```rust
use sigstore_oidc::{get_identity_token, IdentityToken};

// Try ambient credentials first, fall back to interactive OAuth
let token = match IdentityToken::detect_ambient().await? {
    Some(token) => token,
    None => get_identity_token(|response| {
        println!("Visit {}, use code {}", response.verification_uri, response.user_code);
    }).await?,
};
```

With the `interactive` feature enabled:

```rust
use sigstore_oidc::get_interactive_token;

// Opens browser automatically, receives callback on local server
let token = get_interactive_token().await?;
```

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Obtains identity tokens for keyless signing
- [`sigstore-fulcio`](../sigstore-fulcio) - Uses tokens to request certificates

## License

BSD-3-Clause
