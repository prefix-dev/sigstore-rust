# sigstore-oidc

OpenID Connect identity provider for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate handles OIDC (OpenID Connect) authentication for Sigstore's keyless signing flow. It supports obtaining identity tokens from various OIDC providers, which are then used to request short-lived signing certificates from Fulcio.

## Features

- **OAuth 2.0 Authorization Code Flow with PKCE**: Secure authentication via browser or out-of-band code entry
- **Browser auto-open** (requires `browser` feature): Automatically opens the browser for a seamless OAuth flow with local redirect server
- **Out-of-band fallback**: When the browser can't open (or `browser` feature is disabled), prompts the user to manually visit the URL and enter the verification code
- **Ambient credentials**: Automatic detection of CI/CD environment tokens
- **Token parsing**: OIDC token validation and claim extraction

## Cargo Features

- `browser` - Enables automatic browser opening during authentication. Adds the `open` dependency. Without this feature, OOB (out-of-band) mode is used.

## Ambient credential detection

Ambient OIDC credentials are detected in CI systems like GitHub: See [ambient-id](https://github.com/astral-sh/ambient-id) for a list of supported environments, and details for their use.

## Usage

```rust
use sigstore_oidc::{get_identity_token, IdentityToken};

// Opens browser (with `browser` feature) or prompts for manual code entry
let token = get_identity_token().await?;
```

The `sigstore-sign` crate provides end-to-end signing examples:

```sh
# Sign a blob
cargo run -p sigstore-sign --features browser --example sign_blob -- artifact.txt -o artifact.sigstore.json

# Sign a conda package attestation
cargo run -p sigstore-sign --features browser --example sign_attestation -- package.conda -o package.sigstore.json
```

The `sigstore-verify` crate provides verification examples:

```sh
# Verify a bundle
cargo run -p sigstore-verify --example verify_bundle -- artifact.txt artifact.sigstore.json

# Verify a conda package attestation
cargo run -p sigstore-verify --example verify_conda_attestation -- package.conda attestation.sigstore.json
```

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Obtains identity tokens for keyless signing
- [`sigstore-fulcio`](../sigstore-fulcio) - Uses tokens to request certificates

## License

BSD-3-Clause
