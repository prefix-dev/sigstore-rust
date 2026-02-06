# sigstore-rust

A Rust implementation of [Sigstore](https://sigstore.dev) for signing and verifying software artifacts.

## Overview

This workspace provides a modular Rust implementation of the Sigstore ecosystem, enabling keyless code signing and verification. Sigstore eliminates the need for long-lived signing keys by binding signatures to OpenID Connect identities and recording them in an immutable transparency log.

## Crates

| Crate | Description |
|-------|-------------|
| [`sigstore-sign`](crates/sigstore-sign) | High-level signing API |
| [`sigstore-verify`](crates/sigstore-verify) | High-level verification API |
| [`sigstore-bundle`](crates/sigstore-bundle) | Sigstore bundle format handling |
| [`sigstore-types`](crates/sigstore-types) | Core types and data structures |
| [`sigstore-crypto`](crates/sigstore-crypto) | Cryptographic primitives |
| [`sigstore-merkle`](crates/sigstore-merkle) | RFC 6962 Merkle tree verification |
| [`sigstore-rekor`](crates/sigstore-rekor) | Rekor transparency log client |
| [`sigstore-fulcio`](crates/sigstore-fulcio) | Fulcio certificate authority client |
| [`sigstore-oidc`](crates/sigstore-oidc) | OpenID Connect authentication |
| [`sigstore-tsa`](crates/sigstore-tsa) | RFC 3161 timestamp authority client |
| [`sigstore-trust-root`](crates/sigstore-trust-root) | Trusted root management |

## Installation

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
# For verification only
sigstore-verify = "0.1"
sigstore-trust-root = "0.1"

# For signing
sigstore-sign = "0.1"
```

## Usage

### Verifying a Signature

```rust
use sigstore_verify::{Verifier, VerificationPolicy};
use sigstore_trust_root::TrustedRoot;

// Load the trusted root (contains Fulcio CA, Rekor keys, etc.)
let root = TrustedRoot::production()?;
let verifier = Verifier::new(&root);

// Parse the bundle (contains signature, certificate, transparency log entry)
let bundle: sigstore_types::Bundle = serde_json::from_str(&bundle_json)?;

// Verify the signature
verifier.verify(&bundle, artifact_bytes)?;

// Or verify with identity policy
let policy = VerificationPolicy::new()
    .issuer("https://token.actions.githubusercontent.com")
    .subject_regex(r"^https://github\.com/myorg/.*$")?;

verifier.verify_with_policy(&bundle, artifact_bytes, &policy)?;
```

### Signing an Artifact

```rust
use sigstore_sign::{Signer, SigningConfig};

// Create a signer (will authenticate via OIDC)
let config = SigningConfig::production();
let signer = Signer::new(config).await?;

// Sign the artifact - returns a Sigstore bundle
let bundle = signer.sign(artifact_bytes).await?;

// Save the bundle
let bundle_json = serde_json::to_string_pretty(&bundle)?;
```

## Examples

### Sign and verify an artifact locally

```bash
# Sign the README.md file
cargo run -p sigstore-sign --features browser --example sign_blob -- README.md -o README.md.sigstore.json

# Verify with our tool
cargo run -p sigstore-verify --example verify_bundle -- README.md README.md.sigstore.json

# You can also verify with cosign
cosign verify-blob --bundle README.md.sigstore.json \
    --certificate-identity $INSERT_YOUR_EMAIL \
    --certificate-oidc-issuer https://github.com/login/oauth \
    README.md
```

### Verify a Bundle from GitHub

You can verify Sigstore bundles from GitHub releases:

```sh
# 1. Download a release artifact and its Sigstore bundle
curl -LO https://github.com/sigstore/cosign/releases/download/v3.0.2/cosign_checksums.txt
curl -LO https://github.com/sigstore/cosign/releases/download/v3.0.2/cosign_checksums.txt.sigstore.json

# 2. Verify the bundle (cryptographic verification without identity policy)
cargo run -p sigstore-verify --example verify_bundle -- \
    cosign_checksums.txt cosign_checksums.txt.sigstore.json

# 3. Or verify with identity policy (this release was signed with Google's keyless signer)
cargo run -p sigstore-verify --example verify_bundle -- \
    --identity "keyless@projectsigstore.iam.gserviceaccount.com" \
    --issuer "https://accounts.google.com" \
    cosign_checksums.txt cosign_checksums.txt.sigstore.json
```

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                            │
├────────────────────────┬────────────────────────────────────────┤
│     sigstore-sign      │           sigstore-verify              │
├────────────────────────┴────────────────────────────────────────┤
│                      sigstore-bundle                            │
├─────────────┬─────────────┬─────────────┬───────────────────────┤
│sigstore-oidc│sigstore-    │sigstore-    │  sigstore-trust-root  │
│             │fulcio       │rekor        │                       │
├─────────────┴──┬──────────┴────────┬────┴───────────────────────┤
│  sigstore-tsa  │  sigstore-merkle  │  sigstore-crypto           │
├────────────────┴─────────────────-─┴────────────────────────────┤
│                      sigstore-types                             │
└─────────────────────────────────────────────────────────────────┘
```

## How Sigstore Works

1. **Keyless Signing**: Instead of managing long-lived keys, signers authenticate with an OIDC provider (GitHub, Google, etc.)
2. **Short-lived Certificates**: Fulcio issues a certificate valid for ~10 minutes, binding the OIDC identity to an ephemeral key
3. **Transparency Log**: The signature is recorded in Rekor, providing a tamper-evident audit trail
4. **Verification**: Verifiers check the certificate chain, signature, and transparency log entry against the trusted root

## Features

- Full Sigstore bundle support (v0.1, v0.2, v0.3 formats)
- Keyless signing with OIDC authentication
- Certificate chain validation against Fulcio CA
- Transparency log verification (checkpoints, inclusion proofs, SETs)
- RFC 3161 timestamp support
- Identity-based verification policies
- Ambient credential detection for CI/CD environments

## Cryptography

This library uses [aws-lc-rs](https://github.com/aws/aws-lc-rs) as its cryptographic backend. AWS-LC is a general-purpose cryptographic library maintained by AWS, based on code from BoringSSL. It provides:

- ECDSA (P-256, P-384) signature verification and signing
- Ed25519 signature support
- SHA-256/SHA-384/SHA-512 hashing
- X.509 certificate parsing and validation

AWS-LC is [FIPS 140-3 validated](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4816), making this library suitable for environments with compliance requirements.

## Minimum Supported Rust Version

Rust 1.70 or later.

## License

BSD-3-Clause
