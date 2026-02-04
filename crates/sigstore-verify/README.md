# sigstore-verify

Sigstore signature verification for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides high-level APIs for verifying Sigstore signatures. It handles the complete verification flow: bundle parsing, certificate chain validation, signature verification, transparency log verification, and identity policy enforcement.

## Features

- **Bundle verification**: Verify standard Sigstore bundles
- **Certificate validation**: X.509 chain validation against Fulcio CA
- **Transparency log verification**: Checkpoint signatures, inclusion proofs, SETs
- **Timestamp verification**: RFC 3161 timestamp validation
- **Identity policies**: Verify signer identity claims (issuer, subject, etc.)

## Verification Steps

1. Parse and validate bundle structure
2. Verify certificate chain against trusted root
3. Verify signature over artifact
4. Verify transparency log entry (checkpoint, inclusion proof, or SET)
5. Verify timestamps if present
6. Check identity against policy (optional)

## Usage

```rust
use sigstore_verify::{verify, Verifier, VerificationPolicy};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Artifact, Bundle, Sha256Hash};

// Fetch trusted root via TUF (recommended - ensures up-to-date trust material)
let root = TrustedRoot::production().await?;
let bundle: Bundle = serde_json::from_str(bundle_json)?;
let policy = VerificationPolicy::default();

// Verify with raw artifact bytes
let artifact_bytes = b"hello world";
let result = verify(artifact_bytes.as_slice(), &bundle, &policy, &root)?;

// Or verify with pre-computed SHA-256 digest (useful for large files)
let digest = Sha256Hash::from_hex("b94d27b9...")?;
let result = verify(digest, &bundle, &policy, &root)?;

// Using the Verifier struct directly
let verifier = Verifier::new(&root);
let result = verifier.verify(artifact_bytes.as_slice(), &bundle, &policy)?;
```

## Verification Policies

```rust
use sigstore_verify::VerificationPolicy;

// Default policy (verify tlog, timestamps, and certificate chain)
let policy = VerificationPolicy::default();

// Require specific identity and issuer
let policy = VerificationPolicy::default()
    .require_identity("user@example.com")
    .require_issuer("https://accounts.google.com");

// Skip certain verifications (for testing only)
let policy = VerificationPolicy::default()
    .skip_tlog()
    .skip_certificate_chain();
```

## Related Crates

- [`sigstore-sign`](../sigstore-sign) - Create signatures to verify with this crate

## License

BSD-3-Clause
