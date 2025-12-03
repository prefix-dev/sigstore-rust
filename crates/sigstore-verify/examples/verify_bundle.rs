//! Example: Verify a Sigstore bundle
//!
//! This example demonstrates how to verify a Sigstore bundle against an artifact.
//!
//! # Usage
//!
//! Verify a local bundle:
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- artifact.txt artifact.sigstore.json
//! ```
//!
//! Verify with identity requirements:
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- \
//!     --certificate-identity "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0" \
//!     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
//!     artifact.txt artifact.sigstore.json
//! ```
//!
//! Verify with regex matching (cosign-compatible):
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- \
//!     --certificate-identity-regexp ".*" \
//!     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
//!     artifact.txt artifact.sigstore.json
//! ```
//!
//! Verify using digest instead of file:
//! ```sh
//! cargo run -p sigstore-verify --example verify_bundle -- \
//!     --certificate-identity-regexp ".*" \
//!     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
//!     sha256:abc123... bundle.sigstore.json
//! ```
//!
//! # Getting a bundle from GitHub
//!
//! You can download attestation bundles from GitHub releases using the GitHub CLI:
//! ```sh
//! # Download attestation for a release artifact
//! gh attestation download <artifact-url> -o bundle.sigstore.json
//!
//! # Or verify directly with gh (uses sigstore under the hood)
//! gh attestation verify <artifact> --owner <owner>
//! ```

use regex::Regex;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Artifact, Bundle, Sha256Hash};
use sigstore_verify::{verify, VerificationPolicy};

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut identity: Option<String> = None;
    let mut identity_regexp: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--identity" | "-i" | "--certificate-identity" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --certificate-identity requires a value");
                    process::exit(1);
                }
                identity = Some(args[i].clone());
            }
            "--certificate-identity-regexp" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --certificate-identity-regexp requires a value");
                    process::exit(1);
                }
                identity_regexp = Some(args[i].clone());
            }
            "--issuer" | "-o" | "--certificate-oidc-issuer" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --certificate-oidc-issuer requires a value");
                    process::exit(1);
                }
                issuer = Some(args[i].clone());
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                process::exit(0);
            }
            arg if !arg.starts_with('-') => {
                positional.push(arg.to_string());
            }
            unknown => {
                eprintln!("Error: Unknown option: {}", unknown);
                print_usage(&args[0]);
                process::exit(1);
            }
        }
        i += 1;
    }

    if positional.len() != 2 {
        eprintln!("Error: Expected exactly 2 positional arguments (artifact/digest and bundle)");
        print_usage(&args[0]);
        process::exit(1);
    }

    let artifact_or_digest = &positional[0];
    let bundle_path = &positional[1];

    // Check if artifact is a digest (sha256:...)
    let is_digest = artifact_or_digest.starts_with("sha256:");

    // Read bundle
    let bundle_json = match fs::read_to_string(bundle_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading bundle '{}': {}", bundle_path, e);
            process::exit(1);
        }
    };

    // Parse bundle
    let bundle = match Bundle::from_json(&bundle_json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error parsing bundle: {}", e);
            process::exit(1);
        }
    };

    // Load trusted root (production Sigstore infrastructure)
    let trusted_root = match TrustedRoot::production() {
        Ok(root) => root,
        Err(e) => {
            eprintln!("Error loading trusted root: {}", e);
            process::exit(1);
        }
    };

    // Build verification policy
    let mut policy = VerificationPolicy::default();
    if let Some(id) = &identity {
        policy = policy.require_identity(id);
    }
    if let Some(iss) = &issuer {
        policy = policy.require_issuer(iss);
    }

    // Print bundle info
    println!("Verifying bundle...");
    if is_digest {
        println!("  Digest: {}", artifact_or_digest);
    } else {
        println!("  Artifact: {}", artifact_or_digest);
    }
    println!("  Bundle: {}", bundle_path);
    println!("  Media Type: {}", bundle.media_type);
    if let Ok(v) = bundle.version() {
        println!("  Version: {:?}", v);
    }
    if let Some(id) = &identity {
        println!("  Required Identity: {}", id);
    }
    if let Some(re) = &identity_regexp {
        println!("  Required Identity Regexp: {}", re);
    }
    if let Some(iss) = &issuer {
        println!("  Required Issuer: {}", iss);
    }

    // Verify
    let result = if is_digest {
        // Parse digest (sha256:hex...)
        let hex_digest = artifact_or_digest.strip_prefix("sha256:").unwrap();
        let digest = match Sha256Hash::from_hex(hex_digest) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error parsing digest: {}", e);
                process::exit(1);
            }
        };
        let artifact = Artifact::from(digest);
        verify(artifact, &bundle, &policy, &trusted_root)
    } else {
        // Read artifact file
        let artifact_bytes = match fs::read(artifact_or_digest) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading artifact '{}': {}", artifact_or_digest, e);
                process::exit(1);
            }
        };
        verify(&artifact_bytes, &bundle, &policy, &trusted_root)
    };

    match result {
        Ok(result) => {
            // Check identity regexp if provided
            if let Some(re_str) = &identity_regexp {
                let re = match Regex::new(re_str) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Error compiling identity regexp: {}", e);
                        process::exit(1);
                    }
                };
                if let Some(id) = &result.identity {
                    if !re.is_match(id) {
                        eprintln!("\nVerification: FAILED");
                        eprintln!("  Identity '{}' does not match regexp '{}'", id, re_str);
                        process::exit(1);
                    }
                } else {
                    eprintln!("\nVerification: FAILED");
                    eprintln!("  No identity found in certificate");
                    process::exit(1);
                }
            }

            if result.success {
                println!("\nVerification: SUCCESS");
                if let Some(id) = &result.identity {
                    println!("  Identity: {}", id);
                }
                if let Some(iss) = &result.issuer {
                    println!("  Issuer: {}", iss);
                }
                if let Some(time) = result.integrated_time {
                    use chrono::{DateTime, Utc};
                    if let Some(dt) = DateTime::<Utc>::from_timestamp(time, 0) {
                        println!("  Signed at: {}", dt);
                    }
                }
                for warning in &result.warnings {
                    println!("  Warning: {}", warning);
                }
                process::exit(0);
            } else {
                eprintln!("\nVerification: FAILED");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("\nVerification error: {}", e);
            process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [OPTIONS] <ARTIFACT|DIGEST> <BUNDLE>", program);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <ARTIFACT|DIGEST>  Path to artifact file OR sha256:hex digest");
    eprintln!("  <BUNDLE>           Path to the Sigstore bundle (.sigstore.json)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --certificate-identity <ID>        Required certificate identity (exact match)");
    eprintln!("  --certificate-identity-regexp <RE> Required certificate identity (regex)");
    eprintln!("  --certificate-oidc-issuer <ISSUER> Required OIDC issuer");
    eprintln!("  -h, --help                         Print this help message");
    eprintln!();
    eprintln!("Aliases (for backwards compatibility):");
    eprintln!("  -i, --identity  Same as --certificate-identity");
    eprintln!("  -o, --issuer    Same as --certificate-oidc-issuer");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Verify a bundle");
    eprintln!("  {} artifact.txt artifact.sigstore.json", program);
    eprintln!();
    eprintln!("  # Verify with identity regex (cosign-compatible)");
    eprintln!("  {} --certificate-identity-regexp \".*\" \\", program);
    eprintln!("      --certificate-oidc-issuer https://token.actions.githubusercontent.com \\");
    eprintln!("      artifact.txt artifact.sigstore.json");
    eprintln!();
    eprintln!("  # Verify using digest instead of file");
    eprintln!("  {} --certificate-identity-regexp \".*\" \\", program);
    eprintln!("      --certificate-oidc-issuer https://token.actions.githubusercontent.com \\");
    eprintln!("      sha256:abc123def456... bundle.sigstore.json");
    eprintln!();
    eprintln!("Getting bundles from GitHub:");
    eprintln!("  gh attestation download <artifact-url> -o bundle.sigstore.json");
}
