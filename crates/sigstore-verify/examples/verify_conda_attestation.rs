//! Example: Verify a Conda package attestation from GitHub Actions
//!
//! This example demonstrates how to verify attestations for conda packages
//! produced by GitHub Actions workflows, showing both the signature verification
//! and the in-toto attestation contents.
//!
//! # Usage
//!
//! ```sh
//! # Download a conda package and its attestation from GitHub
//! gh run download <run-id> --repo <owner/repo>
//! gh attestation download <package.conda> --repo <owner/repo>
//!
//! # Verify the attestation
//! cargo run -p sigstore-verify --example verify_conda_attestation -- \
//!     package.conda attestation.sigstore.json
//! ```
//!
//! # Example with test data
//!
//! ```sh
//! cargo run -p sigstore-verify --example verify_conda_attestation -- \
//!     crates/sigstore-verify/test_data/bundles/signed-package-2.1.0-hb0f4dca_0.conda \
//!     crates/sigstore-verify/test_data/bundles/conda-attestation.sigstore.json
//! ```

use sigstore_trust_root::TrustedRoot;
use sigstore_types::{bundle::SignatureContent, Bundle};
use sigstore_verify::{verify, VerificationPolicy};

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <CONDA_PACKAGE> <ATTESTATION>", args[0]);
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  <CONDA_PACKAGE>  Path to the .conda package file");
        eprintln!("  <ATTESTATION>    Path to the attestation bundle (.sigstore.json)");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} package.conda attestation.sigstore.json", args[0]);
        process::exit(1);
    }

    let artifact_path = &args[1];
    let bundle_path = &args[2];

    // Read artifact
    let artifact = match fs::read(artifact_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading artifact '{}': {}", artifact_path, e);
            process::exit(1);
        }
    };

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

    // Print bundle info
    println!("Verifying conda package attestation...");
    println!();
    println!("Package: {}", artifact_path);
    println!("Bundle:  {}", bundle_path);
    println!("Media Type: {}", bundle.media_type);

    // Extract and display in-toto attestation info if present
    if let SignatureContent::DsseEnvelope(dsse) = &bundle.content {
        println!();
        println!("In-Toto Attestation:");
        println!("  Payload Type: {}", dsse.payload_type);

        // payload is already PayloadBytes
        if let Ok(payload_str) = std::str::from_utf8(dsse.payload.as_bytes()) {
            if let Ok(statement) = serde_json::from_str::<serde_json::Value>(payload_str) {
                if let Some(stmt_type) = statement.get("_type").and_then(|v| v.as_str()) {
                    println!("  Statement Type: {}", stmt_type);
                }
                if let Some(pred_type) = statement.get("predicateType").and_then(|v| v.as_str()) {
                    println!("  Predicate Type: {}", pred_type);
                }
                if let Some(subjects) = statement.get("subject").and_then(|v| v.as_array()) {
                    println!("  Subjects:");
                    for subject in subjects {
                        if let Some(name) = subject.get("name").and_then(|v| v.as_str()) {
                            println!("    - {}", name);
                            if let Some(digest) = subject.get("digest") {
                                if let Some(sha256) = digest.get("sha256").and_then(|v| v.as_str())
                                {
                                    println!("      sha256: {}", sha256);
                                }
                            }
                        }
                    }
                }
                if let Some(predicate) = statement.get("predicate") {
                    println!("  Predicate:");
                    if let Some(channel) = predicate.get("targetChannel").and_then(|v| v.as_str()) {
                        println!("    Target Channel: {}", channel);
                    }
                }
            }
        }
    }

    // Build verification policy - for GitHub Actions attestations, we expect
    // the identity to be the workflow file path and issuer to be GitHub
    let policy =
        VerificationPolicy::default().require_issuer("https://token.actions.githubusercontent.com");

    // Verify
    println!();
    match verify(&artifact, &bundle, &policy, &trusted_root) {
        Ok(result) => {
            if result.success {
                println!("Verification: SUCCESS");
                println!();
                println!("Certificate Details:");
                if let Some(id) = &result.identity {
                    println!("  Identity (SAN): {}", id);
                }
                if let Some(iss) = &result.issuer {
                    println!("  OIDC Issuer: {}", iss);
                }
                if let Some(time) = result.integrated_time {
                    use chrono::{DateTime, Utc};
                    if let Some(dt) = DateTime::<Utc>::from_timestamp(time, 0) {
                        println!("  Signed at: {}", dt);
                    }
                }
                for warning in &result.warnings {
                    println!();
                    println!("Warning: {}", warning);
                }
                process::exit(0);
            } else {
                eprintln!("Verification: FAILED");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Verification error: {}", e);
            process::exit(1);
        }
    }
}
