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
//!     --identity "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0" \
//!     --issuer "https://token.actions.githubusercontent.com" \
//!     artifact.txt artifact.sigstore.json
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

use sigstore_bundle::Bundle;
use sigstore_trust_root::TrustedRoot;
use sigstore_verify::{verify, VerificationPolicy};

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut identity: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--identity" | "-i" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --identity requires a value");
                    process::exit(1);
                }
                identity = Some(args[i].clone());
            }
            "--issuer" | "-o" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --issuer requires a value");
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
        eprintln!("Error: Expected exactly 2 positional arguments (artifact and bundle)");
        print_usage(&args[0]);
        process::exit(1);
    }

    let artifact_path = &positional[0];
    let bundle_path = &positional[1];

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
    println!("  Artifact: {}", artifact_path);
    println!("  Bundle: {}", bundle_path);
    println!("  Media Type: {}", bundle.media_type());
    if let Ok(v) = bundle.version() {
        println!("  Version: {:?}", v);
    }
    if let Some(id) = &identity {
        println!("  Required Identity: {}", id);
    }
    if let Some(iss) = &issuer {
        println!("  Required Issuer: {}", iss);
    }

    // Verify
    match verify(&artifact, &bundle, &policy, &trusted_root) {
        Ok(result) => {
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
    eprintln!("Usage: {} [OPTIONS] <ARTIFACT> <BUNDLE>", program);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <ARTIFACT>    Path to the artifact file to verify");
    eprintln!("  <BUNDLE>      Path to the Sigstore bundle (.sigstore.json)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -i, --identity <IDENTITY>  Required certificate identity (SAN)");
    eprintln!("  -o, --issuer <ISSUER>      Required OIDC issuer");
    eprintln!("  -h, --help                 Print this help message");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Verify a bundle");
    eprintln!("  {} artifact.txt artifact.sigstore.json", program);
    eprintln!();
    eprintln!("  # Verify with identity requirements (for GitHub Actions)");
    eprintln!(
        "  {} --identity https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0 \\",
        program
    );
    eprintln!("      --issuer https://token.actions.githubusercontent.com \\");
    eprintln!("      artifact.txt artifact.sigstore.json");
    eprintln!();
    eprintln!("Getting bundles from GitHub:");
    eprintln!("  # Download attestation bundle for a GitHub release artifact");
    eprintln!("  gh attestation download <artifact-url> -o bundle.sigstore.json");
}
