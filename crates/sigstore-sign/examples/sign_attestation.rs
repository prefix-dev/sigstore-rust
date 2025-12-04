//! Example: Sign a conda package attestation with Sigstore
//!
//! This example demonstrates how to create an in-toto attestation for a conda package
//! using Sigstore's keyless signing, similar to what GitHub Actions produces.
//!
//! # Usage
//!
//! Sign a conda package (interactive OAuth flow):
//! ```sh
//! cargo run -p sigstore-sign --example sign_attestation -- \
//!     package.conda -o package.sigstore.json
//! ```
//!
//! Sign with an identity token (e.g., from GitHub Actions):
//! ```sh
//! cargo run -p sigstore-sign --example sign_attestation -- \
//!     --token "$OIDC_TOKEN" \
//!     package.conda -o package.sigstore.json
//! ```
//!
//! # In GitHub Actions
//!
//! ```yaml
//! jobs:
//!   sign:
//!     runs-on: ubuntu-latest
//!     permissions:
//!       id-token: write  # Required for OIDC token
//!     steps:
//!       - uses: actions/checkout@v4
//!       - name: Sign package
//!         run: cargo run -p sigstore-sign --example sign_attestation -- package.conda
//! ```
//!
//! # Example with test data
//!
//! ```sh
//! cargo run -p sigstore-sign --example sign_attestation -- \
//!     crates/sigstore-verify/test_data/bundles/signed-package-2.1.0-hb0f4dca_0.conda
//! ```

use sigstore_oidc::{get_ambient_token, get_identity_token, is_ci_environment, IdentityToken};
use sigstore_sign::{Attestation, SigningConfig, SigningContext};

use std::env;
use std::fs;
use std::path::Path;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut token: Option<String> = None;
    let mut output: Option<String> = None;
    let mut staging = false;
    let mut channel: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--token" | "-t" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --token requires a value");
                    process::exit(1);
                }
                token = Some(args[i].clone());
            }
            "--output" | "-o" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --output requires a value");
                    process::exit(1);
                }
                output = Some(args[i].clone());
            }
            "--channel" | "-c" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --channel requires a value");
                    process::exit(1);
                }
                channel = Some(args[i].clone());
            }
            "--staging" => {
                staging = true;
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

    if positional.len() != 1 {
        eprintln!("Error: Expected exactly 1 positional argument (package path)");
        print_usage(&args[0]);
        process::exit(1);
    }

    let package_path = &positional[0];
    let output_path = output.unwrap_or_else(|| format!("{}.sigstore.json", package_path));
    let target_channel = channel.unwrap_or_else(|| "https://example.com/my-channel".to_string());

    // Read package
    let package_bytes = match fs::read(package_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading package '{}': {}", package_path, e);
            process::exit(1);
        }
    };

    // Get package filename
    let package_name = Path::new(package_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(package_path);

    println!("Creating attestation for: {}", package_path);
    println!("  Package: {}", package_name);
    println!("  Size: {} bytes", package_bytes.len());

    // Compute package hash
    let package_hash = sigstore_crypto::sha256(&package_bytes);
    println!("  SHA256: {}", hex::encode(package_hash.as_bytes()));

    // Get identity token
    let identity_token = match get_token(token).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error obtaining identity token: {}", e);
            process::exit(1);
        }
    };

    println!("  Identity: {}", identity_token.subject());
    println!("  Issuer: {}", identity_token.issuer());

    // Get signing config
    let config = if staging {
        println!("  Using: staging infrastructure");
        SigningConfig::staging()
    } else {
        println!("  Using: production infrastructure");
        SigningConfig::production()
    };

    println!("  Fulcio URL: {}", config.fulcio_url);
    println!("  Rekor URL: {}", config.rekor_url);
    if let Some(ref tsa_url) = config.tsa_url {
        println!("  TSA URL: {}", tsa_url);
    }

    // Create attestation using the high-level API
    let predicate = serde_json::json!({
        "targetChannel": target_channel
    });

    let attestation = Attestation::new(
        "https://schemas.conda.org/attestations-publish-1.schema.json",
        predicate,
    )
    .add_subject(package_name, package_hash);

    println!("\nIn-Toto Statement:");
    println!("  Type: https://in-toto.io/Statement/v1");
    println!("  Predicate Type: https://schemas.conda.org/attestations-publish-1.schema.json");
    println!(
        "  Subject: {} (sha256:{}...)",
        package_name,
        &hex::encode(package_hash.as_bytes())[..16]
    );

    // Create signing context and sign
    let context = SigningContext::with_config(config);
    let signer = context.signer(identity_token);

    println!("\nSigning attestation...");
    let bundle = match signer.sign_attestation(attestation).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error signing attestation: {}", e);
            process::exit(1);
        }
    };

    // Write bundle
    let bundle_json = bundle.to_json_pretty().expect("Failed to serialize bundle");
    fs::write(&output_path, &bundle_json).expect("Failed to write bundle");

    println!("\nAttestation created successfully!");
    println!("  Bundle: {}", output_path);
    println!("  Media Type: {}", bundle.media_type);

    // Print tlog entry info
    if let Some(entry) = bundle.verification_material.tlog_entries.first() {
        println!(
            "  Entry Kind: {} v{}",
            entry.kind_version.kind, entry.kind_version.version
        );
        println!("  Log Index: {}", entry.log_index);
        let ts = entry.integrated_time;
        if ts == 0 {
            println!("  Integrated Time: (uses RFC3161 timestamps)");
        } else {
            use chrono::{DateTime, Utc};
            if let Some(dt) = DateTime::<Utc>::from_timestamp(ts, 0) {
                println!("  Integrated Time: {}", dt);
            }
        }
    }

    // Print RFC3161 timestamp info
    let ts_count = bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
        .len();
    if ts_count > 0 {
        println!("  RFC3161 Timestamps: {}", ts_count);
    }

    println!("\nVerify with:");
    println!(
        "  cargo run -p sigstore-verify --example verify_conda_attestation -- {} {}",
        package_path, output_path
    );
}

async fn get_token(explicit_token: Option<String>) -> Result<IdentityToken, String> {
    if let Some(token_str) = explicit_token {
        return IdentityToken::from_jwt(&token_str).map_err(|e| format!("Invalid token: {}", e));
    }

    if is_ci_environment() {
        println!("  Detected CI environment, using ambient credentials");
        return get_ambient_token()
            .await
            .map_err(|e| format!("Failed to get ambient token: {}", e));
    }

    println!("  Starting interactive authentication...");
    println!();

    get_identity_token(|response| {
        println!("Please visit: {}", response.verification_uri);
        if let Some(complete_uri) = &response.verification_uri_complete {
            println!("Or open: {}", complete_uri);
        }
        println!();
        println!("Enter code: {}", response.user_code);
        println!();
        println!("Waiting for authentication...");
    })
    .await
    .map_err(|e| format!("OAuth failed: {}", e))
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [OPTIONS] <PACKAGE>", program);
    eprintln!();
    eprintln!("Create a Sigstore attestation for a conda package.");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <PACKAGE>            Path to the .conda package file");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --output <FILE>  Output bundle path (default: <package>.sigstore.json)");
    eprintln!("  -t, --token <TOKEN>  OIDC identity token (skips interactive auth)");
    eprintln!("  -c, --channel <URL>  Target channel URL for the attestation");
    eprintln!("      --staging        Use Sigstore staging infrastructure");
    eprintln!("  -h, --help           Print this help message");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Sign interactively (opens browser for OAuth)");
    eprintln!("  {} package.conda", program);
    eprintln!();
    eprintln!("  # Sign with explicit output path");
    eprintln!(
        "  {} package.conda -o my-attestation.sigstore.json",
        program
    );
    eprintln!();
    eprintln!("  # Sign with a pre-obtained token");
    eprintln!("  {} --token \"$OIDC_TOKEN\" package.conda", program);
}
