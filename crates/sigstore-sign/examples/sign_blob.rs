//! Example: Sign a blob with Sigstore
//!
//! This example demonstrates how to sign an artifact using Sigstore's keyless signing.
//!
//! # Usage
//!
//! Sign a file (interactive OAuth flow):
//! ```sh
//! cargo run -p sigstore-sign --example sign_blob -- artifact.txt -o artifact.sigstore.json
//! ```
//!
//! Sign with an identity token (e.g., from GitHub Actions):
//! ```sh
//! cargo run -p sigstore-sign --example sign_blob -- \
//!     --token "$OIDC_TOKEN" \
//!     artifact.txt -o artifact.sigstore.json
//! ```
//!
//! Use Rekor V2 API (when available):
//! ```sh
//! cargo run -p sigstore-sign --example sign_blob -- --v2 artifact.txt
//! ```
//!
//! # In GitHub Actions
//!
//! The example will automatically detect GitHub Actions and use ambient credentials:
//! ```yaml
//! jobs:
//!   sign:
//!     runs-on: ubuntu-latest
//!     permissions:
//!       id-token: write  # Required for OIDC token
//!     steps:
//!       - uses: actions/checkout@v4
//!       - name: Sign artifact
//!         run: cargo run -p sigstore-sign --example sign_blob -- artifact.txt -o artifact.sigstore.json
//! ```

use sigstore_oidc::{get_identity_token, IdentityToken};
use sigstore_rekor::RekorApiVersion;
use sigstore_sign::{SigningConfig, SigningContext};

use std::env;
use std::fs;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut token: Option<String> = None;
    let mut output: Option<String> = None;
    let mut staging = false;
    let mut use_v2 = false;
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
            "--staging" => {
                staging = true;
            }
            "--v2" => {
                use_v2 = true;
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
        eprintln!("Error: Expected exactly 1 positional argument (artifact path)");
        print_usage(&args[0]);
        process::exit(1);
    }

    let artifact_path = &positional[0];
    let output_path = output.unwrap_or_else(|| format!("{}.sigstore.json", artifact_path));

    // Read artifact
    let artifact = match fs::read(artifact_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading artifact '{}': {}", artifact_path, e);
            process::exit(1);
        }
    };

    println!("Signing artifact: {}", artifact_path);
    println!("  Size: {} bytes", artifact.len());

    // Get identity token
    let identity_token = match get_token(token).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error obtaining identity token: {}", e);
            process::exit(1);
        }
    };

    // Print token info
    println!("  Identity: {}", identity_token.subject());
    if let Some(email) = identity_token.email() {
        println!("  Email: {}", email);
    }
    println!("  Issuer: {}", identity_token.issuer());

    // Create signing context with appropriate API version
    let base_config = if staging {
        println!("  Using: staging infrastructure");
        SigningConfig::staging()
    } else {
        println!("  Using: production infrastructure");
        SigningConfig::production()
    };

    let config = if use_v2 {
        base_config.with_rekor_version(RekorApiVersion::V2)
    } else {
        base_config
    };

    println!("  Rekor API: {:?}", config.rekor_api_version);
    println!("  Rekor URL: {}", config.rekor_url);
    if let Some(ref tsa_url) = config.tsa_url {
        println!("  TSA URL: {}", tsa_url);
    } else {
        println!("  TSA URL: (none)");
    }

    let context = SigningContext::with_config(config);

    // Create signer and sign
    let signer = context.signer(identity_token);

    println!("\nSigning...");
    let bundle = match signer.sign(&artifact).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error signing artifact: {}", e);
            process::exit(1);
        }
    };

    // Write bundle
    let bundle_json = match bundle.to_json_pretty() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error serializing bundle: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = fs::write(&output_path, &bundle_json) {
        eprintln!("Error writing bundle to '{}': {}", output_path, e);
        process::exit(1);
    }

    println!("\nSignature created successfully!");
    println!("  Bundle: {}", output_path);
    println!("  Media Type: {}", bundle.media_type);

    // Print tlog entry info
    if let Some(entry) = bundle.verification_material.tlog_entries.first() {
        println!(
            "  Entry Kind: {} v{}",
            entry.kind_version.kind, entry.kind_version.version
        );
        println!("  Log Index: {}", entry.log_index);
        // For V2, integrated_time is always 0 - RFC3161 timestamps are used instead
        let ts = entry.integrated_time;
        if ts == 0 && entry.kind_version.version == "0.0.2" {
            println!("  Integrated Time: (V2 uses RFC3161 timestamps)");
        } else {
            use chrono::{DateTime, Utc};
            if let Some(dt) = DateTime::<Utc>::from_timestamp(ts, 0) {
                println!("  Integrated Time: {}", dt);
            }
        }
        // Show if we have inclusion proof (V2) vs just promise (V1)
        if entry.inclusion_proof.is_some() {
            println!("  Inclusion Proof: yes (with checkpoint)");
        } else if entry.inclusion_promise.is_some() {
            println!("  Inclusion Promise: yes (SET)");
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
    } else {
        println!("  RFC3161 Timestamps: none (V2 bundles require timestamps!)");
    }

    println!("\nVerify with:");
    println!(
        "  cargo run -p sigstore-verify --example verify_bundle -- {} {}",
        artifact_path, output_path
    );
}

async fn get_token(explicit_token: Option<String>) -> Result<IdentityToken, String> {
    // 1. Use explicit token if provided
    if let Some(token_str) = explicit_token {
        return IdentityToken::from_jwt(&token_str).map_err(|e| format!("Invalid token: {}", e));
    }

    // 2. Try ambient credentials (CI/CD environments)
    if let Some(token) = IdentityToken::detect_ambient()
        .await
        .map_err(|e| e.to_string())?
    {
        println!("  Detected CI environment, using ambient credentials");
        return Ok(token);
    }

    // 3. Fall back to interactive OAuth device code flow
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
    eprintln!("Usage: {} [OPTIONS] <ARTIFACT>", program);
    eprintln!();
    eprintln!("Sign an artifact using Sigstore keyless signing.");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <ARTIFACT>           Path to the artifact file to sign");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --output <FILE>  Output bundle path (default: <artifact>.sigstore.json)");
    eprintln!("  -t, --token <TOKEN>  OIDC identity token (skips interactive auth)");
    eprintln!("      --staging        Use Sigstore staging infrastructure");
    eprintln!("      --v2             Use Rekor V2 API (uses log2025-1.rekor.sigstore.dev)");
    eprintln!("  -h, --help           Print this help message");
    eprintln!();
    eprintln!("By default, Rekor V1 API is used (rekor.sigstore.dev).");
    eprintln!("Use --v2 to use the new Rekor V2 API with inclusion proofs and checkpoints.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Sign interactively (opens browser for OAuth)");
    eprintln!("  {} artifact.txt", program);
    eprintln!();
    eprintln!("  # Sign with explicit output path");
    eprintln!("  {} artifact.txt -o my-bundle.sigstore.json", program);
    eprintln!();
    eprintln!("  # Sign with a pre-obtained token");
    eprintln!("  {} --token \"$OIDC_TOKEN\" artifact.txt", program);
    eprintln!();
    eprintln!("  # Sign using Rekor V2 API");
    eprintln!("  {} --v2 artifact.txt", program);
    eprintln!();
    eprintln!("In GitHub Actions:");
    eprintln!("  # Add 'id-token: write' permission, then run without --token");
    eprintln!("  # The example auto-detects GitHub Actions and uses ambient OIDC");
}
