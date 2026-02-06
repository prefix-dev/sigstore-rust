//! Sigstore Conformance Client
//!
//! CLI implementation following the specification:
//! <https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md>
//!
//! This binary implements the conformance test protocol for Sigstore clients.

use sigstore_oidc::IdentityToken;
use sigstore_sign::{SigningConfig as SignerSigningConfig, SigningContext};
use sigstore_trust_root::{SigningConfig as TufSigningConfig, TrustedRoot};
use sigstore_types::{Bundle, Sha256Hash, SignatureContent};
use sigstore_verify::{verify, VerificationPolicy};

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }

    let command = &args[1];
    let result = match command.as_str() {
        "sign-bundle" => sign_bundle(&args[2..]),
        "verify-bundle" => verify_bundle(&args[2..]),
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage(&args[0]);
            process::exit(1);
        }
    };

    match result {
        Ok(()) => {
            eprintln!("Operation succeeded!");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Operation failed:\n{}", e);
            process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {} sign-bundle --identity-token TOKEN --bundle FILE [--in-toto] [--staging] [--trusted-root FILE] [--signing-config FILE] ARTIFACT", program);
    eprintln!("  {} verify-bundle --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--staging] [--trusted-root FILE] ARTIFACT_OR_DIGEST", program);
    eprintln!("  {} verify-bundle --bundle FILE --key KEY_FILE [--staging] [--trusted-root FILE] ARTIFACT_OR_DIGEST", program);
}

#[tokio::main]
async fn sign_bundle(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let mut identity_token: Option<String> = None;
    let mut bundle_path: Option<String> = None;
    let mut artifact_path: Option<String> = None;
    let mut staging = false;
    let mut _trusted_root: Option<String> = None;
    let mut _signing_config: Option<String> = None;
    let mut in_toto = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--identity-token" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --identity-token".into());
                }
                identity_token = Some(args[i].clone());
            }
            "--bundle" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --bundle".into());
                }
                bundle_path = Some(args[i].clone());
            }
            "--in-toto" => {
                in_toto = true;
            }
            "--staging" => {
                staging = true;
            }
            "--trusted-root" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --trusted-root".into());
                }
                _trusted_root = Some(args[i].clone());
            }
            "--signing-config" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --signing-config".into());
                }
                _signing_config = Some(args[i].clone());
            }
            arg if !arg.starts_with("--") => {
                artifact_path = Some(arg.to_string());
            }
            unknown => {
                return Err(format!("Unknown option: {}", unknown).into());
            }
        }
        i += 1;
    }

    let identity_token_str = identity_token.ok_or("Missing required --identity-token")?;
    let bundle_path = bundle_path.ok_or("Missing required --bundle")?;
    let artifact_path = artifact_path.ok_or("Missing artifact path")?;

    let signing_config = if let Some(config_path) = &_signing_config {
        let tuf_config = TufSigningConfig::from_file(config_path)?;
        SignerSigningConfig::from_tuf_config(&tuf_config)
    } else if staging {
        SignerSigningConfig::staging()
    } else {
        SignerSigningConfig::production()
    };

    let context = SigningContext::with_config(signing_config);
    let identity_token = IdentityToken::from_jwt(&identity_token_str)?;
    let signer = context.signer(identity_token);

    // Read artifact
    let artifact_data = fs::read(&artifact_path)?;

    // Sign and get bundle
    let bundle = if in_toto {
        signer.sign_raw_statement(&artifact_data).await?
    } else {
        signer.sign(artifact_data.as_slice()).await?
    };

    // Write bundle
    let bundle_json = bundle.to_json_pretty()?;
    fs::write(&bundle_path, bundle_json)?;

    Ok(())
}

fn verify_bundle(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let mut bundle_path: Option<String> = None;
    let mut certificate_identity: Option<String> = None;
    let mut certificate_oidc_issuer: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut artifact_or_digest: Option<String> = None;
    let mut _staging = false;
    let mut trusted_root_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --bundle".into());
                }
                bundle_path = Some(args[i].clone());
            }
            "--certificate-identity" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --certificate-identity".into());
                }
                certificate_identity = Some(args[i].clone());
            }
            "--certificate-oidc-issuer" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --certificate-oidc-issuer".into());
                }
                certificate_oidc_issuer = Some(args[i].clone());
            }
            "--key" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --key".into());
                }
                key_path = Some(args[i].clone());
            }
            "--staging" => {
                _staging = true;
            }
            "--trusted-root" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --trusted-root".into());
                }
                trusted_root_path = Some(args[i].clone());
            }
            arg if !arg.starts_with("--") => {
                artifact_or_digest = Some(arg.to_string());
            }
            unknown => {
                return Err(format!("Unknown option: {}", unknown).into());
            }
        }
        i += 1;
    }

    let bundle_path = bundle_path.ok_or("Missing required --bundle")?;
    let artifact_or_digest = artifact_or_digest.ok_or("Missing artifact or digest")?;

    // Check if using key-based or certificate-based verification
    let use_key_verification = key_path.is_some();
    if !use_key_verification {
        // Certificate-based verification requires identity and issuer
        if certificate_identity.is_none() || certificate_oidc_issuer.is_none() {
            return Err(
                "Either --key or both --certificate-identity and --certificate-oidc-issuer must be provided".into(),
            );
        }
    }

    // Load trusted root - use provided path or default to production
    let trusted_root = if let Some(root_path) = trusted_root_path {
        TrustedRoot::from_file(&root_path)?
    } else {
        // Default to production trusted root when not specified
        TrustedRoot::production()?
    };

    // Load bundle
    let bundle_json = fs::read_to_string(&bundle_path)?;
    let bundle = Bundle::from_json(&bundle_json)?;

    // Handle key-based verification
    if let Some(key_path) = key_path {
        use sigstore_types::DerPublicKey;
        use sigstore_verify::verify_with_key;

        // Load public key from PEM file
        let key_pem = fs::read_to_string(&key_path)?;
        let public_key = DerPublicKey::from_pem(&key_pem)
            .map_err(|e| format!("Failed to parse public key: {}", e))?;

        // Verify using the public key
        if artifact_or_digest.starts_with("sha256:") {
            // It's a digest
            let digest_hex = artifact_or_digest
                .strip_prefix("sha256:")
                .ok_or("Invalid digest format")?;
            let digest_bytes =
                hex::decode(digest_hex).map_err(|e| format!("Invalid hex digest: {}", e))?;

            if digest_bytes.len() != 32 {
                return Err(format!(
                    "Invalid SHA256 digest length: expected 32 bytes, got {}",
                    digest_bytes.len()
                )
                .into());
            }

            let artifact_digest = Sha256Hash::try_from_slice(&digest_bytes)
                .map_err(|e| format!("Invalid digest: {}", e))?;

            let result = verify_with_key(artifact_digest, &bundle, &public_key, &trusted_root)?;
            if !result.success {
                return Err("Verification failed".into());
            }
        } else {
            // It's a file path
            let artifact_data = fs::read(&artifact_or_digest)?;
            let result = verify_with_key(&artifact_data, &bundle, &public_key, &trusted_root)?;
            if !result.success {
                return Err("Verification failed".into());
            }
        }

        return Ok(());
    }

    // Certificate-based verification
    let certificate_identity = certificate_identity.unwrap();
    let certificate_oidc_issuer = certificate_oidc_issuer.unwrap();

    // Create verification policy
    let policy = VerificationPolicy::default()
        .require_identity(certificate_identity)
        .require_issuer(certificate_oidc_issuer);

    // Check if artifact_or_digest is a digest or file
    if artifact_or_digest.starts_with("sha256:") {
        // It's a digest - verify the bundle without the artifact file
        let digest_hex = artifact_or_digest
            .strip_prefix("sha256:")
            .ok_or("Invalid digest format")?;

        // Decode hex digest
        let digest_bytes =
            hex::decode(digest_hex).map_err(|e| format!("Invalid hex digest: {}", e))?;

        if digest_bytes.len() != 32 {
            return Err(format!(
                "Invalid SHA256 digest length: expected 32 bytes, got {}",
                digest_bytes.len()
            )
            .into());
        }

        // Extract expected hash from bundle
        let expected_hash = match &bundle.content {
            SignatureContent::MessageSignature(msg_sig) => {
                if let Some(digest) = &msg_sig.message_digest {
                    digest.digest.as_bytes().to_vec()
                } else {
                    return Err("Bundle does not contain message digest for verification".into());
                }
            }
            SignatureContent::DsseEnvelope(envelope) => {
                if envelope.payload_type == "application/vnd.in-toto+json" {
                    let payload_bytes = envelope.payload.as_bytes();
                    let payload_str = String::from_utf8(payload_bytes.to_vec())
                        .map_err(|e| format!("Invalid UTF-8 in payload: {}", e))?;
                    let statement: serde_json::Value = serde_json::from_str(&payload_str)
                        .map_err(|e| format!("Failed to parse statement: {}", e))?;

                    if let Some(subjects) = statement.get("subject").and_then(|s| s.as_array()) {
                        if let Some(subject) = subjects.first() {
                            if let Some(sha256) = subject
                                .get("digest")
                                .and_then(|d| d.get("sha256"))
                                .and_then(|h| h.as_str())
                            {
                                hex::decode(sha256).map_err(|e| {
                                    format!("Failed to decode subject digest: {}", e)
                                })?
                            } else {
                                return Err("No sha256 digest in subject".into());
                            }
                        } else {
                            return Err("No subjects in statement".into());
                        }
                    } else {
                        return Err("No subject array in statement".into());
                    }
                } else {
                    return Err("DSSE envelope does not contain in-toto statement".into());
                }
            }
        };

        // Verify that the provided digest matches the one in the bundle
        if expected_hash != digest_bytes {
            return Err(format!(
                "Digest mismatch: provided {} but bundle contains {}",
                hex::encode(&digest_bytes),
                hex::encode(&expected_hash)
            )
            .into());
        }

        // Convert digest bytes to Sha256Hash for verification
        let artifact_digest = Sha256Hash::try_from_slice(&digest_bytes)
            .map_err(|e| format!("Invalid digest: {}", e))?;

        // Verify the signature with trusted root using the digest directly
        let result = verify(artifact_digest, &bundle, &policy, &trusted_root)?;

        if !result.success {
            return Err("Verification failed".into());
        }

        Ok(())
    } else {
        // It's a file path
        let artifact_data = fs::read(&artifact_or_digest)?;

        // Verify with trusted root
        let result = verify(&artifact_data, &bundle, &policy, &trusted_root)?;

        if !result.success {
            return Err("Verification failed".into());
        }

        Ok(())
    }
}
