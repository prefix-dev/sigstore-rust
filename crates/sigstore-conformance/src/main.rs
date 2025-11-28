//! Sigstore Conformance Client
//!
//! CLI implementation following the specification:
//! <https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md>
//!
//! This binary implements the conformance test protocol for Sigstore clients.

use sigstore_bundle::{BundleV03, TlogEntryBuilder};
use sigstore_crypto::{CertificatePem, KeyPair};
use sigstore_fulcio::FulcioClient;
use sigstore_oidc::parse_identity_token;
use sigstore_rekor::RekorClient;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, DerCertificate, SignatureContent};
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
    eprintln!("  {} sign-bundle --identity-token TOKEN --bundle FILE [--staging] [--trusted-root FILE] [--signing-config FILE] ARTIFACT", program);
    eprintln!("  {} verify-bundle --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--staging] [--trusted-root FILE] ARTIFACT_OR_DIGEST", program);
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

    let identity_token = identity_token.ok_or("Missing required --identity-token")?;
    let bundle_path = bundle_path.ok_or("Missing required --bundle")?;
    let artifact_path = artifact_path.ok_or("Missing artifact path")?;

    // Parse signing config if present to get URLs
    let (fulcio_url, rekor_url, use_rekor_v2, tsa_url) = if let Some(config_path) = &_signing_config
    {
        let config_content = fs::read_to_string(config_path)?;
        let config_json: serde_json::Value = serde_json::from_str(&config_content)?;

        let fulcio_url = config_json
            .get("caUrls")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or("No caUrls in signing config")?;

        let tlogs = config_json
            .get("tlogs")
            .or_else(|| config_json.get("rekorTlogUrls"))
            .and_then(|v| v.as_array())
            .ok_or("No tlogs in signing config")?;

        let log = tlogs.first().ok_or("Empty tlogs list")?;
        let url = log
            .get("baseUrl")
            .or_else(|| log.get("url"))
            .and_then(|v| v.as_str())
            .ok_or("No baseUrl or url in tlog")?;
        let version = log
            .get("majorApiVersion")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        let tsa_url = config_json
            .get("tsaUrls")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|t| t.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        (fulcio_url, url.to_string(), version == 2, tsa_url)
    } else {
        let fulcio_url = if staging {
            "https://fulcio.sigstage.dev".to_string()
        } else {
            "https://fulcio.sigstore.dev".to_string()
        };

        let url = if staging {
            "https://rekor.sigstage.dev".to_string()
        } else {
            "https://rekor.sigstore.dev".to_string()
        };
        (fulcio_url, url, false, None)
    };

    // Read artifact
    let artifact_data = fs::read(&artifact_path)?;

    // Parse identity token to extract email or subject
    let token_info = parse_identity_token(&identity_token)?;
    let subject = token_info.email().unwrap_or(token_info.subject());

    // Generate ephemeral key pair
    let key_pair = KeyPair::generate_ecdsa_p256()?;
    let public_key_pem = key_pair.public_key_to_pem()?;

    // Get signing certificate from Fulcio
    let fulcio_client = FulcioClient::new(&fulcio_url);

    let proof_of_possession = key_pair.sign(subject.as_bytes())?;
    let cert_response = fulcio_client
        .create_signing_certificate(&identity_token, &public_key_pem, &proof_of_possession)
        .await?;

    // Get the leaf certificate (v0.3 bundles use single cert, not chain)
    let leaf_cert_pem = cert_response
        .leaf_certificate()
        .ok_or("No leaf certificate in response")?;

    // Parse PEM to type-safe DerCertificate (validates CERTIFICATE header)
    let leaf_cert_der = DerCertificate::from_pem(leaf_cert_pem)
        .map_err(|e| format!("Invalid certificate PEM: {}", e))?;

    // Sign the artifact
    let signature = key_pair.sign(&artifact_data)?;

    // For Rekor V2 API, signature needs to be base64-encoded
    use base64::Engine;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_bytes());

    // Compute artifact hash using sigstore-crypto
    let artifact_hash = sigstore_crypto::sha256(&artifact_data);

    // For v2, we still need hex for now
    let artifact_hash_hex = artifact_hash.to_hex();

    // Upload to Rekor
    let rekor = RekorClient::new(&rekor_url);

    // Use CertificatePem for type-safe Rekor entry creation
    let certificate_pem = CertificatePem::new(leaf_cert_pem.to_string());

    let log_entry = if use_rekor_v2 {
        let hashed_rekord =
            sigstore_rekor::HashedRekordV2::new(&artifact_hash_hex, &signature_b64, leaf_cert_pem);
        rekor.create_entry_v2(hashed_rekord).await?
    } else {
        let hashed_rekord =
            sigstore_rekor::HashedRekord::new(&artifact_hash, &signature, &certificate_pem);
        rekor.create_entry(hashed_rekord).await?
    };

    // Build bundle using the from_log_entry helper
    let kind_version = if use_rekor_v2 { "0.0.2" } else { "0.0.1" };
    let tlog_entry =
        TlogEntryBuilder::from_log_entry(&log_entry, "hashedrekord", kind_version).build();

    let mut bundle =
        BundleV03::with_certificate_and_signature(leaf_cert_der, signature.clone(), artifact_hash)
            .with_tlog_entry(tlog_entry);

    if let Some(tsa_url) = tsa_url {
        eprintln!("Using TSA: {}", tsa_url);
        let tsa_client = sigstore_tsa::TimestampClient::new(tsa_url);

        // Hash the signature
        let signature_digest = sigstore_crypto::sha256(signature.as_bytes());

        // Timestamp the signature digest
        let timestamp_der = tsa_client.timestamp_sha256(&signature_digest).await?;

        bundle = bundle.with_rfc3161_timestamp(timestamp_der);
    }

    let bundle = bundle.into_bundle();

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
    let certificate_identity =
        certificate_identity.ok_or("Missing required --certificate-identity")?;
    let certificate_oidc_issuer =
        certificate_oidc_issuer.ok_or("Missing required --certificate-oidc-issuer")?;
    let artifact_or_digest = artifact_or_digest.ok_or("Missing artifact or digest")?;

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

        // Create a policy that skips artifact hash validation since we already checked it
        let digest_policy = policy.skip_artifact_hash();
        let dummy_artifact = vec![];

        // Verify the signature with trusted root
        let result = verify(&dummy_artifact, &bundle, &digest_policy, &trusted_root)?;

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
