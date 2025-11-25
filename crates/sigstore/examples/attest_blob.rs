use serde::{Deserialize, Serialize};
use sigstore::bundle::{BundleBuilder, TlogEntryBuilder};
use sigstore::crypto::KeyPair;
use sigstore::fulcio::FulcioClient;
use sigstore::oidc::get_identity_token;
use sigstore::rekor::{DsseEntry, RekorClient};
use sigstore::types::{DsseEnvelope, DsseSignature, MediaType};
use sigstore_types::{KeyId, PayloadBytes};
use std::env;
use std::fs;
use std::path::PathBuf;

/// In-toto Statement v1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InTotoStatement {
    #[serde(rename = "_type")]
    type_: String,
    subject: Vec<Subject>,
    predicate_type: String,
    predicate: serde_json::Value,
}

/// Subject of the in-toto statement
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Subject {
    name: String,
    digest: SubjectDigest,
}

/// Digest for a subject
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubjectDigest {
    sha256: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <file-to-attest> <output-bundle> [predicate-type]",
            args[0]
        );
        eprintln!("  predicate-type defaults to 'https://slsa.dev/provenance/v1'");
        std::process::exit(1);
    }
    let file_path = PathBuf::from(&args[1]);
    let bundle_path = PathBuf::from(&args[2]);
    let predicate_type = args
        .get(3)
        .map(|s| s.as_str())
        .unwrap_or("https://slsa.dev/provenance/v1");

    println!("Creating attestation for file: {:?}", file_path);
    let artifact_data = fs::read(&file_path)?;

    // Hash the artifact using sigstore-crypto
    let artifact_hash = sigstore_crypto::sha256(&artifact_data);
    let artifact_hash_hex = hex::encode(artifact_hash);

    // 1. OIDC: Get Identity Token
    println!("Getting OIDC identity token...");
    let token_response = get_identity_token(|response| {
        println!("Please visit the following URL to authenticate:");
        println!(
            "{}",
            response
                .verification_uri_complete
                .as_ref()
                .unwrap_or(&response.verification_uri)
        );
        println!("User code: {}", response.user_code);
    })
    .await?;
    let id_token = token_response.raw().to_string();
    println!(
        "Got identity token for: {}",
        token_response.email().unwrap_or("unknown")
    );

    // 2. Keys: Generate ephemeral key pair
    println!("Generating ephemeral key pair...");
    let key_pair = KeyPair::generate_ecdsa_p256()?;
    let public_key_pem = key_pair.public_key_to_pem()?;

    // 3. Fulcio: Get Signing Certificate
    println!("Requesting signing certificate from Fulcio...");
    let fulcio_client = FulcioClient::public();

    // Create proof of possession
    let email = token_response.email().ok_or("No email in token")?;
    let proof_of_possession = key_pair.sign(email.as_bytes())?;

    let cert_response = fulcio_client
        .create_signing_certificate(&id_token, &public_key_pem, &proof_of_possession)
        .await?;

    // Extract the leaf certificate (PEM)
    let leaf_cert_pem = cert_response
        .leaf_certificate()
        .ok_or("No leaf certificate in response")?;

    // For the bundle, we need the DER encoded certificate bytes
    let leaf_cert_der_b64 = pem_to_der_base64(leaf_cert_pem)?;
    use base64::Engine;
    let leaf_cert_der = base64::engine::general_purpose::STANDARD.decode(&leaf_cert_der_b64)?;

    println!("Got signing certificate");

    // 4. Create In-Toto Statement
    println!("Creating in-toto statement...");

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artifact");

    let statement = InTotoStatement {
        type_: "https://in-toto.io/Statement/v1".to_string(),
        subject: vec![Subject {
            name: file_name.to_string(),
            digest: SubjectDigest {
                sha256: artifact_hash_hex.clone(),
            },
        }],
        predicate_type: predicate_type.to_string(),
        predicate: serde_json::json!({
            "buildDefinition": {
                "buildType": "https://slsa.dev/container-based-build/v0.1",
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner"
                }
            }
        }),
    };

    // Serialize statement to JSON
    let statement_json = serde_json::to_string(&statement)?;
    let statement_bytes = statement_json.as_bytes();

    // 5. Create and Sign DSSE Envelope
    println!("Creating DSSE envelope...");

    // Create PAE (Pre-Authentication Encoding) and sign it
    // For in-toto, the payload type must be "application/vnd.in-toto+json"
    let payload_type = "application/vnd.in-toto+json";
    let pae = sigstore::types::dsse::pae(payload_type, statement_bytes);
    let signature = key_pair.sign(&pae)?;

    // Create DSSE envelope (PayloadBytes handles base64 encoding at serde level)
    let dsse_envelope = DsseEnvelope::new(
        payload_type.to_string(),
        PayloadBytes::from_bytes(statement_bytes),
        vec![DsseSignature {
            sig: signature.into(),
            keyid: KeyId::default(),
        }],
    );

    // Serialize envelope to JSON for Rekor
    let envelope_json = serde_json::to_string(&dsse_envelope)?;

    // 6. Rekor: Upload to Transparency Log
    println!("Uploading to Rekor...");
    let rekor = RekorClient::public();

    // Create DSSE entry
    let dsse_entry = DsseEntry::new(&envelope_json, leaf_cert_pem);

    let log_entry = rekor.create_dsse_entry(dsse_entry).await?;
    println!("Created Rekor entry with index: {}", log_entry.log_index);

    // 7. Bundle: Construct Sigstore Bundle
    println!("Constructing bundle...");

    // Create Tlog entry for bundle using the from_log_entry helper
    // This automatically extracts log_id, inclusion_promise, inclusion_proof, etc.
    let tlog_entry = TlogEntryBuilder::from_log_entry(&log_entry, "dsse", "0.0.1").build();

    let bundle = BundleBuilder::new()
        .version(MediaType::Bundle0_3)
        .certificate(leaf_cert_der)
        .dsse_envelope(dsse_envelope)
        .add_tlog_entry(tlog_entry)
        .build()
        .map_err(|e| format!("Failed to build bundle: {}", e))?;

    // 8. Save Bundle
    let bundle_json = bundle.to_json_pretty()?;
    fs::write(&bundle_path, bundle_json)?;
    println!("Bundle saved to: {:?}", bundle_path);
    println!("\nYou can verify this attestation with:");
    println!("cosign verify-blob-attestation --bundle {} --certificate-identity {} --certificate-oidc-issuer https://oauth2.sigstore.dev/auth --type {} {}",
        bundle_path.display(),
        token_response.email().unwrap_or("unknown"),
        predicate_type,
        file_path.display());

    Ok(())
}

fn pem_to_der_base64(pem: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem
        .find(start_marker)
        .ok_or("Invalid PEM: missing start marker")?;
    let end = pem
        .find(end_marker)
        .ok_or("Invalid PEM: missing end marker")?;

    if start > end {
        return Err("Invalid PEM: start after end".into());
    }

    let content = &pem[start + start_marker.len()..end];
    let clean_content: String = content.chars().filter(|c| !c.is_whitespace()).collect();

    Ok(clean_content)
}
