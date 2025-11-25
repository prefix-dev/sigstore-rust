use sigstore::bundle::{BundleBuilder, TlogEntryBuilder};
use sigstore::crypto::KeyPair;
use sigstore::fulcio::FulcioClient;
use sigstore::oidc::get_identity_token;
use sigstore::rekor::{HashedRekord, RekorClient};
use sigstore::types::{MediaType, Sha256Hash};
use std::env;
use std::fs;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <file-to-sign> <output-bundle>", args[0]);
        std::process::exit(1);
    }
    let file_path = PathBuf::from(&args[1]);
    let bundle_path = PathBuf::from(&args[2]);

    println!("Signing file: {:?}", file_path);
    let artifact_data = fs::read(&file_path)?;

    // 1. OIDC: Get Identity Token
    println!("Getting OIDC identity token...");
    // Use default issuer (sigstore.dev)
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

    // Get public key in PEM format
    println!("Public Key PEM:\n{}", public_key_pem);

    // Create proof of possession
    // The proof of possession is a signature over the subject (email) from the OIDC token
    let email = token_response.email().ok_or("No email in token")?;
    println!("Signing proof of possession for subject: {}", email);
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

    // 4. Sign the artifact
    println!("Signing artifact...");

    // Hash the artifact data using sigstore-crypto
    let hash_bytes = sigstore_crypto::sha256(&artifact_data);
    let artifact_hash_typed = Sha256Hash::from_bytes(hash_bytes);

    // Sign the artifact data directly
    let signature = key_pair.sign(&artifact_data)?;

    // 5. Rekor: Upload to Transparency Log
    println!("Uploading to Rekor...");
    let rekor = RekorClient::public();

    // Create hashedrekord entry with certificate (not public key) for identity verification
    let cert_as_pem = sigstore_crypto::PublicKeyPem::new(leaf_cert_pem.to_string());
    let hashed_rekord = HashedRekord::new(&artifact_hash_typed, &signature, &cert_as_pem);

    let log_entry = rekor.create_entry(hashed_rekord).await?;
    println!("Created Rekor entry with index: {}", log_entry.log_index);

    // 6. Bundle: Construct Sigstore Bundle
    println!("Constructing bundle...");

    // Create Tlog entry for bundle using the from_log_entry helper
    // This automatically extracts log_id, inclusion_promise, inclusion_proof, etc.
    let tlog_entry = TlogEntryBuilder::from_log_entry(&log_entry, "hashedrekord", "0.0.1").build();

    // Create digest hash from bytes
    let digest_hash = sigstore_types::Sha256Hash::from_bytes(hash_bytes);

    let bundle = BundleBuilder::new()
        .version(MediaType::Bundle0_3)
        .certificate(leaf_cert_der)
        .message_signature_with_digest(
            signature.as_bytes().to_vec(),
            digest_hash,
            sigstore_types::HashAlgorithm::Sha2256,
        )
        .add_tlog_entry(tlog_entry)
        .build()
        .map_err(|e| format!("Failed to build bundle: {}", e))?;

    // 7. Save Bundle
    let bundle_json = bundle.to_json_pretty()?;
    fs::write(&bundle_path, bundle_json)?;
    println!("Bundle saved to: {:?}", bundle_path);
    println!("You can verify this bundle with:");
    println!("cosign verify-blob --bundle {} --certificate-identity {} --certificate-oidc-issuer https://oauth2.sigstore.dev/auth {}", 
        bundle_path.display(), token_response.email().unwrap_or("unknown"), file_path.display());

    Ok(())
}

fn pem_to_der_base64(pem: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Simple PEM parser: find BEGIN and END lines, take content between them, remove newlines
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
