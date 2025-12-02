use sigstore_trust_root::{TrustedRoot, TrustedRootExt};
use std::path::PathBuf;

#[test]
fn test_parse_conformance_trusted_root() {
    // Find the conformance test directory
    let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.pop(); // crates
    test_file.pop(); // root
    test_file.push("sigstore-conformance");
    test_file.push("test/assets/bundle-verify/intoto-expired-certificate_fail/trusted_root.json");

    if !test_file.exists() {
        eprintln!(
            "Skipping test - conformance suite not found at {:?}",
            test_file
        );
        return;
    }

    let trusted_root = TrustedRoot::from_file(&test_file).expect("Failed to parse trusted root");

    // Basic sanity checks
    assert!(!trusted_root.media_type.is_empty());

    // Should have some trust anchors
    let has_data = !trusted_root.tlogs.is_empty()
        || !trusted_root.certificate_authorities.is_empty()
        || !trusted_root.ctlogs.is_empty()
        || !trusted_root.timestamp_authorities.is_empty();

    assert!(
        has_data,
        "Trusted root should contain at least some trust anchors"
    );

    println!("✓ Parsed trusted root with:");
    println!("  - {} transparency logs", trusted_root.tlogs.len());
    println!(
        "  - {} certificate authorities",
        trusted_root.certificate_authorities.len()
    );
    println!("  - {} CT logs", trusted_root.ctlogs.len());
    println!(
        "  - {} timestamp authorities",
        trusted_root.timestamp_authorities.len()
    );
}

#[test]
fn test_trusted_root_api() {
    // Find the conformance test directory
    let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.pop();
    test_file.pop();
    test_file.push("sigstore-conformance");
    test_file.push("test/assets/bundle-verify/intoto-expired-certificate_fail/trusted_root.json");

    if !test_file.exists() {
        eprintln!("Skipping test - conformance suite not found");
        return;
    }

    let trusted_root = TrustedRoot::from_file(&test_file).expect("Failed to parse trusted root");

    // Test API methods
    let fulcio_certs = trusted_root
        .fulcio_certs()
        .expect("Failed to get Fulcio certs");
    println!("Fulcio certificates: {}", fulcio_certs.len());

    let rekor_keys = trusted_root.rekor_keys().expect("Failed to get Rekor keys");
    println!("Rekor keys: {}", rekor_keys.len());

    let ctfe_keys = trusted_root.ctfe_keys().expect("Failed to get CTFE keys");
    println!("CTFE keys: {}", ctfe_keys.len());

    let tsa_certs = trusted_root
        .tsa_certs_with_validity()
        .expect("Failed to get TSA certs");
    println!("TSA certificates: {}", tsa_certs.len());
}
