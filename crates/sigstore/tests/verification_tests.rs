//! End-to-end verification tests
//!
//! These tests validate the complete verification flow using real bundles.

use sigstore::bundle::{validate_bundle, validate_bundle_with_options, ValidationOptions};
use sigstore::types::Bundle;
use sigstore::verify::{verify, VerificationPolicy, Verifier};
use sigstore_types::LogIndex;

/// Real v0.3 bundle from sigstore-python tests
const V03_BUNDLE: &str = include_str!("../../sigstore-bundle/tests/fixtures/bundle_v3.json");

/// Real v0.3 bundle from sigstore-rs with DSSE and inclusion proof
const V03_BUNDLE_DSSE: &str = r#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"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"},"tlogEntries":[{"logIndex":"166143216","logId":{"keyId":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="},"kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":"1738060096","inclusionPromise":{"signedEntryTimestamp":"MEQCIFdvIafa5jqan78r7Ypre1hdOCE1lnZ5LT0lYEtlCYnAAiBHWRe5/97eWPqVypxIzKbDUVtK7Y3rJmYT0DCOuRtY5g=="},"inclusionProof":{"logIndex":"44238954","rootHash":"TiowMOu0x46fW4pXrRyW7TeVb6f1/VDnDZWcP1xL/HU=","treeSize":"44238955","hashes":["iMecnh5ol+AiQUqe67cka5QnpS7+Uac/PP2yxDQ7KnQ=","VXEdyQrtr/iiIQPJ76SNiRpLd8/wXguekWT+nmHbP84=","lkPY9Ya80uK1vUlI2ekwn125ntq+s+Hx32de1Zre35s=","FXn3gvhalfR91NP/m43gQswlqzo8LYuMe95EdKvsD7c=","kHIAOKN34D4Q4Mu3aTF4dLRO7QKWDSrkRXJ8wj0a2j0=","sTh7uuXvFFqHGFy/+afvnA9fsSMiHIZoWRAdHhNZMFQ=","ABrujg3xYGHOAy9tkUTpYsPw8qCs6bGbyGms261oTf4=","WYCyxkm3nLuN6MubBiGGY9Z5Try/M4gliHJK7VMo7V4=","jU9+tgjTIKUYGeU7T7RjqyL+F+gFV9tCdwX2GZ1UtQs=","vemyaMj0Na1LMjbB/9Dmkq8T+jAb3o+yCESgAayUABU="],"checkpoint":{"envelope":"rekor.sigstore.dev - 1193050959916656506\n44238955\nTiowMOu0x46fW4pXrRyW7TeVb6f1/VDnDZWcP1xL/HU=\n\n— rekor.sigstore.dev wNI9ajBEAiBF3lyT0Jg0paKCvqJQ0t97+hcneAqZHeiRuLinOba/YQIgG65ZKAhE+byLy+VQ4/14FwvJG0FMhq4CNoDONpzvOMc=\n"}},"canonicalizedBody":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiZDhiYjhkM2FkMTRmNTYxODQxOTMzODExYjkwZTNiOGY4ZGJjODFhMTQ2NDlkOThkNGI3Zjg0YjM1M2ZmODM0NSJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6ImZhZDU0M2M3YTFlOWFjZmE0Y2I2ZWNkN2UxNGZiN2UzY2QxMzVjMDllZmU4ZGRjOTY4ZDQ5NGJjMjIyMTM2ZGQifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVVQ0lRQ0VKTzkxb21WUHc2WVJDVEVlN3YzRllObzZMeFBTSlozMitScUZoeXFONVFJZ1dXdzk2THhWSzhPVGZ5N1I5SFRlVnhuSTg3bnI4aHg1Tm4wRGdCNDkzbE09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VkemVrTkRRbXB4WjBGM1NVSkJaMGxWVEZNM05DOXBSWEExYkM5SlNHaDZPVE5aVkhKMVduWmFjblZOZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmQwMVVTVFJOVkVGNVQwUkZNVmRvWTA1TmFsVjNUVlJKTkUxVVFYcFBSRVV4VjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVnBWRlZ4TW5wU1NHdFdlR1pwUjFsSFluRlNWWFZZZVRGS2JEQm5RVzloV0VabFQyY0taV29yYVVoaFEzcHdOVkZSV214TlIzSTNjVzl1Vml0SGQzUlRSMlkwY21GdVZWSnplSHBsWWtSWWJXSmlOMGQyVFhGUFEwSldhM2RuWjFaV1RVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVlNZWFV2Q2tOTlYxUldOSFI2T0daSFZUSXZWVEIyYmtseWJWRTBkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMWxuV1VSV1VqQlNRVkZJTDBKR1ozZFdiMXBWWVVoU01HTklUVFpNZVRsdVlWaFNiMlJYU1hWWk1qbDBURE5rZG1KSFdqSk1NMDV3V2pOT01BcGlNMHBzVEZoU2JHTXpVWFpNYldSd1pFZG9NVmxwT1ROaU0wcHlXbTE0ZG1RelRYWlpWMDR3WVZjNWRVeHViR2hpVjNoQlkyMVdiV041T1c5YVYwWnJDbU41T1hSWlYyeDFUVVJyUjBOcGMwZEJVVkZDWnpjNGQwRlJSVVZMTW1nd1pFaENlazlwT0haa1J6bHlXbGMwZFZsWFRqQmhWemwxWTNrMWJtRllVbThLWkZkS01XTXlWbmxaTWpsMVpFZFdkV1JETldwaU1qQjNSV2RaUzB0M1dVSkNRVWRFZG5wQlFrRm5VVVZqU0ZaNllVUkJNa0puYjNKQ1owVkZRVmxQTHdwTlFVVkVRa05vYUU1Nll6Ulpha1UxVFVSTmVFMVhSVEZPYlZsM1RrZEdhazlVUlRGWmVrNXNUV3BLYWxwVVl6UlBWRVpxVDFkV2JGcEhTbTFOUWpSSENrTnBjMGRCVVZGQ1p6YzRkMEZSVVVWRlJrSm9XVEowYUZveVZXZFpWelZyU1VoT2NGb3lOSGRKVVZsTFMzZFpRa0pCUjBSMmVrRkNRbEZSVkdReU9YTUtXbTVaZG1NeWJHNWpNMUoyWTIxVmRHUkhWbnBrUkVGa1FtZHZja0puUlVWQldVOHZUVUZGUjBKQk9YbGFWMXA2VERKb2JGbFhVbnBNTWpGb1lWYzBkd3BQZDFsTFMzZFpRa0pCUjBSMmVrRkNRMEZSZEVSRGRHOWtTRkozWTNwdmRrd3pVblpoTWxaMVRHMUdhbVJIYkhaaWJrMTFXakpzTUdGSVZtbGtXRTVzQ21OdFRuWmlibEpzWW01UmRWa3lPWFJOUjFGSFEybHpSMEZSVVVKbk56aDNRVkZyUlZabmVGVmhTRkl3WTBoTk5reDVPVzVoV0ZKdlpGZEpkVmt5T1hRS1RETmtkbUpIV2pKTU0wNXdXak5PTUdJelNteE1XRkpzWXpOUmRreHRaSEJrUjJneFdXazVNMkl6U25KYWJYaDJaRE5OZGxsWFRqQmhWemwxVEc1c2FBcGlWM2hCWTIxV2JXTjVPVzlhVjBaclkzazVkRmxYYkhWTlJHZEhRMmx6UjBGUlVVSm5OemgzUVZGdlJVdG5kMjlaVkdNelQwZEplRTlVUVhwTlZFWm9DazVVV20xTlJGSm9XWHByZUU1WFRYcGFWRWw1V1RKVk0wOUVhM2haZW14c1dsZFNhVnBxUVdSQ1oyOXlRbWRGUlVGWlR5OU5RVVZNUWtFNFRVUlhaSEFLWkVkb01WbHBNVzlpTTA0d1dsZFJkMDVuV1V0TGQxbENRa0ZIUkhaNlFVSkVRVkZ2UkVOYWIyUklVbmRqZW05MlRESmtjR1JIYURGWmFUVnFZakl3ZGdwa01qbHpXbTVaZG1NeWJHNWpNMUoyWTIxVmRHUkhWbnBrUkVFMFFtZHZja0puUlVWQldVOHZUVUZGVGtKRGIwMUxSMFV6VG5wb2FVMVVhM2ROZWtWNENsbFVWVEphYWtFd1dWZE5OVTFVVm1wTk1sVjVUVzFPYkU1Nlp6Vk5WMDAxV2xkV2ExbHRXWGRJZDFsTFMzZFpRa0pCUjBSMmVrRkNSR2RSVWtSQk9Ya0tXbGRhZWt3eWFHeFpWMUo2VERJeGFHRlhOSGRIVVZsTFMzZFpRa0pCUjBSMmVrRkNSSGRSVEVSQmF6Uk9WR3Q1VDFSbmQwNVVTWGRMUVZsTFMzZFpRZ3BDUVVkRWRucEJRa1ZCVVdGRVFtaHZaRWhTZDJONmIzWk1NbVJ3WkVkb01WbHBOV3BpTWpCMlpESTVjMXB1V1hkR1oxbExTM2RaUWtKQlIwUjJla0ZDQ2tWUlVVbEVRVmswVDBSVmQwNVVVWGRhUVZsTFMzZFpRa0pCUjBSMmVrRkNSV2RTVjBSR1VtOWtTRkozWTNwdmRrd3laSEJrUjJneFdXazFhbUl5TUhZS1pESTVjMXB1V1haak1teHVZek5TZG1OdFZYUmtSMVo2WkVNNGRWb3liREJoU0ZacFRETmtkbU50ZEcxaVJ6a3pZM2s1YUZrelVuQmlNalIxWlZkR2RBcGlSVUo1V2xkYWVrd3lhR3haVjFKNlRESXhhR0ZYTkhkUFFWbExTM2RaUWtKQlIwUjJla0ZDUlhkUmNVUkRhR2hPZW1NMFdXcEZOVTFFVFhoTlYwVXhDazV0V1hkT1IwWnFUMVJGTVZsNlRteE5ha3BxV2xSak5FOVVSbXBQVjFac1drZEtiVTFDVVVkRGFYTkhRVkZSUW1jM09IZEJVbEZGUW1kM1JXTklWbm9LWVVSQ1lVSm5iM0pDWjBWRlFWbFBMMDFCUlZaQ1JYZE5VMjFvTUdSSVFucFBhVGgyV2pKc01HRklWbWxNYlU1MllsTTVNMkl5ZUcxa2FUbDZZVmRrZWdwa1J6bDVXbE14TUZwWVRqQk1Na1pxWkVkc2RtSnVUWFpqYmxaMVkzazRlRTE2UVhkUFJGRjVUMVJGTVU5VE9XaGtTRkpzWWxoQ01HTjVPSGhOUWxsSENrTnBjMGRCVVZGQ1p6YzRkMEZTV1VWRFFYZEhZMGhXYVdKSGJHcE5TVWRMUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpJZDBWbFowSTBRVWhaUVROVU1IY0tZWE5pU0VWVVNtcEhValJqYlZkak0wRnhTa3RZY21wbFVFc3pMMmcwY0hsblF6aHdOMjgwUVVGQlIxVnlTRkpvWldkQlFVSkJUVUZTZWtKR1FXbEZRUXByU0hsWU5FRllUVUoyY2paclluZE5lbVZZYkVORFFVUk9SbW80ZFVzMk9IWlpMMnNyUldWMVFXVnJRMGxEUzJaME9FeEpkV3BGWm10MVRtVXdTVlV2Q2tNM1RUaE1TR1ZxVFhkclREYzNOMDByT0doRmNsbEhZVTFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbU5CVFVkUlEwMURZMGRwYkZKMVlUQndTM05SY1ZJS2FFMURXV3BhVW1sR0swMHljREF6Y1dkamRrZG9NMFJwVW10WWNGSlZXRTU0UjBWTVRsSlJiVWR2Y1RaVlN6WlVibmRKZDJOcU0ya3pZalJTUlVVdmJRcEtaRTB2UmtKVEwydElZVWhpVlRKbmRHMDBURE5xWlZWWk1GRXlhamRaVlhObWVWQjJjamRITjI5YVpqUmhWSEJyTWtGWENpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9XX19"}],"timestampVerificationData":{"rfc3161Timestamps":[]}},"dsseEnvelope":{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoic2lnbmVkLXBhY2thZ2UtMS4yLjAtaGIwZjRkY2FfMC5jb25kYSIsImRpZ2VzdCI6eyJzaGEyNTYiOiI1OWVkODFlZTdhMjQ4NWM0NzU4OGViZGJhZDE0NzY0YmY3MjJjOTM0MzhiNDNmZTk1M2E2NTE3NDdiYzYyYWQ3In19XSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2xzYS5kZXYvc3BlYy92MS4wL3Byb3ZlbmFuY2UiLCJwcmVkaWNhdGUiOnt9fQ==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEUCIQCEJO91omVPw6YRCTEe7v3FYNo6LxPSJZ32+RqFhyqN5QIgWWw96LxVK8OTfy7R9HTeVxnI87nr8hx5Nn0DgB493lM=","keyid":""}]}}"#;

const HAPPY_PATH_V03_BUNDLE_DSSE: &str =
    include_str!("../../sigstore-bundle/tests/fixtures/happy-path.json");

// ==== Bundle Parsing Tests ====

#[test]
fn test_parse_v03_bundle() {
    let bundle = Bundle::from_json(V03_BUNDLE).expect("Failed to parse v0.3 bundle");

    assert!(bundle.media_type.contains("v0.3"));
    assert!(bundle.has_inclusion_proof());
    assert!(!bundle.verification_material.tlog_entries.is_empty());
}

#[test]
fn test_parse_v03_dsse_bundle() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).expect("Failed to parse DSSE bundle");

    assert!(bundle.media_type.contains("v0.3"));
    assert!(bundle.has_inclusion_proof());
    assert!(bundle.has_inclusion_promise());

    // Check DSSE envelope
    match &bundle.content {
        sigstore::types::bundle::SignatureContent::DsseEnvelope(env) => {
            assert_eq!(env.payload_type, "application/vnd.in-toto+json");
            assert!(!env.signatures.is_empty());
        }
        _ => panic!("Expected DSSE envelope"),
    }
}

// ==== Bundle Validation Tests ====

#[test]
fn test_validate_bundle_structure() {
    let bundle = Bundle::from_json(V03_BUNDLE).unwrap();

    let result = validate_bundle(&bundle);
    assert!(
        result.is_ok(),
        "Bundle validation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_validate_bundle_with_inclusion_proof() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();

    let options = ValidationOptions {
        require_inclusion_proof: true,
        require_timestamp: false,
    };

    let result = validate_bundle_with_options(&bundle, &options);
    assert!(result.is_ok(), "Validation failed: {:?}", result.err());
}

#[test]
fn test_validate_bundle_merkle_proof() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();

    // This validates the Merkle inclusion proof
    let options = ValidationOptions {
        require_inclusion_proof: true,
        require_timestamp: false,
    };

    let result = validate_bundle_with_options(&bundle, &options);
    assert!(
        result.is_ok(),
        "Merkle proof validation failed: {:?}",
        result.err()
    );
}

// ==== Verifier Tests ====

#[test]
fn test_verifier_creation() {
    let verifier = Verifier::new();
    let bundle = Bundle::from_json(V03_BUNDLE).unwrap();

    // Dummy artifact for testing
    let artifact = b"test artifact";

    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_artifact_hash();

    let result = verifier.verify(artifact, &bundle, &policy);
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
}

#[test]
fn test_verify_with_policy() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();
    let artifact = b"test artifact";

    // Test with default policy (requires tlog verification)
    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_artifact_hash();

    let result = verify(artifact, &bundle, &policy);
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());

    let verification = result.unwrap();
    assert!(verification.success);
    assert!(verification.integrated_time.is_some());
}

#[test]
fn test_verify_extracts_integrated_time() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();
    let artifact = b"test artifact";

    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_artifact_hash();

    let result = verify(artifact, &bundle, &policy).unwrap();

    assert!(result.integrated_time.is_some());
    let time = result.integrated_time.unwrap();
    assert!(time > 0, "Integrated time should be positive");

    // The integrated time in the bundle is 1738060096 (2025-01-28)
    assert_eq!(time, 1738060096);
}

#[test]
fn test_skip_tlog_verification() {
    let bundle = Bundle::from_json(V03_BUNDLE).unwrap();
    let artifact = b"test artifact";

    let policy = VerificationPolicy::default()
        .skip_tlog()
        .skip_timestamp()
        .skip_artifact_hash();

    let result = verify(artifact, &bundle, &policy);
    assert!(result.is_ok());
}

// ==== Policy Tests ====

#[test]
fn test_policy_builder() {
    let policy = VerificationPolicy::default()
        .require_identity("test@example.com")
        .require_issuer("https://accounts.google.com")
        .skip_tlog()
        .skip_timestamp();

    assert_eq!(policy.identity, Some("test@example.com".to_string()));
    assert_eq!(
        policy.issuer,
        Some("https://accounts.google.com".to_string())
    );
    assert!(!policy.verify_tlog);
    assert!(!policy.verify_timestamp);
}

#[test]
fn test_policy_with_identity() {
    let policy = VerificationPolicy::with_identity("user@example.com");
    assert_eq!(policy.identity, Some("user@example.com".to_string()));
    assert!(policy.verify_tlog); // Default is true
}

#[test]
fn test_policy_with_issuer() {
    let policy = VerificationPolicy::with_issuer("https://token.actions.githubusercontent.com");
    assert_eq!(
        policy.issuer,
        Some("https://token.actions.githubusercontent.com".to_string())
    );
}

// ==== Integration Tests ====

#[test]
fn test_full_verification_flow() {
    // Load bundle
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();

    // Verify bundle structure first
    let validation_result = validate_bundle(&bundle);
    assert!(
        validation_result.is_ok(),
        "Validation failed: {:?}",
        validation_result.err()
    );

    // Check it has the expected components
    assert!(bundle.has_inclusion_proof(), "Should have inclusion proof");
    assert!(
        bundle.signing_certificate().is_some(),
        "Should have certificate"
    );

    // Extract tlog entry info
    let entry = &bundle.verification_material.tlog_entries[0];
    assert_eq!(entry.kind_version.kind, "dsse");
    assert_eq!(entry.log_index, LogIndex::new("166143216".to_string()));

    // Verify inclusion proof
    let proof = entry.inclusion_proof.as_ref().expect("Should have proof");
    assert_eq!(proof.tree_size, "44238955");
    assert_eq!(proof.hashes.len(), 10);

    // Run full verification
    let artifact = b"dummy artifact";
    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_artifact_hash();

    let result = verify(artifact, &bundle, &policy).unwrap();
    assert!(result.success);
    assert_eq!(result.integrated_time, Some(1738060096));
}

#[test]
fn test_full_verification_flow_happy_path() {
    // Load bundle
    // let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();
    let bundle = Bundle::from_json(HAPPY_PATH_V03_BUNDLE_DSSE).unwrap();

    // Verify bundle structure first
    let validation_result = validate_bundle(&bundle);
    assert!(
        validation_result.is_ok(),
        "Validation failed: {:?}",
        validation_result.err()
    );

    // Check it has the expected components
    assert!(bundle.has_inclusion_proof(), "Should have inclusion proof");
    assert!(
        bundle.signing_certificate().is_some(),
        "Should have certificate"
    );

    // Extract tlog entry info
    let entry = &bundle.verification_material.tlog_entries[0];
    assert_eq!(entry.kind_version.kind, "dsse");
    assert_eq!(entry.log_index, LogIndex::new("155690850".to_string()));

    // Verify inclusion proof
    let proof = entry.inclusion_proof.as_ref().expect("Should have proof");
    assert_eq!(proof.tree_size, "33786589");
    assert_eq!(proof.hashes.len(), 11);

    // Run full verification
    let artifact = b"dummy artifact";
    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_artifact_hash();

    let result = verify(artifact, &bundle, &policy).unwrap();
    assert!(result.success);
    assert_eq!(result.integrated_time, Some(1738060096));
}

#[test]
fn test_verification_with_different_bundle_versions() {
    // v0.3 bundle with message signature
    let v03_msg = Bundle::from_json(V03_BUNDLE).unwrap();
    let artifact = b"test";
    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_artifact_hash();

    let result = verify(artifact, &v03_msg, &policy);
    assert!(result.is_ok(), "v0.3 message signature verification failed");

    // v0.3 bundle with DSSE
    let v03_dsse = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();
    let result = verify(artifact, &v03_dsse, &policy);
    assert!(result.is_ok(), "v0.3 DSSE verification failed");
}

#[test]
fn test_checkpoint_parsing() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();
    let entry = &bundle.verification_material.tlog_entries[0];
    let proof = entry.inclusion_proof.as_ref().unwrap();

    // Parse checkpoint
    let checkpoint = proof
        .checkpoint
        .parse()
        .expect("Failed to parse checkpoint");

    assert_eq!(
        checkpoint.origin,
        "rekor.sigstore.dev - 1193050959916656506"
    );
    assert_eq!(checkpoint.tree_size, 44238955);
    assert!(!checkpoint.root_hash.is_empty());
}

#[test]
fn test_serialization_roundtrip() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();

    // Serialize
    let json = bundle.to_json().expect("Failed to serialize");

    // Deserialize
    let bundle2 = Bundle::from_json(&json).expect("Failed to deserialize");

    // Verify key properties match
    assert_eq!(bundle.media_type, bundle2.media_type);
    assert_eq!(
        bundle.verification_material.tlog_entries.len(),
        bundle2.verification_material.tlog_entries.len()
    );
}
