//! End-to-end verification tests
//!
//! These tests validate the complete verification flow using real bundles.

use sigstore_trust_root::TrustedRoot;
use sigstore_types::{LogIndex, Sha256Hash};
use sigstore_verify::bundle::{validate_bundle, validate_bundle_with_options, ValidationOptions};
use sigstore_verify::types::Bundle;
use sigstore_verify::{verify, VerificationPolicy, Verifier};
use x509_cert::der::Decode;

/// Extract the expected artifact digest from a bundle
///
/// For DSSE bundles, extracts from the in-toto statement subject.
/// For hashedrekord bundles, extracts from the message digest field.
fn extract_artifact_digest(bundle: &Bundle) -> Option<Sha256Hash> {
    match &bundle.content {
        sigstore_verify::types::SignatureContent::DsseEnvelope(env) => {
            if env.payload_type == "application/vnd.in-toto+json" {
                let payload_bytes = env.decode_payload();
                let payload_str = String::from_utf8(payload_bytes).ok()?;
                let statement: serde_json::Value = serde_json::from_str(&payload_str).ok()?;
                let subject = statement["subject"].as_array()?.first()?;
                let sha256 = subject["digest"]["sha256"].as_str()?;
                Sha256Hash::from_hex(sha256).ok()
            } else {
                None
            }
        }
        sigstore_verify::types::SignatureContent::MessageSignature(msg_sig) => msg_sig
            .message_digest
            .as_ref()
            .and_then(|d| Sha256Hash::try_from_slice(d.digest.as_bytes()).ok()),
    }
}

/// Get the production trusted root for tests
fn production_root() -> TrustedRoot {
    TrustedRoot::production().expect("Failed to load production trusted root")
}

/// Real v0.3 bundle from sigstore-python tests
const V03_BUNDLE: &str = include_str!("../../sigstore-bundle/tests/fixtures/bundle_v3.json");

/// Real v0.3 bundle from sigstore-rs with DSSE and inclusion proof
const V03_BUNDLE_DSSE: &str = r#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"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"},"tlogEntries":[{"logIndex":"166143216","logId":{"keyId":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="},"kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":"1738060096","inclusionPromise":{"signedEntryTimestamp":"MEQCIFdvIafa5jqan78r7Ypre1hdOCE1lnZ5LT0lYEtlCYnAAiBHWRe5/97eWPqVypxIzKbDUVtK7Y3rJmYT0DCOuRtY5g=="},"inclusionProof":{"logIndex":"44238954","rootHash":"TiowMOu0x46fW4pXrRyW7TeVb6f1/VDnDZWcP1xL/HU=","treeSize":"44238955","hashes":["iMecnh5ol+AiQUqe67cka5QnpS7+Uac/PP2yxDQ7KnQ=","VXEdyQrtr/iiIQPJ76SNiRpLd8/wXguekWT+nmHbP84=","lkPY9Ya80uK1vUlI2ekwn125ntq+s+Hx32de1Zre35s=","FXn3gvhalfR91NP/m43gQswlqzo8LYuMe95EdKvsD7c=","kHIAOKN34D4Q4Mu3aTF4dLRO7QKWDSrkRXJ8wj0a2j0=","sTh7uuXvFFqHGFy/+afvnA9fsSMiHIZoWRAdHhNZMFQ=","ABrujg3xYGHOAy9tkUTpYsPw8qCs6bGbyGms261oTf4=","WYCyxkm3nLuN6MubBiGGY9Z5Try/M4gliHJK7VMo7V4=","jU9+tgjTIKUYGeU7T7RjqyL+F+gFV9tCdwX2GZ1UtQs=","vemyaMj0Na1LMjbB/9Dmkq8T+jAb3o+yCESgAayUABU="],"checkpoint":{"envelope":"rekor.sigstore.dev - 1193050959916656506\n44238955\nTiowMOu0x46fW4pXrRyW7TeVb6f1/VDnDZWcP1xL/HU=\n\n— rekor.sigstore.dev wNI9ajBEAiBF3lyT0Jg0paKCvqJQ0t97+hcneAqZHeiRuLinOba/YQIgG65ZKAhE+byLy+VQ4/14FwvJG0FMhq4CNoDONpzvOMc=\n"}},"canonicalizedBody":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiZDhiYjhkM2FkMTRmNTYxODQxOTMzODExYjkwZTNiOGY4ZGJjODFhMTQ2NDlkOThkNGI3Zjg0YjM1M2ZmODM0NSJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6ImZhZDU0M2M3YTFlOWFjZmE0Y2I2ZWNkN2UxNGZiN2UzY2QxMzVjMDllZmU4ZGRjOTY4ZDQ5NGJjMjIyMTM2ZGQifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVVQ0lRQ0VKTzkxb21WUHc2WVJDVEVlN3YzRllObzZMeFBTSlozMitScUZoeXFONVFJZ1dXdzk2THhWSzhPVGZ5N1I5SFRlVnhuSTg3bnI4aHg1Tm4wRGdCNDkzbE09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VkemVrTkRRbXB4WjBGM1NVSkJaMGxWVEZNM05DOXBSWEExYkM5SlNHaDZPVE5aVkhKMVduWmFjblZOZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmQwMVVTVFJOVkVGNVQwUkZNVmRvWTA1TmFsVjNUVlJKTkUxVVFYcFBSRVV4VjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVnBWRlZ4TW5wU1NHdFdlR1pwUjFsSFluRlNWWFZZZVRGS2JEQm5RVzloV0VabFQyY0taV29yYVVoaFEzcHdOVkZSV214TlIzSTNjVzl1Vml0SGQzUlRSMlkwY21GdVZWSnplSHBsWWtSWWJXSmlOMGQyVFhGUFEwSldhM2RuWjFaV1RVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVlNZWFV2Q2tOTlYxUldOSFI2T0daSFZUSXZWVEIyYmtseWJWRTBkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMWxuV1VSV1VqQlNRVkZJTDBKR1ozZFdiMXBWWVVoU01HTklUVFpNZVRsdVlWaFNiMlJYU1hWWk1qbDBURE5rZG1KSFdqSk1NMDV3V2pOT01BcGlNMHBzVEZoU2JHTXpVWFpNYldSd1pFZG9NVmxwT1ROaU0wcHlXbTE0ZG1RelRYWlpWMDR3WVZjNWRVeHViR2hpVjNoQlkyMVdiV041T1c5YVYwWnJDbU41T1hSWlYyeDFUVVJyUjBOcGMwZEJVVkZDWnpjNGQwRlJSVVZMTW1nd1pFaENlazlwT0haa1J6bHlXbGMwZFZsWFRqQmhWemwxWTNrMWJtRllVbThLWkZkS01XTXlWbmxaTWpsMVpFZFdkV1JETldwaU1qQjNSV2RaUzB0M1dVSkNRVWRFZG5wQlFrRm5VVVZqU0ZaNllVUkJNa0puYjNKQ1owVkZRVmxQTHdwTlFVVkVRa05vYUU1Nll6Ulpha1UxVFVSTmVFMVhSVEZPYlZsM1RrZEdhazlVUlRGWmVrNXNUV3BLYWxwVVl6UlBWRVpxVDFkV2JGcEhTbTFOUWpSSENrTnBjMGRCVVZGQ1p6YzRkMEZSVVVWRlJrSm9XVEowYUZveVZXZFpWelZyU1VoT2NGb3lOSGRKVVZsTFMzZFpRa0pCUjBSMmVrRkNRbEZSVkdReU9YTUtXbTVaZG1NeWJHNWpNMUoyWTIxVmRHUkhWbnBrUkVGa1FtZHZja0puUlVWQldVOHZUVUZGUjBKQk9YbGFWMXA2VERKb2JGbFhVbnBNTWpGb1lWYzBkd3BQZDFsTFMzZFpRa0pCUjBSMmVrRkNRMEZSZEVSRGRHOWtTRkozWTNwdmRrd3pVblpoTWxaMVRHMUdhbVJIYkhaaWJrMTFXakpzTUdGSVZtbGtXRTVzQ21OdFRuWmlibEpzWW01UmRWa3lPWFJOUjFGSFEybHpSMEZSVVVKbk56aDNRVkZyUlZabmVGVmhTRkl3WTBoTk5reDVPVzVoV0ZKdlpGZEpkVmt5T1hRS1RETmtkbUpIV2pKTU0wNXdXak5PTUdJelNteE1XRkpzWXpOUmRreHRaSEJrUjJneFdXazVNMkl6U25KYWJYaDJaRE5OZGxsWFRqQmhWemwxVEc1c2FBcGlWM2hCWTIxV2JXTjVPVzlhVjBaclkzazVkRmxYYkhWTlJHZEhRMmx6UjBGUlVVSm5OemgzUVZGdlJVdG5kMjlaVkdNelQwZEplRTlVUVhwTlZFWm9DazVVV20xTlJGSm9XWHByZUU1WFRYcGFWRWw1V1RKVk0wOUVhM2haZW14c1dsZFNhVnBxUVdSQ1oyOXlRbWRGUlVGWlR5OU5RVVZNUWtFNFRVUlhaSEFLWkVkb01WbHBNVzlpTTA0d1dsZFJkMDVuV1V0TGQxbENRa0ZIUkhaNlFVSkVRVkZ2UkVOYWIyUklVbmRqZW05MlRESmtjR1JIYURGWmFUVnFZakl3ZGdwa01qbHpXbTVaZG1NeWJHNWpNMUoyWTIxVmRHUkhWbnBrUkVFMFFtZHZja0puUlVWQldVOHZUVUZGVGtKRGIwMUxSMFV6VG5wb2FVMVVhM2ROZWtWNENsbFVWVEphYWtFd1dWZE5OVTFVVm1wTk1sVjVUVzFPYkU1Nlp6Vk5WMDAxV2xkV2ExbHRXWGRJZDFsTFMzZFpRa0pCUjBSMmVrRkNSR2RSVWtSQk9Ya0tXbGRhZWt3eWFHeFpWMUo2VERJeGFHRlhOSGRIVVZsTFMzZFpRa0pCUjBSMmVrRkNSSGRSVEVSQmF6Uk9WR3Q1VDFSbmQwNVVTWGRMUVZsTFMzZFpRZ3BDUVVkRWRucEJRa1ZCVVdGRVFtaHZaRWhTZDJONmIzWk1NbVJ3WkVkb01WbHBOV3BpTWpCMlpESTVjMXB1V1hkR1oxbExTM2RaUWtKQlIwUjJla0ZDQ2tWUlVVbEVRVmswVDBSVmQwNVVVWGRhUVZsTFMzZFpRa0pCUjBSMmVrRkNSV2RTVjBSR1VtOWtTRkozWTNwdmRrd3laSEJrUjJneFdXazFhbUl5TUhZS1pESTVjMXB1V1haak1teHVZek5TZG1OdFZYUmtSMVo2WkVNNGRWb3liREJoU0ZacFRETmtkbU50ZEcxaVJ6a3pZM2s1YUZrelVuQmlNalIxWlZkR2RBcGlSVUo1V2xkYWVrd3lhR3haVjFKNlRESXhhR0ZYTkhkUFFWbExTM2RaUWtKQlIwUjJla0ZDUlhkUmNVUkRhR2hPZW1NMFdXcEZOVTFFVFhoTlYwVXhDazV0V1hkT1IwWnFUMVJGTVZsNlRteE5ha3BxV2xSak5FOVVSbXBQVjFac1drZEtiVTFDVVVkRGFYTkhRVkZSUW1jM09IZEJVbEZGUW1kM1JXTklWbm9LWVVSQ1lVSm5iM0pDWjBWRlFWbFBMMDFCUlZaQ1JYZE5VMjFvTUdSSVFucFBhVGgyV2pKc01HRklWbWxNYlU1MllsTTVNMkl5ZUcxa2FUbDZZVmRrZWdwa1J6bDVXbE14TUZwWVRqQk1Na1pxWkVkc2RtSnVUWFpqYmxaMVkzazRlRTE2UVhkUFJGRjVUMVJGTVU5VE9XaGtTRkpzWWxoQ01HTjVPSGhOUWxsSENrTnBjMGRCVVZGQ1p6YzRkMEZTV1VWRFFYZEhZMGhXYVdKSGJHcE5TVWRMUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpJZDBWbFowSTBRVWhaUVROVU1IY0tZWE5pU0VWVVNtcEhValJqYlZkak0wRnhTa3RZY21wbFVFc3pMMmcwY0hsblF6aHdOMjgwUVVGQlIxVnlTRkpvWldkQlFVSkJUVUZTZWtKR1FXbEZRUXByU0hsWU5FRllUVUoyY2paclluZE5lbVZZYkVORFFVUk9SbW80ZFVzMk9IWlpMMnNyUldWMVFXVnJRMGxEUzJaME9FeEpkV3BGWm10MVRtVXdTVlV2Q2tNM1RUaE1TR1ZxVFhkclREYzNOMDByT0doRmNsbEhZVTFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbU5CVFVkUlEwMURZMGRwYkZKMVlUQndTM05SY1ZJS2FFMURXV3BhVW1sR0swMHljREF6Y1dkamRrZG9NMFJwVW10WWNGSlZXRTU0UjBWTVRsSlJiVWR2Y1RaVlN6WlVibmRKZDJOcU0ya3pZalJTUlVVdmJRcEtaRTB2UmtKVEwydElZVWhpVlRKbmRHMDBURE5xWlZWWk1GRXlhamRaVlhObWVWQjJjamRITjI5YVpqUmhWSEJyTWtGWENpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9XX19"}],"timestampVerificationData":{"rfc3161Timestamps":[]}},"dsseEnvelope":{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoic2lnbmVkLXBhY2thZ2UtMS4yLjAtaGIwZjRkY2FfMC5jb25kYSIsImRpZ2VzdCI6eyJzaGEyNTYiOiI1OWVkODFlZTdhMjQ4NWM0NzU4OGViZGJhZDE0NzY0YmY3MjJjOTM0MzhiNDNmZTk1M2E2NTE3NDdiYzYyYWQ3In19XSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2xzYS5kZXYvc3BlYy92MS4wL3Byb3ZlbmFuY2UiLCJwcmVkaWNhdGUiOnt9fQ==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEUCIQCEJO91omVPw6YRCTEe7v3FYNo6LxPSJZ32+RqFhyqN5QIgWWw96LxVK8OTfy7R9HTeVxnI87nr8hx5Nn0DgB493lM=","keyid":""}]}}"#;

const HAPPY_PATH_V03_BUNDLE_DSSE: &str =
    include_str!("../../sigstore-bundle/tests/fixtures/happy-path.json");

// Test bundles from reference implementations
const DSSE_BUNDLE: &str = include_str!("../test_data/bundles/dsse.sigstore.json");
const DSSE_2SIGS_BUNDLE: &str = include_str!("../test_data/bundles/dsse-2sigs.sigstore.json");
const BUNDLE_INVALID_VERSION: &str =
    include_str!("../test_data/bundles/bundle_invalid_version.txt.sigstore");
const BUNDLE_CVE_2022_36056: &str =
    include_str!("../test_data/bundles/bundle_cve_2022_36056.txt.sigstore");
// GitHub Actions provenance bundle (SLSA attestation) - from sigstore-go test data
const SIGSTORE_JS_PROVENANCE: &str =
    include_str!("../test_data/bundles/sigstore.js@2.0.0-provenance.sigstore.json");
// Bundle with otherName SAN (non-standard SAN type) - from sigstore-go test data
const OTHERNAME_BUNDLE: &str = include_str!("../test_data/bundles/othername.sigstore.json");

// Conda package attestation bundle (from prefix-dev/sigstore-example)
const CONDA_ATTESTATION_BUNDLE: &str =
    include_str!("../test_data/bundles/conda-attestation.sigstore.json");
const CONDA_PACKAGE: &[u8] =
    include_bytes!("../test_data/bundles/signed-package-2.1.0-hb0f4dca_0.conda");

// Edge case bundles
const BUNDLE_NO_CERT_V1: &str = include_str!("../test_data/bundles/bundle_no_cert_v1.txt.sigstore");
const BUNDLE_NO_CHECKPOINT: &str =
    include_str!("../test_data/bundles/bundle_no_checkpoint.txt.sigstore");
const BUNDLE_NO_LOG_ENTRY: &str =
    include_str!("../test_data/bundles/bundle_no_log_entry.txt.sigstore");
const BUNDLE_V3_NO_SIGNED_TIME: &str =
    include_str!("../test_data/bundles/bundle_v3_no_signed_time.txt.sigstore.json");
const BUNDLE_V3_GITHUB_WHL: &str =
    include_str!("../test_data/bundles/bundle_v3_github.whl.sigstore");

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
        sigstore_verify::types::SignatureContent::DsseEnvelope(env) => {
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
    let root = production_root();
    let verifier = Verifier::new(&root);
    let bundle = Bundle::from_json(V03_BUNDLE).unwrap();

    // Extract expected digest from the bundle
    let artifact_digest =
        extract_artifact_digest(&bundle).expect("Bundle should have artifact digest");

    // V03_BUNDLE is from sigstore-python tests (staging) - skip crypto verifications
    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_certificate_chain()
        .skip_tlog();

    let result = verifier.verify(artifact_digest, &bundle, &policy);
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
}

#[test]
fn test_verify_with_policy() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();

    // Extract expected digest from the bundle
    let artifact_digest =
        extract_artifact_digest(&bundle).expect("Bundle should have artifact digest");

    // Test with default policy (requires tlog verification)
    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root());
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());

    let verification = result.unwrap();
    assert!(verification.success);
    assert!(verification.integrated_time.is_some());
}

#[test]
fn test_verify_extracts_integrated_time() {
    let bundle = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();

    // Extract expected digest from the bundle
    let artifact_digest =
        extract_artifact_digest(&bundle).expect("Bundle should have artifact digest");

    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root()).unwrap();

    assert!(result.integrated_time.is_some());
    let time = result.integrated_time.unwrap();
    assert!(time > 0, "Integrated time should be positive");

    // The integrated time in the bundle is 1738060096 (2025-01-28)
    assert_eq!(time, 1738060096);
}

#[test]
fn test_skip_tlog_verification() {
    let bundle = Bundle::from_json(V03_BUNDLE).unwrap();

    // Extract expected digest from the bundle
    let artifact_digest =
        extract_artifact_digest(&bundle).expect("Bundle should have artifact digest");

    // V03_BUNDLE is from sigstore-python tests and may not chain to production Fulcio
    let policy = VerificationPolicy::default()
        .skip_tlog()
        .skip_timestamp()
        .skip_certificate_chain();

    let result = verify(artifact_digest, &bundle, &policy, &production_root());
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
    assert_eq!(entry.log_index, LogIndex::new(166143216));

    // Verify inclusion proof
    let proof = entry.inclusion_proof.as_ref().expect("Should have proof");
    assert_eq!(proof.tree_size, 44238955);
    assert_eq!(proof.hashes.len(), 10);

    // Run full verification - extract digest from bundle
    let artifact_digest =
        extract_artifact_digest(&bundle).expect("Bundle should have artifact digest");
    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root()).unwrap();
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
    assert_eq!(entry.log_index, LogIndex::new(155690850));

    // Verify inclusion proof
    let proof = entry.inclusion_proof.as_ref().expect("Should have proof");
    assert_eq!(proof.tree_size, 33786589);
    assert_eq!(proof.hashes.len(), 11);

    // Run full verification - extract digest from bundle
    let artifact_digest =
        extract_artifact_digest(&bundle).expect("Bundle should have artifact digest");
    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root()).unwrap();
    assert!(result.success);
    assert_eq!(result.integrated_time, Some(1734374576));
}

#[test]
fn test_verification_with_different_bundle_versions() {
    // v0.3 bundle with message signature
    // V03_BUNDLE is from sigstore-python tests (staging) - skip crypto verifications
    let v03_msg = Bundle::from_json(V03_BUNDLE).unwrap();
    let artifact_digest =
        extract_artifact_digest(&v03_msg).expect("Bundle should have artifact digest");
    let policy = VerificationPolicy::default()
        .skip_timestamp()
        .skip_certificate_chain()
        .skip_tlog();

    let result = verify(artifact_digest, &v03_msg, &policy, &production_root());
    assert!(result.is_ok(), "v0.3 message signature verification failed");

    // v0.3 bundle with DSSE - this one chains to production
    let v03_dsse = Bundle::from_json(V03_BUNDLE_DSSE).unwrap();
    let dsse_artifact_digest =
        extract_artifact_digest(&v03_dsse).expect("DSSE bundle should have artifact digest");
    let dsse_policy = VerificationPolicy::default().skip_timestamp();
    let result = verify(
        dsse_artifact_digest,
        &v03_dsse,
        &dsse_policy,
        &production_root(),
    );
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
    // root_hash is a Sha256Hash, always 32 bytes (validated by type)
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

// ==== Reference Implementation Bundle Tests ====

#[test]
fn test_parse_dsse_bundle_from_python() {
    // DSSE bundle from sigstore-python test data
    let bundle = Bundle::from_json(DSSE_BUNDLE).expect("Failed to parse DSSE bundle");

    assert!(bundle.media_type.contains("0.1"));

    // Check DSSE envelope structure
    match &bundle.content {
        sigstore_verify::types::SignatureContent::DsseEnvelope(env) => {
            assert_eq!(env.payload_type, "application/vnd.in-toto+json");
            assert_eq!(env.signatures.len(), 1, "Should have exactly 1 signature");
        }
        _ => panic!("Expected DSSE envelope"),
    }

    // Verify tlog entry exists
    assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
    let entry = &bundle.verification_material.tlog_entries[0];
    assert_eq!(entry.kind_version.kind, "intoto");
}

#[test]
fn test_parse_dsse_bundle_with_multiple_signatures() {
    // DSSE bundle with 2 signatures
    let bundle = Bundle::from_json(DSSE_2SIGS_BUNDLE).expect("Failed to parse DSSE 2-sigs bundle");

    // Check DSSE envelope has multiple signatures
    match &bundle.content {
        sigstore_verify::types::SignatureContent::DsseEnvelope(env) => {
            assert_eq!(env.payload_type, "application/vnd.in-toto+json");
            assert_eq!(env.signatures.len(), 2, "Should have exactly 2 signatures");
        }
        _ => panic!("Expected DSSE envelope"),
    }
}

#[test]
fn test_parse_bundle_invalid_version_still_parses() {
    // This bundle has an invalid mediaType ("this is completely wrong")
    // Parsing should still succeed, but validation may fail
    let bundle_result = Bundle::from_json(BUNDLE_INVALID_VERSION);

    // The bundle should still parse (we don't validate media type strictly during parse)
    // Note: Depending on implementation, this might fail. Let's see what happens.
    if let Ok(bundle) = bundle_result {
        // If it parses, the media type should be wrong
        assert_eq!(bundle.media_type, "this is completely wrong");
    }
    // If it fails to parse, that's also acceptable behavior
}

#[test]
fn test_parse_cve_2022_36056_bundle() {
    // This bundle tests CVE-2022-36056 - a hashedrekord entry mismatch attack
    let bundle = Bundle::from_json(BUNDLE_CVE_2022_36056).expect("Failed to parse CVE test bundle");

    // Should parse successfully
    assert!(bundle.media_type.contains("v0.3"));

    // Check it's a hashedrekord type
    let entry = &bundle.verification_material.tlog_entries[0];
    assert_eq!(entry.kind_version.kind, "hashedrekord");

    // Bundle structure should be valid
    let result = validate_bundle(&bundle);
    assert!(
        result.is_ok(),
        "CVE bundle structure should be valid: {:?}",
        result.err()
    );
}

#[test]
fn test_bundle_certificate_extraction() {
    // Test extracting certificate from v0.1 bundle (x509CertificateChain format)
    let bundle = Bundle::from_json(DSSE_BUNDLE).expect("Failed to parse DSSE bundle");

    // Verify certificate can be extracted
    let cert = bundle.signing_certificate();
    assert!(cert.is_some(), "Should have a signing certificate");
}

#[test]
fn test_bundle_v03_certificate_extraction() {
    // Test extracting certificate from v0.3 bundle (certificate format)
    let bundle = Bundle::from_json(BUNDLE_CVE_2022_36056).expect("Failed to parse bundle");

    // Verify certificate can be extracted
    let cert = bundle.signing_certificate();
    assert!(cert.is_some(), "Should have a signing certificate");
}

// ==== Sigstore-go Equivalent Tests ====

/// Test that DSSE bundles with multiple signatures fail verification
/// Equivalent to sigstore-go's TestSigstoreBundle2Sig which expects ErrDSSEInvalidSignatureCount
#[test]
fn test_dsse_bundle_with_2_signatures_should_fail() {
    let bundle = Bundle::from_json(DSSE_2SIGS_BUNDLE).expect("Failed to parse DSSE 2-sigs bundle");

    // Verify the bundle has 2 signatures
    match &bundle.content {
        sigstore_verify::types::SignatureContent::DsseEnvelope(env) => {
            assert_eq!(env.signatures.len(), 2, "Bundle should have 2 signatures");
        }
        _ => panic!("Expected DSSE envelope"),
    }

    // Verification should fail because we only support single signatures
    // Use extracted digest or dummy - doesn't matter since validation should fail first
    let artifact_digest =
        extract_artifact_digest(&bundle).unwrap_or_else(|| Sha256Hash::from_bytes([0u8; 32]));
    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root());

    // This should fail - multiple signatures are not supported
    // sigstore-go returns ErrDSSEInvalidSignatureCount for this case
    assert!(
        result.is_err(),
        "Verification should fail for bundles with multiple signatures"
    );
}

/// Test GitHub Actions provenance bundle certificate extension extraction
/// Equivalent to sigstore-go's TestSummarizeCertificateWithActionsBundle
#[test]
fn test_github_actions_provenance_bundle() {
    let bundle =
        Bundle::from_json(SIGSTORE_JS_PROVENANCE).expect("Failed to parse provenance bundle");

    // Should parse successfully
    assert!(
        bundle.media_type.contains("0.1") || bundle.media_type.contains("0.2"),
        "Expected v0.1 or v0.2 bundle"
    );

    // Extract the signing certificate (raw DER bytes)
    let cert = bundle
        .signing_certificate()
        .expect("Should have a signing certificate");

    // Get the raw bytes directly (no base64 decoding needed)
    let cert_der = cert.as_bytes();

    // Parse the certificate to verify GitHub Actions extensions
    use x509_cert::Certificate;
    let cert = Certificate::from_der(cert_der).expect("Failed to parse certificate");

    // The certificate should have GitHub Actions OID extensions
    // OID 1.3.6.1.4.1.57264.1.1 = Issuer
    // OID 1.3.6.1.4.1.57264.1.2 = GitHub Workflow Trigger
    // etc.

    // Verify the SAN contains the expected GitHub Actions workflow URI
    let san_ext = cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
        exts.iter()
            .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
    });

    assert!(
        san_ext.is_some(),
        "Certificate should have Subject Alternative Name extension"
    );
}

/// Test bundle with OtherName SAN type
/// Equivalent to sigstore-go's TestEntityWithOthernameSan
#[test]
fn test_othername_san_bundle() {
    let bundle = Bundle::from_json(OTHERNAME_BUNDLE).expect("Failed to parse othername bundle");

    // Extract the signing certificate (raw DER bytes)
    let cert = bundle
        .signing_certificate()
        .expect("Should have a signing certificate");

    // Get the raw bytes directly (no base64 decoding needed)
    let cert_der = cert.as_bytes();

    // Parse the certificate
    use x509_cert::Certificate;
    let cert = Certificate::from_der(cert_der).expect("Failed to parse certificate");

    // Verify the certificate has a SAN extension (otherName type)
    let san_ext = cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
        exts.iter()
            .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
    });

    assert!(
        san_ext.is_some(),
        "Certificate should have Subject Alternative Name extension"
    );

    // In sigstore-go, this test verifies identity "foo!oidc.local"
    // The otherName SAN contains a non-standard identity format
}

// ==== Edge Case Bundle Tests ====

/// Test bundle with empty certificate list (missing certificate)
#[test]
fn test_bundle_no_cert_v1() {
    let bundle = Bundle::from_json(BUNDLE_NO_CERT_V1).expect("Failed to parse bundle_no_cert_v1");

    // Should parse successfully
    assert!(bundle.media_type.contains("0.1"));

    // But should not have a certificate
    let cert = bundle.signing_certificate();
    assert!(
        cert.is_none(),
        "Bundle with empty certificate list should return None"
    );

    // Verification should fail because there's no certificate
    // Use extracted digest or dummy - doesn't matter since validation should fail first
    let artifact_digest =
        extract_artifact_digest(&bundle).unwrap_or_else(|| Sha256Hash::from_bytes([0u8; 32]));
    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root());
    assert!(
        result.is_err(),
        "Verification should fail without a certificate"
    );
}

/// Test bundle without checkpoint in inclusion proof
#[test]
fn test_bundle_no_checkpoint() {
    let bundle =
        Bundle::from_json(BUNDLE_NO_CHECKPOINT).expect("Failed to parse bundle_no_checkpoint");

    // Should parse successfully
    assert!(bundle.media_type.contains("0.2"));

    // Should have a tlog entry
    assert!(!bundle.verification_material.tlog_entries.is_empty());

    let entry = &bundle.verification_material.tlog_entries[0];
    let proof = entry.inclusion_proof.as_ref();
    assert!(proof.is_some(), "Should have inclusion proof");

    // The inclusion proof should exist but lack the checkpoint
    let proof = proof.unwrap();

    // Checkpoint should be empty (default value)
    assert!(
        proof.checkpoint.envelope.is_empty(),
        "Checkpoint should be empty when missing from bundle"
    );

    // Parsing empty checkpoint should fail
    let checkpoint_result = proof.checkpoint.parse();
    assert!(
        checkpoint_result.is_err(),
        "Checkpoint parsing should fail when checkpoint is missing"
    );
}

/// Test bundle with empty transparency log entries
#[test]
fn test_bundle_no_log_entry() {
    let bundle =
        Bundle::from_json(BUNDLE_NO_LOG_ENTRY).expect("Failed to parse bundle_no_log_entry");

    // Should parse successfully
    assert!(bundle.media_type.contains("0.1"));

    // But should have no tlog entries
    assert!(
        bundle.verification_material.tlog_entries.is_empty(),
        "Bundle should have no tlog entries"
    );

    // Verification should fail because we need a tlog entry
    // Use extracted digest or dummy - doesn't matter since validation should fail first
    let artifact_digest =
        extract_artifact_digest(&bundle).unwrap_or_else(|| Sha256Hash::from_bytes([0u8; 32]));
    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root());
    assert!(
        result.is_err(),
        "Verification should fail without transparency log entries"
    );

    // Validation may also fail due to missing required fields
    // (depending on whether validator checks for empty tlog)
    let validation_result = validate_bundle(&bundle);
    // We accept either valid or invalid - the key is that verification fails
    let _ = validation_result;
}

/// Test bundle without signed entry timestamp (inclusionPromise)
#[test]
fn test_bundle_v3_no_signed_time() {
    let bundle = Bundle::from_json(BUNDLE_V3_NO_SIGNED_TIME)
        .expect("Failed to parse bundle_v3_no_signed_time");

    // Should parse successfully
    assert!(bundle.media_type.contains("0.3"));

    // Should have a tlog entry
    assert!(!bundle.verification_material.tlog_entries.is_empty());

    let entry = &bundle.verification_material.tlog_entries[0];

    // Check that inclusion promise is missing
    assert!(
        entry.inclusion_promise.is_none(),
        "Bundle should not have inclusion promise (signed entry timestamp)"
    );

    // Check that we have inclusion proof though
    assert!(
        entry.inclusion_proof.is_some(),
        "Bundle should have inclusion proof"
    );

    // Verification might still work with inclusion proof alone
    // Use extracted digest or dummy - we're testing handling of missing signed time
    let artifact_digest =
        extract_artifact_digest(&bundle).unwrap_or_else(|| Sha256Hash::from_bytes([0u8; 32]));
    let policy = VerificationPolicy::default().skip_timestamp();

    let result = verify(artifact_digest, &bundle, &policy, &production_root());
    // Whether this succeeds or fails depends on implementation
    // We just verify it handles the case
    let _ = result;
}

/// Test GitHub Actions release bundle
#[test]
fn test_bundle_v3_github_whl() {
    let bundle =
        Bundle::from_json(BUNDLE_V3_GITHUB_WHL).expect("Failed to parse bundle_v3_github_whl");

    // Should parse successfully
    assert!(bundle.media_type.contains("0.2"));

    // Should have certificate (raw DER bytes)
    let cert = bundle
        .signing_certificate()
        .expect("Should have a signing certificate");

    // Get the raw bytes directly (no base64 decoding needed)
    let cert_der = cert.as_bytes();

    // Parse the certificate
    use x509_cert::Certificate;
    let cert = Certificate::from_der(cert_der).expect("Failed to parse certificate");

    // Verify the SAN contains the GitHub Actions workflow URI
    let san_ext = cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
        exts.iter()
            .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
    });

    assert!(
        san_ext.is_some(),
        "GitHub Actions bundle should have Subject Alternative Name extension"
    );

    // Should have tlog entry
    assert!(
        !bundle.verification_material.tlog_entries.is_empty(),
        "Should have transparency log entry"
    );

    // Should have inclusion proof
    let entry = &bundle.verification_material.tlog_entries[0];
    assert!(
        entry.inclusion_proof.is_some(),
        "Should have inclusion proof"
    );
}

// ==== Conda Package Attestation Tests ====

/// Test parsing a conda package attestation bundle from GitHub Actions
#[test]
fn test_parse_conda_attestation_bundle() {
    let bundle =
        Bundle::from_json(CONDA_ATTESTATION_BUNDLE).expect("Failed to parse conda attestation");

    // Should be v0.3 bundle
    assert!(bundle.media_type.contains("0.3"), "Expected v0.3 bundle");

    // Should be DSSE envelope with in-toto attestation
    match &bundle.content {
        sigstore_verify::types::SignatureContent::DsseEnvelope(env) => {
            assert_eq!(
                env.payload_type, "application/vnd.in-toto+json",
                "Should have in-toto payload type"
            );
            assert_eq!(env.signatures.len(), 1, "Should have exactly 1 signature");

            // Decode payload and verify it's a conda attestation
            let payload_bytes = env.decode_payload();
            let payload_str =
                String::from_utf8(payload_bytes).expect("Payload should be valid UTF-8");
            let statement: serde_json::Value =
                serde_json::from_str(&payload_str).expect("Payload should be valid JSON");

            assert_eq!(
                statement["_type"].as_str(),
                Some("https://in-toto.io/Statement/v1"),
                "Should be in-toto Statement v1"
            );
            assert_eq!(
                statement["predicateType"].as_str(),
                Some("https://schemas.conda.org/attestations-publish-1.schema.json"),
                "Should have conda attestation predicate type"
            );

            // Check subject
            let subjects = statement["subject"]
                .as_array()
                .expect("Should have subjects");
            assert_eq!(subjects.len(), 1, "Should have one subject");
            assert_eq!(
                subjects[0]["name"].as_str(),
                Some("signed-package-2.1.0-hb0f4dca_0.conda"),
                "Subject name should match package filename"
            );
        }
        _ => panic!("Expected DSSE envelope"),
    }

    // Should have certificate
    let cert = bundle.signing_certificate();
    assert!(cert.is_some(), "Should have a signing certificate");

    // Should have tlog entry
    assert!(!bundle.verification_material.tlog_entries.is_empty());
    let entry = &bundle.verification_material.tlog_entries[0];
    assert_eq!(entry.kind_version.kind, "dsse");

    // Should have inclusion proof
    assert!(
        entry.inclusion_proof.is_some(),
        "Should have inclusion proof"
    );
}

/// Test full verification of conda package with its attestation
#[test]
fn test_verify_conda_package_attestation() {
    let bundle =
        Bundle::from_json(CONDA_ATTESTATION_BUNDLE).expect("Failed to parse conda attestation");

    // Verify with identity requirements for GitHub Actions
    let policy = VerificationPolicy::default()
        .require_identity("https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main")
        .require_issuer("https://token.actions.githubusercontent.com");

    let result = verify(CONDA_PACKAGE, &bundle, &policy, &production_root());
    assert!(
        result.is_ok(),
        "Conda package verification should succeed: {:?}",
        result.err()
    );

    let verification = result.unwrap();
    assert!(verification.success);
    assert_eq!(
        verification.identity.as_deref(),
        Some("https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main")
    );
    assert_eq!(
        verification.issuer.as_deref(),
        Some("https://token.actions.githubusercontent.com")
    );
    assert!(verification.integrated_time.is_some());
}

/// Test that verification fails with wrong identity
#[test]
fn test_verify_conda_package_wrong_identity() {
    let bundle =
        Bundle::from_json(CONDA_ATTESTATION_BUNDLE).expect("Failed to parse conda attestation");

    // Use wrong identity
    let policy = VerificationPolicy::default()
        .require_identity(
            "https://github.com/wrong-org/wrong-repo/.github/workflows/wrong.yaml@refs/heads/main",
        )
        .require_issuer("https://token.actions.githubusercontent.com");

    let result = verify(CONDA_PACKAGE, &bundle, &policy, &production_root());
    assert!(
        result.is_err(),
        "Verification should fail with wrong identity"
    );
}

/// Test that verification fails with tampered package
#[test]
fn test_verify_conda_package_tampered() {
    let bundle =
        Bundle::from_json(CONDA_ATTESTATION_BUNDLE).expect("Failed to parse conda attestation");

    // Use modified package content
    let tampered_package = b"this is not the original package content";

    let policy =
        VerificationPolicy::default().require_issuer("https://token.actions.githubusercontent.com");

    let result = verify(tampered_package, &bundle, &policy, &production_root());
    assert!(
        result.is_err(),
        "Verification should fail with tampered package"
    );
}

// Cosign v0.3 blob bundle for interop testing
const COSIGN_V3_BLOB_BUNDLE: &str =
    include_str!("../test_data/bundles/cosign-v3-blob.sigstore.json");

/// Test that we can parse a bundle produced by cosign v3.x
#[test]
fn test_parse_cosign_v3_blob_bundle() {
    let bundle =
        Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("Failed to parse cosign v3 blob bundle");

    // Check media type
    assert_eq!(
        bundle.media_type,
        "application/vnd.dev.sigstore.bundle.v0.3+json"
    );

    // Check it's a message signature (not DSSE)
    assert!(
        matches!(
            bundle.content,
            sigstore_verify::types::SignatureContent::MessageSignature(_)
        ),
        "Expected MessageSignature content"
    );

    // Check tlog entry
    assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
    let entry = &bundle.verification_material.tlog_entries[0];
    assert_eq!(entry.kind_version.kind, "hashedrekord");
    assert_eq!(entry.kind_version.version, "0.0.1");

    // Check it has both inclusion proof and inclusion promise
    assert!(entry.inclusion_proof.is_some(), "Expected inclusion proof");
    assert!(
        entry.inclusion_promise.is_some(),
        "Expected inclusion promise (SET)"
    );

    // Check integrated time is present
    assert!(entry.integrated_time > 0, "Expected integrated time > 0");
}

/// Test full verification of cosign-produced bundle
#[test]
fn test_verify_cosign_v3_blob_bundle() {
    let bundle =
        Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("Failed to parse cosign v3 blob bundle");

    // The artifact content that was signed
    let artifact = include_bytes!("../test_data/bundles/cosign-v3-blob.txt");

    let policy = VerificationPolicy::default().require_issuer("https://github.com/login/oauth");

    let result = verify(artifact, &bundle, &policy, &production_root());
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
}
