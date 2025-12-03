//! Tests for v0.3 bundle parsing and validation
//!
//! These tests use real bundle fixtures from the sigstore-python project.

use sigstore_bundle::{validate_bundle, validate_bundle_with_options, ValidationOptions};
use sigstore_types::{Bundle, LogIndex, MediaType};

/// Test bundle JSON from sigstore-python/test/assets/bundle_v3.txt.sigstore
const BUNDLE_V3_JSON: &str = r#"{
    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
    "verificationMaterial": {
        "certificate": {
            "rawBytes": "MIIC1DCCAlqgAwIBAgIUO3tlVbLtvLPp+6zGOtep1SPkRigwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjQwNDAyMTkxOTA5WhcNMjQwNDAyMTkyOTA5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENdrfpgNU1Rjmz+j65rpJWKc08ruKYy4FX7nmmOnbauFZimsQXrdyDSXKNRtEXX4X3t/Amt+euwPDBh+eq7BCnqOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUGRlBhD0wvzAfLb2dMWOgPrrJuRkwHwYDVR0jBBgwFoAUcYYwphR8Ym/599b0BRp/X//rb6wwIwYDVR0RAQH/BBkwF4EVd2lsbGlhbUB5b3NzYXJpYW4ubmV0MCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2ACswvNxoiMni4dgmKV50H0g5MZYC8pwzy15DQP6yrIZ6AAABjqBAQZ4AAAQDAEcwRQIgeWUmtnD0MFUl5kkX7nbMdLWCsDGIPzdIlN+WaZF0TmkCIQC7+31saqrFe9RmduVZ2dxXhUPrajltuSDHb1vSGOcuHjAKBggqhkjOPQQDAwNoADBlAjEAn2+uuLHsnH9Db7zkIdF65YhiXbgMMF//iHc+B/QETK0HYVcOPTK3p46FUzXFD6xrAjAO2hrkfjBKANKjJJxHV3FVrtS+TR0GCP0HzC3D7Br95TXzfO7+j4Dd8/N/aAr6Ibs="
        },
        "tlogEntries": [
            {
                "logIndex": "25915956",
                "logId": {
                    "keyId": "0y8wo8MtY5wrdiIFohx7sHeI5oKDpK5vQhGHI6G+pJY="
                },
                "kindVersion": {
                    "kind": "hashedrekord",
                    "version": "0.0.1"
                },
                "integratedTime": "1712085549",
                "inclusionPromise": {
                    "signedEntryTimestamp": "MEYCIQD2KXW1NppUhkPPzGR8NrUIyN+MzZSSqGZQO7CzvhSnYgIhAO9AHzjbsr1AHXRHmEpdPZcoFHEwwMTgfqwjoOXVMmqN"
                },
                "inclusionProof": {
                    "logIndex": "25901137",
                    "rootHash": "iGAoHccJIyFemFxmEftti2YC8hvPqixBi5y1EyvfF4c=",
                    "treeSize": "25901138",
                    "hashes": [
                        "UHUr+lvxENI+G902oEsFW5ovQILgqO9mUWWxvvwHZZc=",
                        "IcMBsbH3GRW8FX2CiL/ljMb45vzmENmhp5Yp/7IW998=",
                        "SxC6nr0zP+a6kWb6nO2fmEtz8BYAbqEXc+dsqGLdRPM=",
                        "sppZRSz/vdeLlavgvICrXHLeReMTJw98bs9HJ0I8WnE=",
                        "c8lCSuBS6MzrRnt6OiyYjqhTyxUI/22gpVB7dblfDis=",
                        "eJk64J6cMpIljPSX/72kH0kiIeElyypQm5vJ2gMMyHw=",
                        "hbIK+jmAwQjU7Yi3iKvnfR1u7GNippk7QsRwJXIuRaw=",
                        "tpHWIEB2vNU5ZmC68dj1Hh9cwQK083ozogA6zJ3cJ8A=",
                        "arvuzAipUJ14nDj14OBlvkMSicjdsE9Eus3hq9Jpqdk=",
                        "Edul4W41O3EfxKEEMlX2nW0+GTgCv00nGmcpwhALgVA=",
                        "rBWB37+HwkTZgDv0rMtGBUoDI0UZqcgDZp48M6CaUlA="
                    ],
                    "checkpoint": {
                        "envelope": "rekor.sigstage.dev - 8050909264565447525\n25901138\niGAoHccJIyFemFxmEftti2YC8hvPqixBi5y1EyvfF4c=\n\n— rekor.sigstage.dev 0y8wozBFAiAMJJLbnNOnmizMbVBz9/A/qnMK15BudWoZkuE+obD6CAIhAJf6A3h2iOpuhz/duEhG3fbAQG9PXln4wXPHFBT5wT1a\n"
                    }
                },
                "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI1ZTZhZTlkZTU4YzExNzdiZWE2MTViNGZjYmZiMmZkNjg4ZThjNGI1MWMyZTU2YjZhMzhlODE3ODMzZWMyNGEyIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJRFFTSmk5YWVydFFobVQrY2UxaktOZENlNEtTY3NLR3E5ZlBtMzQyMkRCU0FpRUFoajFzeFo5Nm9ySVRzUXh5TUxJRFJKaW1wb3kxSjFNeWZsY1FWd2tremhzPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTXhSRU5EUVd4eFowRjNTVUpCWjBsVlR6TjBiRlppVEhSMlRGQndLelo2UjA5MFpYQXhVMUJyVW1sbmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFJkMDVFUVhsTlZHdDRUMVJCTlZkb1kwNU5hbEYzVGtSQmVVMVVhM2xQVkVFMVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZPWkhKbWNHZE9WVEZTYW0xNksybzJOWEp3U2xkTFl6QTRjblZMV1hrMFJsZzNibTBLYlU5dVltRjFSbHBwYlhOUldISmtlVVJUV0V0T1VuUkZXRmcwV0ROMEwwRnRkQ3RsZFhkUVJFSm9LMlZ4TjBKRGJuRlBRMEZZYTNkblowWXhUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZIVW14Q0NtaEVNSGQyZWtGbVRHSXlaRTFYVDJkUWNuSktkVkpyZDBoM1dVUldVakJxUWtKbmQwWnZRVlZqV1ZsM2NHaFNPRmx0THpVNU9XSXdRbEp3TDFndkwzSUtZalozZDBsM1dVUldVakJTUVZGSUwwSkNhM2RHTkVWV1pESnNjMkpIYkdoaVZVSTFZak5PZWxsWVNuQlpWelIxWW0xV01FMURkMGREYVhOSFFWRlJRZ3BuTnpoM1FWRkZSVWh0YURCa1NFSjZUMms0ZGxveWJEQmhTRlpwVEcxT2RtSlRPWE5pTW1Sd1ltazVkbGxZVmpCaFJFRjFRbWR2Y2tKblJVVkJXVTh2Q2sxQlJVbENRMEZOU0cxb01HUklRbnBQYVRoMldqSnNNR0ZJVm1sTWJVNTJZbE01YzJJeVpIQmlhVGwyV1ZoV01HRkVRMEpwWjFsTFMzZFpRa0pCU0ZjS1pWRkpSVUZuVWpoQ1NHOUJaVUZDTWtGRGMzZDJUbmh2YVUxdWFUUmtaMjFMVmpVd1NEQm5OVTFhV1VNNGNIZDZlVEUxUkZGUU5ubHlTVm8yUVVGQlFncHFjVUpCVVZvMFFVRkJVVVJCUldOM1VsRkpaMlZYVlcxMGJrUXdUVVpWYkRWcmExZzNibUpOWkV4WFEzTkVSMGxRZW1SSmJFNHJWMkZhUmpCVWJXdERDa2xSUXpjck16RnpZWEZ5Um1VNVVtMWtkVlphTW1SNFdHaFZVSEpoYW14MGRWTkVTR0l4ZGxOSFQyTjFTR3BCUzBKblozRm9hMnBQVUZGUlJFRjNUbThLUVVSQ2JFRnFSVUZ1TWl0MWRVeEljMjVJT1VSaU4zcHJTV1JHTmpWWmFHbFlZbWROVFVZdkwybElZeXRDTDFGRlZFc3dTRmxXWTA5UVZFc3pjRFEyUmdwVmVsaEdSRFo0Y2tGcVFVOHlhSEpyWm1wQ1MwRk9TMnBLU25oSVZqTkdWbkowVXl0VVVqQkhRMUF3U0hwRE0wUTNRbkk1TlZSWWVtWlBOeXRxTkVSa0NqZ3ZUaTloUVhJMlNXSnpQUW90TFMwdExVVk9SQ0JEUlZKVVNVWkpRMEZVUlMwdExTMHRDZz09In19fX0="
            }
        ]
    },
    "messageSignature": {
        "messageDigest": {
            "algorithm": "SHA2_256",
            "digest": "Xmrp3ljBF3vqYVtPy/sv1ojoxLUcLla2o46BeDPsJKI="
        },
        "signature": "MEUCIDQSJi9aertQhmT+ce1jKNdCe4KScsKGq9fPm3422DBSAiEAhj1sxZ96orITsQxyMLIDRJimpoy1J1MyflcQVwkkzhs="
    }
}"#;

#[test]
fn test_parse_v3_bundle() {
    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();

    // Check media type
    assert_eq!(bundle.version().unwrap(), MediaType::Bundle0_3);

    // Check we have a certificate
    assert!(bundle.signing_certificate().is_some());

    // Check tlog entries
    assert_eq!(bundle.verification_material.tlog_entries.len(), 1);
    let entry = &bundle.verification_material.tlog_entries[0];
    assert_eq!(entry.log_index, LogIndex::new(25915956));
    assert_eq!(entry.integrated_time, 1712085549);
    assert_eq!(entry.kind_version.kind, "hashedrekord");
    assert_eq!(entry.kind_version.version, "0.0.1");

    // Check inclusion proof exists
    assert!(bundle.has_inclusion_proof());
    assert!(bundle.has_inclusion_promise());

    // Check inclusion proof details
    let proof = entry.inclusion_proof.as_ref().unwrap();
    assert_eq!(proof.log_index, LogIndex::new(25901137));
    assert_eq!(proof.tree_size, 25901138);
    assert_eq!(proof.hashes.len(), 11);
}

#[test]
fn test_validate_v3_bundle_structure() {
    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();

    // Validate with default options (requires inclusion proof)
    let result = validate_bundle(&bundle);
    assert!(result.is_ok(), "Validation failed: {:?}", result.err());
}

#[test]
fn test_validate_v3_bundle_with_options() {
    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();

    // Validate with custom options
    let options = ValidationOptions {
        require_inclusion_proof: true,
        require_timestamp: false,
    };

    let result = validate_bundle_with_options(&bundle, &options);
    assert!(result.is_ok(), "Validation failed: {:?}", result.err());
}

#[test]
fn test_v3_bundle_checkpoint_parsing() {
    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();
    let entry = &bundle.verification_material.tlog_entries[0];
    let proof = entry.inclusion_proof.as_ref().unwrap();

    // Parse the checkpoint
    let checkpoint = proof.checkpoint.parse().unwrap();

    assert_eq!(
        checkpoint.origin,
        "rekor.sigstage.dev - 8050909264565447525"
    );
    assert_eq!(checkpoint.tree_size, 25901138);
    assert_eq!(checkpoint.root_hash.as_bytes().len(), 32); // Sha256Hash is always 32 bytes
}

#[test]
fn test_v3_bundle_message_signature() {
    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();

    match &bundle.content {
        sigstore_types::bundle::SignatureContent::MessageSignature(sig) => {
            // Check signature is present
            assert!(!sig.signature.as_bytes().is_empty());

            // Check message digest
            let digest = sig.message_digest.as_ref().unwrap();
            assert_eq!(
                digest.algorithm,
                sigstore_types::hash::HashAlgorithm::Sha2256
            );
            assert!(!digest.digest.as_bytes().is_empty());
        }
        sigstore_types::bundle::SignatureContent::DsseEnvelope(_) => {
            panic!("Expected MessageSignature, got DsseEnvelope");
        }
    }
}

#[test]
fn test_v3_bundle_serialization_roundtrip() {
    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();

    // Serialize back to JSON
    let json = bundle.to_json().unwrap();

    // Parse again
    let bundle2 = Bundle::from_json(&json).unwrap();

    // Compare
    assert_eq!(bundle.media_type, bundle2.media_type);
    assert_eq!(
        bundle.verification_material.tlog_entries.len(),
        bundle2.verification_material.tlog_entries.len()
    );
}

#[test]
fn test_invalid_bundle_version() {
    let invalid_json = r#"{
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=9.9",
        "verificationMaterial": {
            "certificate": {"rawBytes": "dGVzdA=="},
            "tlogEntries": []
        },
        "messageSignature": {
            "signature": "dGVzdA=="
        }
    }"#;

    let bundle = Bundle::from_json(invalid_json).unwrap();
    assert!(bundle.version().is_err());
}

#[test]
fn test_v3_bundle_certificate_extraction() {
    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();

    // Get the certificate (raw DER bytes)
    let cert = bundle.signing_certificate().unwrap();
    let cert_bytes = cert.as_bytes();

    // DER-encoded certificate should start with SEQUENCE tag (0x30)
    assert_eq!(cert_bytes[0], 0x30);

    // Certificate should be reasonable size
    assert!(cert_bytes.len() > 100);
    assert!(cert_bytes.len() < 10000);
}

#[test]
fn test_inclusion_proof_verification() {
    use sigstore_merkle::{hash_leaf, verify_inclusion_proof};

    let bundle = Bundle::from_json(BUNDLE_V3_JSON).unwrap();
    let entry = &bundle.verification_material.tlog_entries[0];
    let proof = entry.inclusion_proof.as_ref().unwrap();

    // Get the canonicalized body bytes
    let body = entry.canonicalized_body.as_bytes();

    // Hash the leaf
    let leaf_hash = hash_leaf(body);

    // Proof hashes are already Vec<Sha256Hash>
    let proof_hashes = &proof.hashes;

    // Root hash is already a Sha256Hash
    let root_hash = &proof.root_hash;

    // Verify the inclusion proof
    let leaf_index: u64 = proof.log_index.as_u64().unwrap();
    let tree_size: u64 = proof.tree_size.try_into().unwrap();

    let result = verify_inclusion_proof(&leaf_hash, leaf_index, tree_size, proof_hashes, root_hash);

    assert!(
        result.is_ok(),
        "Inclusion proof verification failed: {:?}",
        result
    );
}
