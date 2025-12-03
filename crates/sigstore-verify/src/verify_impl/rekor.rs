//! Rekor transparency log entry validation
//!
//! This module handles validation of different Rekor entry types against
//! bundle content to ensure consistency.

use crate::error::{Error, Result};
use base64::Engine;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::proto::{Bundle, DsseEnvelope, TransparencyLogEntry};

/// Verify DSSE envelope matches Rekor entry (for DSSE bundles)
pub fn verify_dsse_entries(bundle: &Bundle) -> Result<()> {
    let envelope = match bundle.dsse_envelope() {
        Some(env) => env,
        None => return Ok(()), // Not a DSSE bundle
    };

    let vm = match bundle.verification_material() {
        Some(vm) => vm,
        None => return Ok(()),
    };

    for entry in vm.tlog_entries() {
        let kind = entry.kind().unwrap_or("");
        let version = entry.version().unwrap_or("");

        if kind == "dsse" {
            match version {
                "0.0.1" => verify_dsse_v001(&entry, &envelope, bundle)?,
                "0.0.2" => verify_dsse_v002(&entry, &envelope, bundle)?,
                _ => {} // Unknown version, skip
            }
        }
    }

    Ok(())
}

/// Verify DSSE v0.0.1 entry
///
/// NOTE: This does NOT verify the envelope hash.
/// The envelope hash in DSSE v0.0.1 entries cannot be reliably verified because:
/// 1. The hash is computed over uncanonicalized JSON during submission to Rekor
/// 2. JSON serialization can vary (field ordering, whitespace) between implementations
/// 3. We cannot reproduce the exact JSON representation that was originally submitted
///
/// Instead, we verify:
/// - Payload hash (hash of envelope.payload bytes)
/// - Signatures list matches between entry and envelope (both signature and verifier)
fn verify_dsse_v001(
    entry: &TransparencyLogEntry<'_>,
    envelope: &DsseEnvelope<'_>,
    bundle: &Bundle,
) -> Result<()> {
    let kind = entry.kind().unwrap_or("dsse");
    let version = entry.version().unwrap_or("0.0.1");
    let body_bytes = entry.canonicalized_body_bytes();
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(body_bytes);

    let body = RekorEntryBody::from_base64_json(&body_b64, kind, version)
        .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV001(dsse_body) => (
            &dsse_body.spec.payload_hash.value,
            &dsse_body.spec.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.1 body, got different type".to_string(),
            ))
        }
    };

    // Verify payload hash (v0.0.1 uses hex encoding)
    let payload_bytes = envelope.payload();
    let payload_hash = sigstore_crypto::sha256(payload_bytes);
    let payload_hash_hex = hex::encode(payload_hash);

    if &payload_hash_hex != expected_hash {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            payload_hash_hex, expected_hash
        )));
    }

    // Extract the signing certificate from the bundle
    let cert = bundle
        .signing_certificate()
        .ok_or_else(|| Error::Verification("no signing certificate in bundle".to_string()))?;

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    // IMPORTANT: We must verify BOTH the signature bytes AND the verifier (certificate)
    if envelope.signatures_count() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures_count(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    // We must match both the signature AND the verifier to prevent signature substitution
    for (_keyid, bundle_sig) in envelope.signatures() {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            // Convert Rekor's PEM verifier to DER for canonical comparison
            let rekor_cert_der = rekor_sig
                .to_certificate()
                .map_err(|e| Error::Verification(format!("{}", e)))?;

            // Compare both signature bytes AND the verifier (certificate as DER)
            if bundle_sig == rekor_sig.signature.as_bytes()
                && cert.as_bytes() == rekor_cert_der.as_bytes()
            {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry (signature or verifier mismatch)".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify DSSE v0.0.2 entry (payload hash and signature validation)
fn verify_dsse_v002(
    entry: &TransparencyLogEntry<'_>,
    envelope: &DsseEnvelope<'_>,
    bundle: &Bundle,
) -> Result<()> {
    let kind = entry.kind().unwrap_or("dsse");
    let version = entry.version().unwrap_or("0.0.2");
    let body_bytes = entry.canonicalized_body_bytes();
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(body_bytes);

    let body = RekorEntryBody::from_base64_json(&body_b64, kind, version)
        .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV002(dsse_body) => (
            &dsse_body.spec.dsse_v002.payload_hash.digest,
            &dsse_body.spec.dsse_v002.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.2 body, got different type".to_string(),
            ))
        }
    };

    // Compute actual payload hash
    let payload_bytes = envelope.payload();
    let payload_hash = sigstore_crypto::sha256(payload_bytes);

    // Compare hashes (expected_hash is Vec<u8>)
    if payload_hash.as_slice() != expected_hash.as_slice() {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            hex::encode(payload_hash),
            hex::encode(expected_hash)
        )));
    }

    // Extract the signing certificate from the bundle
    let cert = bundle
        .signing_certificate()
        .ok_or_else(|| Error::Verification("no signing certificate in bundle".to_string()))?;

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    // IMPORTANT: We must verify BOTH the signature bytes AND the verifier (certificate)

    if envelope.signatures_count() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures_count(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    // We must match both the signature AND the verifier to prevent signature substitution
    for (_keyid, bundle_sig) in envelope.signatures() {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            // Compare both signature bytes AND the verifier (certificate)
            // The signature field in the bundle is SignatureBytes, compare as bytes
            // The verifier contains the x509Certificate.rawBytes (DerCertificate)
            if bundle_sig == rekor_sig.content.as_bytes()
                && cert.as_bytes() == rekor_sig.verifier.x509_certificate.raw_bytes.as_bytes()
            {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry (signature or verifier mismatch)".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify DSSE payload matches what's in Rekor (for intoto entries)
pub fn verify_intoto_entries(bundle: &Bundle) -> Result<()> {
    let envelope = match bundle.dsse_envelope() {
        Some(env) => env,
        None => return Ok(()), // Not a DSSE bundle
    };

    let vm = match bundle.verification_material() {
        Some(vm) => vm,
        None => return Ok(()),
    };

    for entry in vm.tlog_entries() {
        let kind = entry.kind().unwrap_or("");
        if kind == "intoto" {
            verify_intoto_v002(&entry, &envelope)?;
        }
    }

    Ok(())
}

/// Verify intoto v0.0.2 entry
fn verify_intoto_v002(entry: &TransparencyLogEntry<'_>, envelope: &DsseEnvelope<'_>) -> Result<()> {
    let kind = entry.kind().unwrap_or("intoto");
    let version = entry.version().unwrap_or("0.0.2");
    let body_bytes = entry.canonicalized_body_bytes();
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(body_bytes);

    let body = RekorEntryBody::from_base64_json(&body_b64, kind, version)
        .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (rekor_payload_b64, rekor_signatures) = match &body {
        RekorEntryBody::IntotoV002(intoto_body) => (
            &intoto_body.spec.content.envelope.payload,
            &intoto_body.spec.content.envelope.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected Intoto v0.0.2 body, got different type".to_string(),
            ))
        }
    };

    // The Rekor entry has the payload double-base64-encoded, decode it once
    let rekor_payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(rekor_payload_b64.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to decode Rekor payload: {}", e)))?;

    // Compare with bundle payload bytes
    if envelope.payload() != rekor_payload_bytes.as_slice() {
        return Err(Error::Verification(
            "DSSE payload in bundle does not match intoto Rekor entry".to_string(),
        ));
    }

    // Validate that the signatures match
    let mut found_match = false;
    for (_keyid, bundle_sig) in envelope.signatures() {
        for rekor_sig in rekor_signatures {
            // The Rekor signature is also double-base64-encoded, decode it once
            let rekor_sig_decoded = base64::engine::general_purpose::STANDARD
                .decode(rekor_sig.sig.as_bytes())
                .map_err(|e| {
                    Error::Verification(format!("failed to decode Rekor signature: {}", e))
                })?;

            if bundle_sig == rekor_sig_decoded.as_slice() {
                found_match = true;
                break;
            }
        }
        if found_match {
            break;
        }
    }

    if !found_match {
        return Err(Error::Verification(
            "DSSE signature in bundle does not match intoto Rekor entry".to_string(),
        ));
    }

    Ok(())
}
