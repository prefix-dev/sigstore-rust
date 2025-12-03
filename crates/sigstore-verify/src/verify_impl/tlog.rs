//! Transparency log verification
//!
//! This module handles verification of transparency log entries including
//! checkpoint verification and SET (Signed Entry Timestamp) verification.

use crate::error::{Error, Result};
use base64::Engine;
use serde::Serialize;
use sigstore_crypto::{verify_signature, Checkpoint, SigningScheme};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::bundle::InclusionProof;
use sigstore_types::{Bundle, SignatureBytes, TransparencyLogEntry};

/// Verify transparency log entries (checkpoints and SETs)
///
/// # Arguments
/// * `bundle` - The bundle containing transparency log entries
/// * `trusted_root` - Trusted root for cryptographic verification
/// * `not_before` - Certificate validity start time (Unix timestamp)
/// * `not_after` - Certificate validity end time (Unix timestamp)
/// * `clock_skew_seconds` - Tolerance in seconds for future time checks
pub fn verify_tlog_entries(
    bundle: &Bundle,
    trusted_root: &TrustedRoot,
    not_before: i64,
    not_after: i64,
    clock_skew_seconds: i64,
) -> Result<Option<i64>> {
    let mut integrated_time_result: Option<i64> = None;

    for entry in &bundle.verification_material.tlog_entries {
        // Verify checkpoint signature if present
        if let Some(ref inclusion_proof) = entry.inclusion_proof {
            verify_checkpoint(
                &inclusion_proof.checkpoint.envelope,
                inclusion_proof,
                trusted_root,
            )?;
        }

        // Verify inclusion promise (SET) if present
        if entry.inclusion_promise.is_some() {
            verify_set(entry, trusted_root)?;
        }

        // Validate integrated time (0 indicates missing/invalid time in v2 entries)
        let time = entry.integrated_time;
        if time > 0 {
            // Check that integrated time is not in the future (with clock skew tolerance)
            let now = chrono::Utc::now().timestamp();
            if time > now + clock_skew_seconds {
                return Err(Error::Verification(format!(
                    "integrated time {} is in the future (current time: {}, tolerance: {}s)",
                    time, now, clock_skew_seconds
                )));
            }

            // Check that integrated time is within certificate validity period
            if time < not_before {
                return Err(Error::Verification(format!(
                    "integrated time {} is before certificate validity (not_before: {})",
                    time, not_before
                )));
            }

            if time > not_after {
                return Err(Error::Verification(format!(
                    "integrated time {} is after certificate validity (not_after: {})",
                    time, not_after
                )));
            }

            integrated_time_result = Some(time);
        }
    }

    Ok(integrated_time_result)
}

/// Verify a checkpoint signature using the trusted root
pub fn verify_checkpoint(
    checkpoint_envelope: &str,
    inclusion_proof: &InclusionProof,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    use sigstore_crypto::verify_signature_auto;

    // Parse the checkpoint (signed note)
    let checkpoint = Checkpoint::from_text(checkpoint_envelope)
        .map_err(|e| Error::Verification(format!("Failed to parse checkpoint: {}", e)))?;

    // Verify that the checkpoint's root hash matches the inclusion proof's root hash
    let checkpoint_root_hash = &checkpoint.root_hash;

    // The root hash in the inclusion proof is already a Sha256Hash
    let proof_root_hash = &inclusion_proof.root_hash;

    if checkpoint_root_hash.as_bytes() != proof_root_hash.as_bytes() {
        return Err(Error::Verification(format!(
            "Checkpoint root hash mismatch: expected {}, got {}",
            checkpoint_root_hash.to_hex(),
            proof_root_hash.to_hex()
        )));
    }

    // Get all Rekor keys with their key hints from trusted root
    let rekor_keys = trusted_root
        .rekor_keys_with_hints()
        .map_err(|e| Error::Verification(format!("Failed to get Rekor keys: {}", e)))?;

    // For each signature in the checkpoint, try to find a matching key and verify
    for sig in &checkpoint.signatures {
        // Find the key with matching key hint
        for (key_hint, public_key) in &rekor_keys {
            if &sig.key_id == key_hint {
                // Found matching key, verify the signature using automatic key type detection
                let message = checkpoint.signed_data();

                verify_signature_auto(public_key, &sig.signature, message).map_err(|e| {
                    Error::Verification(format!("Checkpoint signature verification failed: {}", e))
                })?;

                return Ok(());
            }
        }
    }

    Err(Error::Verification(
        "No matching Rekor key found for checkpoint signature".to_string(),
    ))
}

#[derive(Serialize)]
struct RekorPayload {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logIndex")]
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

/// Verify SET (Signed Entry Timestamp)
pub fn verify_set(entry: &TransparencyLogEntry, trusted_root: &TrustedRoot) -> Result<()> {
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or(Error::Verification("Missing inclusion promise".into()))?;

    // Find the key for the log ID
    let log_key = trusted_root
        .rekor_key_for_log(&entry.log_id.key_id)
        .map_err(|_| Error::Verification(format!("Unknown log ID: {}", entry.log_id.key_id)))?;

    // Construct the payload (base64-encoded body)
    let body = entry.canonicalized_body.to_base64();

    let integrated_time = entry.integrated_time;
    let log_index = entry
        .log_index
        .as_u64()
        .ok_or_else(|| Error::Verification("Invalid log index".into()))? as i64;

    // Log ID for payload must be hex encoded
    let log_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(entry.log_id.key_id.as_str())
        .map_err(|_| Error::Verification("Invalid base64 log ID".into()))?;
    let log_id_hex = hex::encode(log_id_bytes);

    let payload = RekorPayload {
        body,
        integrated_time,
        log_index,
        log_id: log_id_hex,
    };

    let canonical_json = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|e| Error::Verification(format!("Canonicalization failed: {}", e)))?;

    // Get signature bytes from signed timestamp
    let signature = SignatureBytes::new(promise.signed_entry_timestamp.as_bytes().to_vec());

    verify_signature(
        &log_key,
        &canonical_json,
        &signature,
        SigningScheme::EcdsaP256Sha256,
    )
    .map_err(|e| Error::Verification(format!("SET verification failed: {}", e)))?;

    Ok(())
}
