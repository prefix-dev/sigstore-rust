//! Transparency log verification
//!
//! This module handles verification of transparency log entries including
//! checkpoint verification and SET (Signed Entry Timestamp) verification.

use crate::error::{Error, Result};
use base64::Engine;
use serde::Serialize;
use sigstore_crypto::{verify_signature, Checkpoint, SigningScheme};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::proto::{Bundle, InclusionProof, TransparencyLogEntry};
use sigstore_types::{LogKeyId, SignatureBytes};

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
    let vm = match bundle.verification_material() {
        Some(vm) => vm,
        None => return Ok(None),
    };

    let mut integrated_time_result: Option<i64> = None;

    for entry in vm.tlog_entries() {
        // Verify checkpoint signature if present
        if let Some(inclusion_proof) = entry.inclusion_proof() {
            if let Some(checkpoint_envelope) = inclusion_proof.checkpoint_envelope() {
                verify_checkpoint(checkpoint_envelope, &inclusion_proof, trusted_root)?;
            }
        }

        // Verify inclusion promise (SET) if present
        if entry.inclusion_promise().is_some() {
            verify_set(&entry, trusted_root)?;
        }

        // Validate integrated time
        let time = entry.integrated_time();
        // Ignore 0 as it indicates invalid/missing time (V2 entries)
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
    inclusion_proof: &InclusionProof<'_>,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    use sigstore_crypto::verify_signature_auto;

    // Parse the checkpoint (signed note)
    let checkpoint = Checkpoint::from_text(checkpoint_envelope)
        .map_err(|e| Error::Verification(format!("Failed to parse checkpoint: {}", e)))?;

    // Verify that the checkpoint's root hash matches the inclusion proof's root hash
    let checkpoint_root_hash = &checkpoint.root_hash;

    // The root hash in the inclusion proof is already a Sha256Hash
    let proof_root_hash = inclusion_proof.root_hash();

    if let Some(proof_root) = proof_root_hash {
        if checkpoint_root_hash.as_bytes() != proof_root.as_bytes() {
            return Err(Error::Verification(format!(
                "Checkpoint root hash mismatch: expected {}, got {}",
                checkpoint_root_hash.to_hex(),
                proof_root.to_hex()
            )));
        }
    } else {
        return Err(Error::Verification(
            "Inclusion proof missing root hash".to_string(),
        ));
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
pub fn verify_set(entry: &TransparencyLogEntry<'_>, trusted_root: &TrustedRoot) -> Result<()> {
    let promise = entry
        .inclusion_promise()
        .ok_or(Error::Verification("Missing inclusion promise".into()))?;

    // Get the log ID bytes
    let log_id_bytes = entry
        .log_id_bytes()
        .ok_or(Error::Verification("Missing log ID".into()))?;

    // Convert log ID bytes to base64 (LogKeyId format expected by trusted_root)
    let log_id_b64 = base64::engine::general_purpose::STANDARD.encode(log_id_bytes);
    let log_key_id = LogKeyId::new(log_id_b64);

    // Find the key for the log ID
    let log_key = trusted_root
        .rekor_key_for_log(&log_key_id)
        .map_err(|_| {
            Error::Verification(format!("Unknown log ID: {}", hex::encode(log_id_bytes)))
        })?;

    // Construct the payload (base64-encoded body)
    let body = base64::engine::general_purpose::STANDARD.encode(entry.canonicalized_body_bytes());

    let integrated_time = entry.integrated_time();
    let log_index = entry.log_index();

    // Log ID for payload must be hex encoded
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
    let signature = SignatureBytes::new(promise.as_bytes().to_vec());

    verify_signature(
        &log_key,
        &canonical_json,
        &signature,
        SigningScheme::EcdsaP256Sha256,
    )
    .map_err(|e| Error::Verification(format!("SET verification failed: {}", e)))?;

    Ok(())
}
