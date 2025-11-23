//! Transparency log verification
//!
//! This module handles verification of transparency log entries including
//! checkpoint verification and SET (Signed Entry Timestamp) verification.

use crate::error::{Error, Result};
use base64::Engine;
use serde::Serialize;
use sigstore_crypto::{verify_signature, SignedNote, SigningScheme};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::bundle::InclusionProof;
use sigstore_types::{Bundle, TransparencyLogEntry};

/// Verify transparency log entries (checkpoints and SETs)
pub fn verify_tlog_entries(
    bundle: &Bundle,
    trusted_root: Option<&TrustedRoot>,
    not_before: i64,
    not_after: i64,
) -> Result<Option<i64>> {
    let mut integrated_time_result: Option<i64> = None;

    for entry in &bundle.verification_material.tlog_entries {
        // Verify checkpoint signature if present
        if let Some(ref inclusion_proof) = entry.inclusion_proof {
            if let Some(trusted_root) = trusted_root {
                verify_checkpoint(
                    &inclusion_proof.checkpoint.envelope,
                    inclusion_proof,
                    trusted_root,
                )?;
            }
        }

        // Verify inclusion promise (SET) if present
        if entry.inclusion_promise.is_some() {
            if let Some(trusted_root) = trusted_root {
                verify_set(entry, trusted_root)?;
            }
        }

        // Validate integrated time
        if !entry.integrated_time.is_empty() {
            if let Ok(time) = entry.integrated_time.parse::<i64>() {
                // Ignore 0 as it indicates invalid/missing time
                if time > 0 {
                    // Check that integrated time is not in the future
                    let now = chrono::Utc::now().timestamp();
                    if time > now {
                        return Err(Error::Verification(format!(
                            "integrated time {} is in the future (current time: {})",
                            time, now
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
    use sigstore_crypto::checkpoint::{verify_ecdsa_p256, verify_ed25519};

    // Parse the signed note
    let signed_note = SignedNote::from_text(checkpoint_envelope)
        .map_err(|e| Error::Verification(format!("Failed to parse checkpoint: {}", e)))?;

    // Verify that the checkpoint's root hash matches the inclusion proof's root hash
    let checkpoint_root_hash = &signed_note.checkpoint.root_hash;

    // Decode the root hash from the inclusion proof (auto-detects hex or base64 format)
    let proof_root_hash = sigstore_types::Sha256Hash::from_base64_ref(&inclusion_proof.root_hash)
        .map_err(|e| {
            Error::Verification(format!("Failed to decode inclusion proof root hash: {}", e))
        })?;

    if checkpoint_root_hash.as_slice() != proof_root_hash.as_slice() {
        return Err(Error::Verification(format!(
            "Checkpoint root hash mismatch: expected {}, got {}",
            hex::encode(checkpoint_root_hash),
            proof_root_hash.to_hex()
        )));
    }

    // Get all Rekor keys with their key hints from trusted root
    let rekor_keys = trusted_root
        .rekor_keys_with_hints()
        .map_err(|e| Error::Verification(format!("Failed to get Rekor keys: {}", e)))?;

    // For each signature in the checkpoint, try to find a matching key and verify
    for sig in &signed_note.signatures {
        // Find the key with matching key hint
        for (key_hint, key_bytes) in &rekor_keys {
            if &sig.key_id == key_hint {
                // Found matching key, verify the signature
                let message = signed_note.checkpoint_text.as_bytes();

                // Try Ed25519 first
                if verify_ed25519(key_bytes, &sig.signature, message).is_ok() {
                    return Ok(());
                }

                // Try ECDSA P-256
                if verify_ecdsa_p256(key_bytes, &sig.signature, message).is_ok() {
                    return Ok(());
                }

                return Err(Error::Verification(
                    "Checkpoint signature verification failed".to_string(),
                ));
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
    let log_key_bytes = trusted_root
        .rekor_key_for_log(&entry.log_id.key_id)
        .map_err(|_| Error::Verification(format!("Unknown log ID: {}", entry.log_id.key_id)))?;

    // Construct the payload
    let body = entry.canonicalized_body.clone().into_string();

    let integrated_time = entry
        .integrated_time
        .parse::<i64>()
        .map_err(|_| Error::Verification("Invalid integrated time".into()))?;
    let log_index = entry
        .log_index
        .as_u64()
        .map_err(|_| Error::Verification("Invalid log index".into()))? as i64;

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

    // Verify signature
    let signature = promise
        .signed_entry_timestamp
        .decode()
        .map_err(|_| Error::Verification("Invalid base64 signature".into()))?;

    verify_signature(
        &log_key_bytes,
        &canonical_json,
        &signature,
        SigningScheme::EcdsaP256Sha256,
    )
    .map_err(|e| Error::Verification(format!("SET verification failed: {}", e)))?;

    Ok(())
}
