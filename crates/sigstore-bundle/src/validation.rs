//! Bundle validation
//!
//! Validates Sigstore bundles according to version-specific rules.

use crate::error::{Error, Result};
use sigstore_merkle::verify_inclusion_proof;
use sigstore_types::{Bundle, BundleExt, InclusionProofExt, MediaType, Sha256Hash};

/// Validation options
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Require inclusion proof (not just promise)
    pub require_inclusion_proof: bool,
    /// Require timestamp verification data
    pub require_timestamp: bool,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            require_inclusion_proof: true,
            require_timestamp: false,
        }
    }
}

/// Validate a Sigstore bundle
pub fn validate_bundle(bundle: &Bundle) -> Result<()> {
    validate_bundle_with_options(bundle, &ValidationOptions::default())
}

/// Validate a Sigstore bundle with custom options
pub fn validate_bundle_with_options(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // Check media type is valid
    let version = bundle
        .version()
        .map_err(|e| Error::Validation(format!("invalid media type: {}", e)))?;

    // Version-specific validation
    match version {
        MediaType::Bundle0_1 => validate_v0_1(bundle, options),
        MediaType::Bundle0_2 => validate_v0_2(bundle, options),
        MediaType::Bundle0_3 => validate_v0_3(bundle, options),
    }
}

/// Validate a v0.1 bundle
fn validate_v0_1(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // v0.1 requires inclusion promise (SET)
    if !bundle.has_inclusion_promise() {
        return Err(Error::Validation(
            "v0.1 bundle must have inclusion promise".to_string(),
        ));
    }

    // Common validation
    validate_common(bundle, options)
}

/// Validate a v0.2 bundle
fn validate_v0_2(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // v0.2 requires inclusion proof with checkpoint
    if options.require_inclusion_proof && !bundle.has_inclusion_proof() {
        return Err(Error::Validation(
            "v0.2 bundle must have inclusion proof".to_string(),
        ));
    }

    // Validate inclusion proofs
    validate_inclusion_proofs(bundle)?;

    // Common validation
    validate_common(bundle, options)
}

/// Validate a v0.3 bundle
fn validate_v0_3(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    // v0.3 must have single certificate (not chain) or public key
    let vm = bundle
        .verification_material
        .as_ref()
        .ok_or_else(|| Error::Validation("bundle missing verification material".to_string()))?;

    match &vm.content {
        Some(sigstore_types::bundle::VerificationMaterialContent::Certificate(_)) => {}
        Some(sigstore_types::bundle::VerificationMaterialContent::X509CertificateChain(_)) => {
            return Err(Error::Validation(
                "v0.3 bundle must use single certificate, not chain".to_string(),
            ));
        }
        Some(sigstore_types::bundle::VerificationMaterialContent::PublicKey(_)) => {}
        None => {
            return Err(Error::Validation(
                "bundle missing verification material content".to_string(),
            ));
        }
    }

    // v0.3 requires inclusion proof
    if options.require_inclusion_proof && !bundle.has_inclusion_proof() {
        return Err(Error::Validation(
            "v0.3 bundle must have inclusion proof".to_string(),
        ));
    }

    // Validate inclusion proofs
    validate_inclusion_proofs(bundle)?;

    // Common validation
    validate_common(bundle, options)
}

/// Common validation for all bundle versions
fn validate_common(bundle: &Bundle, options: &ValidationOptions) -> Result<()> {
    let vm = bundle
        .verification_material
        .as_ref()
        .ok_or_else(|| Error::Validation("bundle missing verification material".to_string()))?;

    // Must have at least one tlog entry
    if vm.tlog_entries.is_empty() {
        return Err(Error::Validation(
            "bundle must have at least one tlog entry".to_string(),
        ));
    }

    // Check timestamp if required
    if options.require_timestamp {
        let has_timestamps = vm
            .timestamp_verification_data
            .as_ref()
            .map(|tvd| !tvd.rfc3161_timestamps.is_empty())
            .unwrap_or(false);

        if !has_timestamps {
            return Err(Error::Validation(
                "bundle must have timestamp verification data".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate inclusion proofs in the bundle
fn validate_inclusion_proofs(bundle: &Bundle) -> Result<()> {
    let vm = match bundle.verification_material.as_ref() {
        Some(vm) => vm,
        None => return Ok(()), // No verification material means no proofs to validate
    };

    for entry in &vm.tlog_entries {
        if let Some(proof) = &entry.inclusion_proof {
            // Parse the checkpoint to get the expected root
            let checkpoint = proof
                .parse_checkpoint()
                .map_err(|e| Error::Validation(format!("failed to parse checkpoint: {}", e)))?;

            // Get the leaf (canonicalized body) bytes
            let leaf_data = &entry.canonicalized_body;

            // Get proof hashes (now Vec<Vec<u8>>)
            let proof_hashes: Vec<Sha256Hash> = proof
                .hashes
                .iter()
                .filter_map(|h| {
                    if h.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(h);
                        Some(Sha256Hash::from_bytes(arr))
                    } else {
                        None
                    }
                })
                .collect();

            // Get indices (now i64)
            let leaf_index = proof.log_index_u64();
            let tree_size = proof.tree_size_u64();

            // Get expected root from checkpoint (already a Sha256Hash)
            let expected_root = checkpoint.root_hash;

            // Hash the leaf
            let leaf_hash = sigstore_merkle::hash_leaf(leaf_data);

            // Verify the inclusion proof
            verify_inclusion_proof(
                &leaf_hash,
                leaf_index,
                tree_size,
                &proof_hashes,
                &expected_root,
            )
            .map_err(|e| {
                Error::Validation(format!("inclusion proof verification failed: {}", e))
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_options_default() {
        let opts = ValidationOptions::default();
        assert!(opts.require_inclusion_proof);
        assert!(!opts.require_timestamp);
    }
}
