//! Bundle validation
//!
//! Validates Sigstore bundles according to version-specific rules.

use crate::error::{Error, Result};
use sigstore_merkle::verify_inclusion_proof;
use sigstore_types::{Bundle, MediaType, Sha256Hash};

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
    match &bundle.verification_material.content {
        sigstore_types::bundle::VerificationMaterialContent::Certificate(_) => {}
        sigstore_types::bundle::VerificationMaterialContent::X509CertificateChain { .. } => {
            return Err(Error::Validation(
                "v0.3 bundle must use single certificate, not chain".to_string(),
            ));
        }
        sigstore_types::bundle::VerificationMaterialContent::PublicKey { .. } => {}
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
    // Must have at least one tlog entry
    if bundle.verification_material.tlog_entries.is_empty() {
        return Err(Error::Validation(
            "bundle must have at least one tlog entry".to_string(),
        ));
    }

    // Check timestamp if required
    if options.require_timestamp
        && bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .is_empty()
    {
        return Err(Error::Validation(
            "bundle must have timestamp verification data".to_string(),
        ));
    }

    Ok(())
}

/// Validate inclusion proofs in the bundle
fn validate_inclusion_proofs(bundle: &Bundle) -> Result<()> {
    for entry in &bundle.verification_material.tlog_entries {
        if let Some(proof) = &entry.inclusion_proof {
            // Parse the checkpoint to get the expected root
            let checkpoint = proof
                .checkpoint
                .parse()
                .map_err(|e| Error::Validation(format!("failed to parse checkpoint: {}", e)))?;

            // Get the leaf (canonicalized body) bytes
            let leaf_data = entry.canonicalized_body.as_bytes();

            // Get proof hashes (already decoded as Vec<Sha256Hash>)
            let proof_hashes: &[Sha256Hash] = &proof.hashes;

            // Get indices (now i64 internally)
            let leaf_index: u64 = proof
                .log_index
                .as_u64()
                .ok_or_else(|| Error::Validation("invalid log_index in proof".to_string()))?;
            let tree_size: u64 = proof
                .tree_size
                .try_into()
                .map_err(|_| Error::Validation("invalid tree_size in proof".to_string()))?;

            // Get expected root from checkpoint (already a Sha256Hash)
            let expected_root = checkpoint.root_hash;

            // Hash the leaf
            let leaf_hash = sigstore_merkle::hash_leaf(leaf_data);

            // Verify the inclusion proof
            verify_inclusion_proof(
                &leaf_hash,
                leaf_index,
                tree_size,
                proof_hashes,
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
