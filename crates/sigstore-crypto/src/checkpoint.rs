//! Checkpoint verification extension trait.
//!
//! This module provides cryptographic verification capabilities for checkpoints
//! through an extension trait on `sigstore_types::Checkpoint`.

use crate::{Error, Result};
use sigstore_types::{DerPublicKey, KeyHint, SignatureBytes};

// Re-export checkpoint types from sigstore-types
pub use sigstore_types::{Checkpoint, CheckpointSignature};

/// Compute the key hint (4-byte key ID) from a public key.
///
/// The key hint is the first 4 bytes of SHA-256(public key).
pub fn compute_key_hint(public_key: &DerPublicKey) -> KeyHint {
    let hash = crate::hash::sha256(public_key.as_bytes());
    let bytes = hash.as_bytes();
    KeyHint::new([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// OID constants for key type identification
use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
use const_oid::ObjectIdentifier;

/// id-Ed25519: 1.3.101.112
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Key type detected from SPKI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 key
    Ed25519,
    /// ECDSA P-256 key
    EcdsaP256,
    /// Unknown/unsupported key type
    Unknown,
}

/// Detect the key type from SPKI-encoded public key bytes.
///
/// This parses the SubjectPublicKeyInfo structure to determine the algorithm.
pub fn detect_key_type(public_key: &DerPublicKey) -> KeyType {
    use spki::SubjectPublicKeyInfoRef;

    match SubjectPublicKeyInfoRef::try_from(public_key.as_bytes()) {
        Ok(spki) => {
            if spki.algorithm.oid == ID_ED25519 {
                KeyType::Ed25519
            } else if spki.algorithm.oid == ID_EC_PUBLIC_KEY {
                KeyType::EcdsaP256
            } else {
                tracing::warn!("Unknown key algorithm OID: {}", spki.algorithm.oid);
                KeyType::Unknown
            }
        }
        Err(_) => {
            // If we can't parse as SPKI, might be raw key bytes
            // Check if it looks like a raw Ed25519 key (32 bytes)
            if public_key.as_bytes().len() == 32 {
                KeyType::Ed25519
            } else {
                KeyType::Unknown
            }
        }
    }
}

/// Extract raw key bytes from SPKI-encoded public key.
///
/// For Ed25519, this extracts the 32-byte raw key from the SPKI wrapper.
/// For ECDSA, the full SPKI is typically used by aws-lc-rs.
pub fn extract_raw_key(public_key: &DerPublicKey) -> Result<Vec<u8>> {
    use spki::SubjectPublicKeyInfoRef;

    match SubjectPublicKeyInfoRef::try_from(public_key.as_bytes()) {
        Ok(spki) => {
            let raw_bytes = spki.subject_public_key.raw_bytes();
            Ok(raw_bytes.to_vec())
        }
        Err(_) => {
            // Already raw bytes
            Ok(public_key.as_bytes().to_vec())
        }
    }
}

/// Verify an Ed25519 signature.
///
/// Accepts either SPKI-encoded or raw 32-byte public keys.
pub fn verify_ed25519(
    public_key: &DerPublicKey,
    signature: &SignatureBytes,
    message: &[u8],
) -> Result<()> {
    use aws_lc_rs::signature as sig;

    // Extract raw key bytes from SPKI if needed
    let raw_key = extract_raw_key(public_key)?;

    let pk = sig::UnparsedPublicKey::new(&sig::ED25519, &raw_key);
    pk.verify(message, signature.as_bytes())
        .map_err(|_| Error::Verification("Ed25519 verification failed".to_string()))
}

/// Verify an ECDSA P-256 signature.
///
/// Expects SPKI-encoded public key (as produced by x509 certificates).
pub fn verify_ecdsa_p256(
    public_key: &DerPublicKey,
    signature: &SignatureBytes,
    message: &[u8],
) -> Result<()> {
    use aws_lc_rs::signature as sig;

    // aws-lc-rs expects the full SPKI for ECDSA, or raw uncompressed point
    let pk = sig::UnparsedPublicKey::new(&sig::ECDSA_P256_SHA256_ASN1, public_key.as_bytes());

    pk.verify(message, signature.as_bytes())
        .map_err(|_| Error::Verification("ECDSA P-256 verification failed".to_string()))
}

/// Verify a signature using automatic key type detection.
///
/// This function detects the key type from the SPKI structure and calls
/// the appropriate verification function.
pub fn verify_signature_auto(
    public_key: &DerPublicKey,
    signature: &SignatureBytes,
    message: &[u8],
) -> Result<()> {
    match detect_key_type(public_key) {
        KeyType::Ed25519 => verify_ed25519(public_key, signature, message),
        KeyType::EcdsaP256 => verify_ecdsa_p256(public_key, signature, message),
        KeyType::Unknown => Err(Error::Verification(
            "unsupported or unrecognized public key type".to_string(),
        )),
    }
}

/// Extension trait for checkpoint signature verification.
///
/// This trait adds cryptographic verification capabilities to `Checkpoint`.
pub trait CheckpointVerifyExt {
    /// Verify the checkpoint signature using the provided public key.
    ///
    /// This verifies that the signature over the checkpoint text is valid.
    /// The public key should match the key hint in the signature.
    ///
    /// The key type is automatically detected from the SPKI structure.
    ///
    /// Returns Ok(()) if verification succeeds, or an error if it fails.
    fn verify_signature(&self, public_key: &DerPublicKey) -> Result<()>;
}

impl CheckpointVerifyExt for Checkpoint {
    fn verify_signature(&self, public_key: &DerPublicKey) -> Result<()> {
        // Compute key hint from public key
        let key_hint = compute_key_hint(public_key);

        // Find signature with matching key hint
        let signature = self
            .find_signature_by_key_hint(&key_hint)
            .ok_or_else(|| Error::Checkpoint("No signature found matching key hint".to_string()))?;

        // The signed data is the checkpoint text (without the signatures part)
        let signed_data = self.signed_data();

        // Use automatic key type detection
        verify_signature_auto(public_key, &signature.signature, signed_data)
            .map_err(|e| Error::Checkpoint(format!("Signature verification failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checkpoint() {
        let text = "rekor.sigstore.dev - 2605736670972794746\n23083062\ndauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=\nTimestamp: 1689177396617352539\n\n— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs";

        let checkpoint = Checkpoint::from_text(text).unwrap();
        assert_eq!(
            checkpoint.origin,
            "rekor.sigstore.dev - 2605736670972794746"
        );
        assert_eq!(checkpoint.tree_size, 23083062);
        assert_eq!(checkpoint.other_content.len(), 1);
        assert_eq!(
            checkpoint.other_content[0],
            "Timestamp: 1689177396617352539"
        );
    }

    #[test]
    fn test_parse_signature() {
        let text = "rekor.sigstore.dev - 2605736670972794746\n23083062\ndauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=\nTimestamp: 1689177396617352539\n\n— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs";

        let checkpoint = Checkpoint::from_text(text).unwrap();
        assert_eq!(checkpoint.signatures.len(), 1);
        assert_eq!(checkpoint.signatures[0].name, "rekor.sigstore.dev");
        // Key hint is first 4 bytes of base64-decoded signature
        assert_eq!(checkpoint.signatures[0].key_id.as_bytes().len(), 4);
    }
}
