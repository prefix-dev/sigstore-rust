//! Checkpoint note format parsing and verification.
//!
//! This module implements parsing and verification of the note format used by Rekor
//! checkpoints. The note format is specified by golang.org/x/mod/sumdb/note and consists
//! of a signed message with one or more cryptographic signatures.
//!
//! # Format
//!
//! A note consists of a text header and signature lines, separated by a blank line:
//!
//! ```text
//! <origin>
//! <tree_size>
//! <root_hash_base64>
//! <optional_metadata>
//!
//! — <signer_name> <signature_base64>
//! ```
//!
//! The signature lines begin with the Unicode em dash (U+2014, "—"), not an ASCII hyphen.
//! Each base64-decoded signature consists of a 4-byte key ID followed by the signature bytes.

use crate::{Error, Result};
use base64::Engine;

/// A single signature in a note.
///
/// Each signature consists of:
/// - A name identifying the signer (e.g., "rekor.sigstore.dev")
/// - A 4-byte key ID (key hint) used to match the signature to a public key
/// - The signature bytes
#[derive(Debug, Clone, PartialEq)]
pub struct NoteSignature {
    /// The name of the signer (appears after the em dash).
    pub name: String,

    /// The 4-byte key ID extracted from the beginning of the decoded signature.
    pub key_id: [u8; 4],

    /// The signature bytes (after the 4-byte key ID).
    pub signature: Vec<u8>,
}

/// A checkpoint header containing the log state.
///
/// The checkpoint consists of:
/// - Origin: The name of the log (e.g., "rekor.sigstore.dev - 2605736670972794746")
/// - Tree size: The number of entries in the log
/// - Root hash: The Merkle tree root hash
/// - Optional metadata lines
#[derive(Debug, Clone, PartialEq)]
pub struct LogCheckpoint {
    /// The origin (log name).
    pub origin: String,

    /// The tree size (number of entries in the log).
    pub tree_size: u64,

    /// The root hash of the Merkle tree (binary).
    pub root_hash: Vec<u8>,

    /// Optional metadata lines (e.g., "Timestamp: 1679349379012118479").
    pub metadata: Vec<String>,
}

/// A signed note containing a checkpoint and signatures.
///
/// This represents a complete note in the format used by Rekor checkpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedNote {
    /// The checkpoint header (before the blank line).
    pub checkpoint: LogCheckpoint,

    /// The raw text of the checkpoint (used for signature verification).
    pub checkpoint_text: String,

    /// The signatures (after the blank line).
    pub signatures: Vec<NoteSignature>,
}

impl LogCheckpoint {
    /// Parse a checkpoint from text lines.
    ///
    /// The checkpoint must have at least 3 lines:
    /// 1. Origin
    /// 2. Tree size (integer)
    /// 3. Root hash (base64)
    ///    4+. Optional metadata
    pub fn from_text(text: &str) -> Result<Self> {
        let lines: Vec<&str> = text.lines().collect();

        if lines.is_empty() {
            return Err(Error::Checkpoint("Empty checkpoint".to_string()));
        }

        // Line 0: Origin
        let origin = lines[0].trim();
        if origin.is_empty() {
            return Err(Error::Checkpoint("Empty origin".to_string()));
        }

        // Line 1: Tree size
        if lines.len() < 2 {
            return Err(Error::Checkpoint("Missing tree size".to_string()));
        }
        let tree_size = lines[1]
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::Checkpoint(format!("Invalid tree size: {}", lines[1])))?;

        // Line 2: Root hash (base64)
        if lines.len() < 3 {
            return Err(Error::Checkpoint("Missing root hash".to_string()));
        }
        let root_hash = base64::engine::general_purpose::STANDARD
            .decode(lines[2].trim())
            .map_err(|e| Error::Checkpoint(format!("Invalid root hash base64: {}", e)))?;

        // Lines 3+: Optional metadata
        let metadata = lines[3..]
            .iter()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        Ok(LogCheckpoint {
            origin: origin.to_string(),
            tree_size,
            root_hash,
            metadata,
        })
    }

    /// Serialize a checkpoint to text format.
    pub fn to_text(&self) -> String {
        let root_hash_b64 = base64::engine::general_purpose::STANDARD.encode(&self.root_hash);
        let mut output = format!("{}\n{}\n{}\n", self.origin, self.tree_size, root_hash_b64);

        // Add metadata lines
        for line in &self.metadata {
            output.push_str(line);
            output.push('\n');
        }

        output
    }
}

impl NoteSignature {
    /// Parse a signature line.
    ///
    /// The line must be in the format: `— <name> <base64_signature>`
    /// The em dash (U+2014) is required at the start.
    pub fn from_line(line: &str) -> Result<Self> {
        // Check for em dash at the start
        if !line.starts_with('—') {
            return Err(Error::Checkpoint(
                "Signature line must start with em dash (U+2014)".to_string(),
            ));
        }

        // Split into parts: "— <name> <signature>"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::Checkpoint(
                "Signature line must have format: — <name> <base64_signature>".to_string(),
            ));
        }

        let name = parts[1].to_string();
        let signature_b64 = parts[2];

        // Decode the signature
        let signature_with_key_id = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|e| Error::Checkpoint(format!("Invalid signature base64: {}", e)))?;

        // Extract key ID (first 4 bytes) and signature (rest)
        if signature_with_key_id.len() < 5 {
            return Err(Error::Checkpoint(
                "Signature too short (must be at least 5 bytes for 4-byte key ID + signature)"
                    .to_string(),
            ));
        }

        let key_id: [u8; 4] = signature_with_key_id[0..4]
            .try_into()
            .map_err(|_| Error::Checkpoint("Failed to extract key ID".to_string()))?;
        let signature = signature_with_key_id[4..].to_vec();

        Ok(NoteSignature {
            name,
            key_id,
            signature,
        })
    }
}

impl SignedNote {
    /// Parse a signed note from text.
    ///
    /// The note must have a blank line separating the checkpoint from signatures.
    pub fn from_text(text: &str) -> Result<Self> {
        if text.is_empty() {
            return Err(Error::Checkpoint("Empty note".to_string()));
        }

        // Find the blank line separator
        let parts: Vec<&str> = text.split("\n\n").collect();
        if parts.len() < 2 {
            return Err(Error::Checkpoint(
                "Missing blank line separator".to_string(),
            ));
        }
        if parts.len() > 2 {
            return Err(Error::Checkpoint(
                "Multiple blank line separators".to_string(),
            ));
        }

        let checkpoint_text = parts[0];
        let signatures_text = parts[1];

        // Parse checkpoint
        let checkpoint = LogCheckpoint::from_text(checkpoint_text)?;

        // Parse signatures
        let signature_lines: Vec<&str> = signatures_text.lines().collect();
        if signature_lines.is_empty() {
            return Err(Error::Checkpoint("No signatures found".to_string()));
        }

        let mut signatures = Vec::new();
        for line in signature_lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            signatures.push(NoteSignature::from_line(line)?);
        }

        if signatures.is_empty() {
            return Err(Error::Checkpoint("No valid signatures found".to_string()));
        }

        // The checkpoint_text needs to include the trailing newline that comes before
        // the blank line separator, as this is what gets signed
        let checkpoint_text_with_newline = format!("{}\n", checkpoint_text);

        Ok(SignedNote {
            checkpoint,
            checkpoint_text: checkpoint_text_with_newline,
            signatures,
        })
    }

    /// Find a signature matching the given key hint (key ID).
    ///
    /// Returns the signature if found, or None if no matching signature exists.
    pub fn find_signature_by_key_hint(&self, key_hint: &[u8; 4]) -> Option<&NoteSignature> {
        self.signatures.iter().find(|sig| &sig.key_id == key_hint)
    }

    /// Verify the checkpoint signature using the provided public key.
    ///
    /// This verifies that the signature over the checkpoint text is valid.
    /// The public key should match the key hint in the signature.
    ///
    /// Returns Ok(()) if verification succeeds, or an error if it fails.
    pub fn verify_signature(&self, public_key_der: &[u8]) -> Result<()> {
        // Compute key hint from public key
        let key_hint = compute_key_hint(public_key_der);

        // Find signature with matching key hint
        let signature = self
            .find_signature_by_key_hint(&key_hint)
            .ok_or_else(|| Error::Checkpoint("No signature found matching key hint".to_string()))?;

        // The signed data is the checkpoint text (without the signatures part)
        let signed_data = self.checkpoint_text.as_bytes();

        // Try to verify as different key types
        // First try Ed25519
        if let Ok(()) = verify_ed25519(public_key_der, &signature.signature, signed_data) {
            return Ok(());
        }

        // Then try ECDSA P-256
        if let Ok(()) = verify_ecdsa_p256(public_key_der, &signature.signature, signed_data) {
            return Ok(());
        }

        Err(Error::Checkpoint(
            "Signature verification failed".to_string(),
        ))
    }
}

/// Compute the key hint (4-byte key ID) from a public key.
///
/// The key hint is the first 4 bytes of SHA-256(public key).
pub fn compute_key_hint(public_key_der: &[u8]) -> [u8; 4] {
    let hash = crate::hash::sha256(public_key_der);
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Verify an Ed25519 signature.
pub fn verify_ed25519(public_key_der: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    use aws_lc_rs::signature;

    // For Ed25519, the public key DER encoding includes an OID prefix
    // We need to extract the raw 32-byte key
    // Ed25519 public key DER format: 0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x03 0x21 0x00 [32 bytes]
    let raw_key = if public_key_der.len() == 44
        && public_key_der.starts_with(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]) {
        &public_key_der[12..]
    } else {
        // Assume it's already raw
        public_key_der
    };

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, raw_key);
    public_key
        .verify(message, signature)
        .map_err(|_| Error::Verification("Ed25519 verification failed".to_string()))
}

/// Verify an ECDSA P-256 signature.
pub fn verify_ecdsa_p256(public_key_der: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    use aws_lc_rs::signature;

    // Parse the public key
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_der);

    // Verify the signature
    public_key
        .verify(message, signature)
        .map_err(|_| Error::Verification("ECDSA P-256 verification failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checkpoint() {
        let text = "rekor.sigstore.dev - 2605736670972794746\n23083062\ndauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=\nTimestamp: 1689177396617352539";

        let checkpoint = LogCheckpoint::from_text(text).unwrap();
        assert_eq!(
            checkpoint.origin,
            "rekor.sigstore.dev - 2605736670972794746"
        );
        assert_eq!(checkpoint.tree_size, 23083062);
        assert_eq!(checkpoint.metadata.len(), 1);
        assert_eq!(checkpoint.metadata[0], "Timestamp: 1689177396617352539");
    }

    #[test]
    fn test_parse_signature_line() {
        let line = "— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs";

        let sig = NoteSignature::from_line(line).unwrap();
        assert_eq!(sig.name, "rekor.sigstore.dev");
        // Key hint is first 4 bytes of base64-decoded signature
        assert_eq!(sig.key_id.len(), 4);
    }

    #[test]
    fn test_parse_signed_note() {
        let note = "rekor.sigstore.dev - 2605736670972794746\n23083062\ndauhleYK4YyAdxwwDtR0l0KnSOWZdG2bwqHftlanvcI=\nTimestamp: 1689177396617352539\n\n— rekor.sigstore.dev xNI9ajBFAiBxaGyEtxkzFLkaCSEJqFuSS3dJjEZCNiyByVs1CNVQ8gIhAOoNnXtmMtTctV2oRnSRUZAo4EWUYPK/vBsqOzAU6TMs";

        let signed_note = SignedNote::from_text(note).unwrap();
        assert_eq!(signed_note.checkpoint.tree_size, 23083062);
        assert_eq!(signed_note.signatures.len(), 1);
        assert_eq!(signed_note.signatures[0].name, "rekor.sigstore.dev");
    }
}
