//! Checkpoint (signed tree head) types
//!
//! A checkpoint represents a signed commitment to the state of a transparency log.
//! Format specified in: https://github.com/transparency-dev/formats/blob/main/log/README.md

use crate::encoding::{base64_bytes, Sha256Hash};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// A checkpoint (signed tree head) from a transparency log
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    /// The origin string identifying the log
    pub origin: String,
    /// Tree size (number of leaves)
    pub tree_size: u64,
    /// Root hash of the Merkle tree (32 bytes SHA-256)
    pub root_hash: Sha256Hash,
    /// Other data lines (optional extension data)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_content: Vec<String>,
    /// Signatures over the checkpoint
    pub signatures: Vec<CheckpointSignature>,
}

/// A signature on a checkpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointSignature {
    /// Key identifier (first 4 bytes of SHA-256 of the public key)
    #[serde(with = "base64_bytes")]
    pub key_id: Vec<u8>,
    /// Signature bytes
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl Checkpoint {
    /// Parse a checkpoint from its text representation
    ///
    /// Format:
    /// ```text
    /// <origin>
    /// <tree_size>
    /// <root_hash_base64>
    /// [other_content...]
    ///
    /// — <key_id_base64> <sig_base64>
    /// [additional signatures...]
    /// ```
    pub fn from_text(text: &str) -> Result<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let mut lines = text.lines();

        // Parse origin
        let origin = lines
            .next()
            .ok_or_else(|| Error::InvalidCheckpoint("missing origin".to_string()))?
            .trim()
            .to_string();

        // Parse tree size
        let tree_size_str = lines
            .next()
            .ok_or_else(|| Error::InvalidCheckpoint("missing tree size".to_string()))?
            .trim();
        let tree_size = tree_size_str
            .parse()
            .map_err(|_| Error::InvalidCheckpoint("invalid tree size".to_string()))?;

        // Parse root hash
        let root_hash_b64 = lines
            .next()
            .ok_or_else(|| Error::InvalidCheckpoint("missing root hash".to_string()))?
            .trim();
        let root_hash_bytes = STANDARD
            .decode(root_hash_b64)
            .map_err(|_| Error::InvalidCheckpoint("invalid root hash base64".to_string()))?;
        let root_hash = Sha256Hash::try_from_slice(&root_hash_bytes)
            .map_err(|e| Error::InvalidCheckpoint(format!("invalid root hash: {}", e)))?;

        // Parse other content until empty line
        let mut other_content = Vec::new();
        let mut signatures = Vec::new();

        for line in lines {
            if line.is_empty() {
                continue;
            }

            if line.starts_with("— ") || line.starts_with("\u{2014} ") {
                // This is a signature line
                // Format: — <origin> <key_id_base64><signature_base64>
                // Note: key_id is first 4 bytes (encoded), signature follows directly
                let content = if let Some(stripped) = line.strip_prefix("— ") {
                    stripped
                } else if let Some(stripped) = line.strip_prefix("\u{2014} ") {
                    stripped
                } else {
                    unreachable!("line must start with one of the prefixes")
                };

                // Split into origin and key_id+signature
                let parts: Vec<&str> = content.splitn(2, ' ').collect();
                if parts.len() != 2 {
                    return Err(Error::InvalidCheckpoint(
                        "invalid signature line format".to_string(),
                    ));
                }

                let key_and_sig = parts[1];
                // Key ID is first 4 bytes = first 8 base64 chars (4 bytes = 32 bits / 6 = ~5.3, but padded to 8)
                // Actually, let's decode the whole thing and split by size
                let decoded = STANDARD.decode(key_and_sig).map_err(|_| {
                    Error::InvalidCheckpoint("invalid signature base64".to_string())
                })?;

                if decoded.len() < 4 {
                    return Err(Error::InvalidCheckpoint(
                        "signature too short for key_id".to_string(),
                    ));
                }

                let key_id = decoded[..4].to_vec();
                let signature = decoded[4..].to_vec();

                signatures.push(CheckpointSignature { key_id, signature });
            } else {
                // Other content line
                other_content.push(line.to_string());
            }
        }

        Ok(Checkpoint {
            origin,
            tree_size,
            root_hash,
            other_content,
            signatures,
        })
    }

    /// Encode the checkpoint to its text representation (without signatures)
    pub fn to_signed_note_body(&self) -> String {
        let mut result = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.tree_size,
            self.root_hash.to_base64()
        );

        for line in &self.other_content {
            result.push_str(line);
            result.push('\n');
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checkpoint() {
        let checkpoint_text = "rekor.sigstore.dev - 1193050959916656506
42591958
npv1T/m9N8zX0jPlbh4rB51zL6GpnV9bQaXSOdzAV+s=

— rekor.sigstore.dev wNI9ajBFAiEA0OP4Pv5ks5MoTTwcM0kS6HMn8gZ5fFPjT9s6vVqXgHkCIDCe5qWSdM4OXpCQ1YNP2KpLo1r/2dRfFHXkPR5h3ywe
";

        let checkpoint = Checkpoint::from_text(checkpoint_text).unwrap();
        assert_eq!(
            checkpoint.origin,
            "rekor.sigstore.dev - 1193050959916656506"
        );
        assert_eq!(checkpoint.tree_size, 42591958);
        assert_eq!(checkpoint.root_hash.as_bytes().len(), 32); // Sha256Hash is always 32 bytes
        assert_eq!(checkpoint.signatures.len(), 1);
    }
}
