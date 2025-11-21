//! In-toto attestation types
//!
//! In-toto provides a framework for securing software supply chain integrity.
//! This module defines types for in-toto attestation statements, commonly used
//! with DSSE envelopes in Sigstore.
//!
//! Specification: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md

use serde::{Deserialize, Serialize};

/// In-toto Statement v1
///
/// An in-toto statement is a generic attestation format that binds a predicate
/// to a set of subjects (artifacts). It's commonly used for SLSA provenance,
/// vulnerability scans, and other supply chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statement {
    /// Type identifier for the statement (typically "https://in-toto.io/Statement/v1")
    #[serde(rename = "_type")]
    pub type_: String,
    /// Subjects (artifacts) being attested about
    pub subject: Vec<Subject>,
    /// Type of the predicate (e.g., "https://slsa.dev/provenance/v1")
    pub predicate_type: String,
    /// The actual attestation content (format depends on predicate_type)
    pub predicate: serde_json::Value,
}

/// Subject of an in-toto statement
///
/// A subject represents an artifact being attested about, identified by
/// its name and cryptographic digest(s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Name of the artifact (e.g., file name, package name)
    pub name: String,
    /// Cryptographic digest(s) of the artifact
    pub digest: Digest,
}

/// Digest for a subject
///
/// Contains one or more cryptographic hashes of the artifact.
/// At minimum, sha256 should be provided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest {
    /// SHA-256 hash (hex-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// SHA-512 hash (hex-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
}

impl Statement {
    /// Check if any subject in the statement matches the given SHA-256 hash
    pub fn matches_sha256(&self, hash_hex: &str) -> bool {
        self.subject.iter().any(|subject| {
            subject
                .digest
                .sha256
                .as_ref()
                .map_or(false, |h| h == hash_hex)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statement_deserialization() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "example.txt",
                    "digest": {
                        "sha256": "abc123"
                    }
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }"#;

        let statement: Statement = serde_json::from_str(json).unwrap();
        assert_eq!(statement.type_, "https://in-toto.io/Statement/v1");
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].name, "example.txt");
        assert_eq!(
            statement.subject[0].digest.sha256,
            Some("abc123".to_string())
        );
    }

    #[test]
    fn test_matches_sha256() {
        let statement = Statement {
            type_: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![
                Subject {
                    name: "file1.txt".to_string(),
                    digest: Digest {
                        sha256: Some("hash1".to_string()),
                        sha512: None,
                    },
                },
                Subject {
                    name: "file2.txt".to_string(),
                    digest: Digest {
                        sha256: Some("hash2".to_string()),
                        sha512: None,
                    },
                },
            ],
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate: serde_json::json!({}),
        };

        assert!(statement.matches_sha256("hash1"));
        assert!(statement.matches_sha256("hash2"));
        assert!(!statement.matches_sha256("hash3"));
    }
}
