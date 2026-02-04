//! Trusted root types and parsing

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sigstore_types::{DerCertificate, DerPublicKey, HashAlgorithm, KeyHint, LogId, LogKeyId};
use std::collections::HashMap;

/// TSA certificate with optional validity period (start, end)
pub type TsaCertWithValidity = (
    CertificateDer<'static>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// A trusted root bundle containing all trust anchors
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRoot {
    /// Media type of the trusted root
    pub media_type: String,

    /// Transparency logs (Rekor)
    #[serde(default)]
    pub tlogs: Vec<TransparencyLog>,

    /// Certificate authorities (Fulcio)
    #[serde(default)]
    pub certificate_authorities: Vec<CertificateAuthority>,

    /// Certificate Transparency logs
    #[serde(default)]
    pub ctlogs: Vec<CertificateTransparencyLog>,

    /// Timestamp authorities (RFC 3161 TSAs)
    #[serde(default)]
    pub timestamp_authorities: Vec<TimestampAuthority>,
}

/// A transparency log entry (Rekor)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLog {
    /// Base URL of the transparency log
    pub base_url: String,

    /// Hash algorithm used
    pub hash_algorithm: HashAlgorithm,

    /// Public key for verification
    pub public_key: PublicKey,

    /// Log ID
    pub log_id: LogId,
}

/// A certificate authority entry (Fulcio)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthority {
    /// Subject information
    #[serde(default)]
    pub subject: CertificateSubject,

    /// URI of the CA
    pub uri: String,

    /// Certificate chain
    pub cert_chain: CertChain,

    /// Validity period
    #[serde(default)]
    pub valid_for: Option<ValidityPeriod>,
}

/// A Certificate Transparency log entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateTransparencyLog {
    /// Base URL of the CT log
    pub base_url: String,

    /// Hash algorithm used
    pub hash_algorithm: HashAlgorithm,

    /// Public key for verification
    pub public_key: PublicKey,

    /// Log ID
    pub log_id: LogId,
}

/// A timestamp authority entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimestampAuthority {
    /// Subject information
    #[serde(default)]
    pub subject: CertificateSubject,

    /// URI of the TSA
    #[serde(default)]
    pub uri: Option<String>,

    /// Certificate chain
    pub cert_chain: CertChain,

    /// Validity period
    #[serde(default)]
    pub valid_for: Option<ValidityPeriod>,
}

/// Public key information
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    /// Raw bytes of the public key (DER-encoded)
    pub raw_bytes: DerPublicKey,

    /// Key details/type
    pub key_details: String,

    /// Validity period for this key
    #[serde(default)]
    pub valid_for: Option<ValidityPeriod>,
}

/// Subject information for a certificate.
///
/// Note: This is different from `sigstore_types::Subject` which represents
/// an in-toto Statement subject (artifact name + digest).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSubject {
    /// Organization name
    #[serde(default)]
    pub organization: Option<String>,

    /// Common name
    #[serde(default)]
    pub common_name: Option<String>,
}

/// Certificate chain
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertChain {
    /// Certificates in the chain
    pub certificates: Vec<CertificateEntry>,
}

/// A certificate entry
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateEntry {
    /// Raw bytes of the certificate (DER-encoded)
    pub raw_bytes: DerCertificate,
}

/// Validity period for a key or certificate
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityPeriod {
    /// Start time (ISO 8601)
    #[serde(default)]
    pub start: Option<String>,

    /// End time (ISO 8601)
    #[serde(default)]
    pub end: Option<String>,
}

impl TrustedRoot {
    /// Parse a trusted root from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load a trusted root from a file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let json =
            std::fs::read_to_string(path).map_err(|e| Error::Json(serde_json::Error::io(e)))?;
        Self::from_json(&json)
    }

    /// Get all Fulcio certificate authority certificates
    pub fn fulcio_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut certs = Vec::new();
        for ca in &self.certificate_authorities {
            for cert_entry in &ca.cert_chain.certificates {
                certs.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        Ok(certs)
    }

    /// Get all Rekor public keys mapped by key ID
    pub fn rekor_keys(&self) -> Result<HashMap<String, Vec<u8>>> {
        let mut keys = HashMap::new();
        for tlog in &self.tlogs {
            keys.insert(
                tlog.log_id.key_id.to_string(),
                tlog.public_key.raw_bytes.as_bytes().to_vec(),
            );
        }
        Ok(keys)
    }

    /// Get all Rekor public keys with their key hints (4-byte identifiers)
    ///
    /// Returns a vector of (key_hint, public_key) tuples where key_hint is
    /// the first 4 bytes of the keyId from the log_id field.
    pub fn rekor_keys_with_hints(&self) -> Result<Vec<(KeyHint, DerPublicKey)>> {
        let mut keys = Vec::new();
        for tlog in &self.tlogs {
            // Decode the key_id to get the key hint (first 4 bytes)
            let key_id_bytes = tlog.log_id.key_id.decode()?;

            if key_id_bytes.len() >= 4 {
                let key_hint = KeyHint::new([
                    key_id_bytes[0],
                    key_id_bytes[1],
                    key_id_bytes[2],
                    key_id_bytes[3],
                ]);
                keys.push((key_hint, tlog.public_key.raw_bytes.clone()));
            }
        }
        Ok(keys)
    }

    /// Get a specific Rekor public key by log ID
    pub fn rekor_key_for_log(&self, log_id: &LogKeyId) -> Result<DerPublicKey> {
        for tlog in &self.tlogs {
            if &tlog.log_id.key_id == log_id {
                return Ok(tlog.public_key.raw_bytes.clone());
            }
        }
        Err(Error::KeyNotFound(log_id.to_string()))
    }

    /// Get all Certificate Transparency log public keys mapped by key ID
    pub fn ctfe_keys(&self) -> Result<HashMap<LogKeyId, DerPublicKey>> {
        let mut keys = HashMap::new();
        for ctlog in &self.ctlogs {
            keys.insert(
                ctlog.log_id.key_id.clone(),
                ctlog.public_key.raw_bytes.clone(),
            );
        }
        Ok(keys)
    }

    /// Get all Certificate Transparency log public keys with their SHA-256 log IDs
    /// Returns a list of (log_id, public_key) pairs where log_id is the SHA-256 hash
    /// of the public key (used for matching against SCTs)
    pub fn ctfe_keys_with_ids(&self) -> Result<Vec<(Vec<u8>, DerPublicKey)>> {
        let mut result = Vec::new();
        for ctlog in &self.ctlogs {
            let key_bytes = ctlog.public_key.raw_bytes.as_bytes();
            // Compute SHA-256 hash of the public key to get the log ID
            let log_id = sigstore_crypto::sha256(key_bytes).as_bytes().to_vec();
            result.push((log_id, ctlog.public_key.raw_bytes.clone()));
        }
        Ok(result)
    }

    /// Get all TSA certificates with their validity periods
    pub fn tsa_certs_with_validity(&self) -> Result<Vec<TsaCertWithValidity>> {
        let mut result = Vec::new();

        for tsa in &self.timestamp_authorities {
            for cert_entry in &tsa.cert_chain.certificates {
                let cert_der = cert_entry.raw_bytes.as_bytes().to_vec();

                // Parse validity period
                let (start, end) = if let Some(valid_for) = &tsa.valid_for {
                    let start = valid_for
                        .start
                        .as_ref()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc));
                    let end = valid_for
                        .end
                        .as_ref()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc));
                    (start, end)
                } else {
                    (None, None)
                };

                result.push((CertificateDer::from(&cert_der[..]).into_owned(), start, end));
            }
        }

        Ok(result)
    }

    /// Get TSA root certificates (for chain validation)
    pub fn tsa_root_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut roots = Vec::new();
        for tsa in &self.timestamp_authorities {
            // The last certificate in the chain is typically the root
            if let Some(cert_entry) = tsa.cert_chain.certificates.last() {
                roots.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        Ok(roots)
    }

    /// Get TSA intermediate certificates (for chain validation)
    pub fn tsa_intermediate_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut intermediates = Vec::new();
        for tsa in &self.timestamp_authorities {
            // All certificates except the first (leaf) and last (root) are intermediates
            let chain_len = tsa.cert_chain.certificates.len();
            if chain_len > 2 {
                for cert_entry in &tsa.cert_chain.certificates[1..chain_len - 1] {
                    intermediates
                        .push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
                }
            }
        }
        Ok(intermediates)
    }

    /// Get TSA leaf certificates (the first certificate in each chain)
    /// These are the actual TSA signing certificates
    pub fn tsa_leaf_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut leaves = Vec::new();
        for tsa in &self.timestamp_authorities {
            // The first certificate in the chain is the leaf (TSA signing cert)
            if let Some(cert_entry) = tsa.cert_chain.certificates.first() {
                leaves.push(CertificateDer::from(cert_entry.raw_bytes.as_bytes()).into_owned());
            }
        }
        Ok(leaves)
    }

    /// Check if a Rekor key ID exists in the trusted root
    pub fn has_rekor_key(&self, key_id: &LogKeyId) -> bool {
        self.tlogs.iter().any(|tlog| &tlog.log_id.key_id == key_id)
    }

    /// Get the validity period for a TSA at a given time
    pub fn tsa_validity_for_time(
        &self,
        timestamp: DateTime<Utc>,
    ) -> Result<Option<(DateTime<Utc>, DateTime<Utc>)>> {
        for tsa in &self.timestamp_authorities {
            if let Some(valid_for) = &tsa.valid_for {
                let start = valid_for
                    .start
                    .as_ref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc));
                let end = valid_for
                    .end
                    .as_ref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc));

                // Check if timestamp falls within this TSA's validity
                if let (Some(start_time), Some(end_time)) = (start, end) {
                    if timestamp >= start_time && timestamp <= end_time {
                        return Ok(Some((start_time, end_time)));
                    }
                } else if let Some(start_time) = start {
                    // Only start time specified, check if after start
                    if timestamp >= start_time {
                        return Ok(start.zip(end));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Check if a timestamp is within any TSA's validity period from the trust root
    ///
    /// Returns true if:
    /// - There are no timestamp authorities configured (no TSA verification)
    /// - Any TSA has no `valid_for` field (open-ended validity)
    /// - The timestamp falls within at least one TSA's `valid_for` period
    ///
    /// Returns false only if there are TSAs with validity constraints and the
    /// timestamp doesn't fall within any of them.
    pub fn is_timestamp_within_tsa_validity(&self, timestamp: DateTime<Utc>) -> bool {
        // If no TSAs are configured, no validity check needed
        if self.timestamp_authorities.is_empty() {
            return true;
        }

        for tsa in &self.timestamp_authorities {
            // If a TSA has no valid_for constraint, it's valid for all time
            let Some(valid_for) = &tsa.valid_for else {
                return true;
            };

            let start = valid_for
                .start
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
            let end = valid_for
                .end
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            // Check if timestamp falls within this TSA's validity period
            let after_start = start.map_or(true, |s| timestamp >= s);
            let before_end = end.map_or(true, |e| timestamp <= e);

            if after_start && before_end {
                return true;
            }
        }

        // No TSA's validity period matched
        false
    }
}

/// Embedded production trusted root from <https://tuf-repo-cdn.sigstore.dev/>
/// This is the default trusted root for Sigstore's public production instance.
pub const SIGSTORE_PRODUCTION_TRUSTED_ROOT: &str = include_str!("trusted_root.json");

/// Embedded staging trusted root from <https://tuf-repo-cdn.sigstage.dev/>
/// This is the trusted root for Sigstore's staging/testing instance.
pub const SIGSTORE_STAGING_TRUSTED_ROOT: &str = include_str!("trusted_root_staging.json");


#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TRUSTED_ROOT: &str = r#"{
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [{
            "baseUrl": "https://rekor.sigstore.dev",
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYI4heOTrNrZO27elFE8ynfrdPMikttRkbe+vJKQ50G6bfwQ3WyhLpRwwwohelDAm8xRzJ56nYsIa3VHivVvpmA==",
                "keyDetails": "PKIX_ECDSA_P256_SHA_256"
            },
            "logId": {
                "keyId": "test-key-id"
            }
        }],
        "certificateAuthorities": [],
        "ctlogs": [],
        "timestampAuthorities": []
    }"#;

    #[test]
    fn test_parse_trusted_root() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        assert_eq!(root.tlogs.len(), 1);
        assert_eq!(
            root.tlogs[0].log_id.key_id,
            LogKeyId::new("test-key-id".to_string())
        );
    }

    #[test]
    fn test_rekor_keys() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        let keys = root.rekor_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("test-key-id"));
    }

    #[test]
    fn test_has_rekor_key() {
        let root = TrustedRoot::from_json(SAMPLE_TRUSTED_ROOT).unwrap();
        assert!(root.has_rekor_key(&LogKeyId::new("test-key-id".to_string())));
        assert!(!root.has_rekor_key(&LogKeyId::new("non-existent".to_string())));
    }

    #[test]
    fn test_from_json_production() {
        let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
        assert!(!root.tlogs.is_empty());
        assert!(!root.certificate_authorities.is_empty());
        assert!(!root.ctlogs.is_empty());
    }

    #[test]
    fn test_from_json_staging() {
        let root = TrustedRoot::from_json(SIGSTORE_STAGING_TRUSTED_ROOT).unwrap();
        assert!(!root.tlogs.is_empty());
        assert!(!root.certificate_authorities.is_empty());
        assert!(!root.ctlogs.is_empty());
        // Staging should have different URLs from production
        assert!(root.tlogs[0].base_url.contains("sigstage.dev"));
    }
}
