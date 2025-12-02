//! Trusted root types and parsing
//!
//! This module re-exports the official Sigstore protobuf types and provides
//! extension methods for common operations.

use crate::{Error, Result};
use chrono::{DateTime, TimeZone, Utc};
use rustls_pki_types::CertificateDer;
use std::collections::HashMap;

// Re-export protobuf types
pub use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::{
        DistinguishedName, HashAlgorithm as ProtoHashAlgorithm, LogId as ProtoLogId, PublicKey,
        TimeRange, X509Certificate, X509CertificateChain,
    },
    trustroot::v1::{CertificateAuthority, TransparencyLogInstance, TrustedRoot},
};

/// TSA certificate with optional validity period (start, end)
pub type TsaCertWithValidity = (
    CertificateDer<'static>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// Embedded production trusted root from <https://tuf-repo-cdn.sigstore.dev/>
/// This is the default trusted root for Sigstore's public production instance.
pub const SIGSTORE_PRODUCTION_TRUSTED_ROOT: &str = include_str!("trusted_root.json");

/// Embedded staging trusted root from <https://tuf-repo-cdn.sigstage.dev/>
/// This is the trusted root for Sigstore's staging/testing instance.
pub const SIGSTORE_STAGING_TRUSTED_ROOT: &str = include_str!("trusted_root_staging.json");

/// Extension trait for TrustedRoot with helper methods
pub trait TrustedRootExt {
    /// Parse a trusted root from JSON
    fn from_json(json: &str) -> Result<TrustedRoot>;

    /// Load a trusted root from a file
    fn from_file(path: impl AsRef<std::path::Path>) -> Result<TrustedRoot>;

    /// Load the default Sigstore production trusted root
    fn production() -> Result<TrustedRoot>;

    /// Load the Sigstore staging trusted root
    fn staging() -> Result<TrustedRoot>;

    /// Get all Fulcio certificate authority certificates
    fn fulcio_certs(&self) -> Result<Vec<CertificateDer<'static>>>;

    /// Get all Rekor public keys mapped by key ID (hex-encoded)
    fn rekor_keys(&self) -> Result<HashMap<String, Vec<u8>>>;

    /// Get all Rekor public keys with their key hints (4-byte identifiers)
    fn rekor_keys_with_hints(&self) -> Result<Vec<([u8; 4], Vec<u8>)>>;

    /// Get a specific Rekor public key by log ID (base64-encoded)
    fn rekor_key_for_log(&self, log_id: &str) -> Result<Vec<u8>>;

    /// Get all Certificate Transparency log public keys mapped by key ID
    fn ctfe_keys(&self) -> Result<HashMap<String, Vec<u8>>>;

    /// Get all Certificate Transparency log public keys with their SHA-256 log IDs
    fn ctfe_keys_with_ids(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Get all TSA certificates with their validity periods
    fn tsa_certs_with_validity(&self) -> Result<Vec<TsaCertWithValidity>>;

    /// Get TSA root certificates (for chain validation)
    fn tsa_root_certs(&self) -> Result<Vec<CertificateDer<'static>>>;

    /// Get TSA intermediate certificates (for chain validation)
    fn tsa_intermediate_certs(&self) -> Result<Vec<CertificateDer<'static>>>;

    /// Get TSA leaf certificates (the first certificate in each chain)
    fn tsa_leaf_certs(&self) -> Result<Vec<CertificateDer<'static>>>;

    /// Check if a Rekor key ID exists in the trusted root
    fn has_rekor_key(&self, key_id: &str) -> bool;

    /// Check if a timestamp is within any TSA's validity period
    fn is_timestamp_within_tsa_validity(&self, timestamp: DateTime<Utc>) -> bool;
}

/// Convert protobuf TimeRange to chrono DateTime
fn time_range_to_datetimes(
    range: Option<&TimeRange>,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let Some(range) = range else {
        return (None, None);
    };

    let start = range
        .start
        .as_ref()
        .and_then(|t| Utc.timestamp_opt(t.seconds, t.nanos as u32).single());

    let end = range
        .end
        .as_ref()
        .and_then(|t| Utc.timestamp_opt(t.seconds, t.nanos as u32).single());

    (start, end)
}

impl TrustedRootExt for TrustedRoot {
    fn from_json(json: &str) -> Result<TrustedRoot> {
        Ok(serde_json::from_str(json)?)
    }

    fn from_file(path: impl AsRef<std::path::Path>) -> Result<TrustedRoot> {
        let json =
            std::fs::read_to_string(path).map_err(|e| Error::Json(serde_json::Error::io(e)))?;
        Self::from_json(&json)
    }

    fn production() -> Result<TrustedRoot> {
        Self::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
    }

    fn staging() -> Result<TrustedRoot> {
        Self::from_json(SIGSTORE_STAGING_TRUSTED_ROOT)
    }

    fn fulcio_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut certs = Vec::new();
        for ca in &self.certificate_authorities {
            if let Some(cert_chain) = &ca.cert_chain {
                for cert in &cert_chain.certificates {
                    certs.push(CertificateDer::from(cert.raw_bytes.as_slice()).into_owned());
                }
            }
        }
        Ok(certs)
    }

    fn rekor_keys(&self) -> Result<HashMap<String, Vec<u8>>> {
        let mut keys = HashMap::new();
        for tlog in &self.tlogs {
            if let (Some(log_id), Some(public_key)) = (&tlog.log_id, &tlog.public_key) {
                let key_id_hex = hex::encode(&log_id.key_id);
                if let Some(raw_bytes) = &public_key.raw_bytes {
                    keys.insert(key_id_hex, raw_bytes.clone());
                }
            }
        }
        Ok(keys)
    }

    fn rekor_keys_with_hints(&self) -> Result<Vec<([u8; 4], Vec<u8>)>> {
        let mut keys = Vec::new();
        for tlog in &self.tlogs {
            if let (Some(log_id), Some(public_key)) = (&tlog.log_id, &tlog.public_key) {
                if log_id.key_id.len() >= 4 {
                    let key_hint: [u8; 4] = [
                        log_id.key_id[0],
                        log_id.key_id[1],
                        log_id.key_id[2],
                        log_id.key_id[3],
                    ];
                    if let Some(raw_bytes) = &public_key.raw_bytes {
                        keys.push((key_hint, raw_bytes.clone()));
                    }
                }
            }
        }
        Ok(keys)
    }

    fn rekor_key_for_log(&self, log_id: &str) -> Result<Vec<u8>> {
        // Try to decode as base64 first, then hex
        let log_id_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, log_id)
                .or_else(|_| hex::decode(log_id))
                .map_err(|_| Error::InvalidKey(format!("invalid log ID encoding: {}", log_id)))?;

        for tlog in &self.tlogs {
            if let Some(tlog_log_id) = &tlog.log_id {
                if tlog_log_id.key_id == log_id_bytes {
                    if let Some(public_key) = &tlog.public_key {
                        if let Some(raw_bytes) = &public_key.raw_bytes {
                            return Ok(raw_bytes.clone());
                        }
                    }
                }
            }
        }
        Err(Error::KeyNotFound(log_id.to_string()))
    }

    fn ctfe_keys(&self) -> Result<HashMap<String, Vec<u8>>> {
        let mut keys = HashMap::new();
        for ctlog in &self.ctlogs {
            if let (Some(log_id), Some(public_key)) = (&ctlog.log_id, &ctlog.public_key) {
                let key_id_hex = hex::encode(&log_id.key_id);
                if let Some(raw_bytes) = &public_key.raw_bytes {
                    keys.insert(key_id_hex, raw_bytes.clone());
                }
            }
        }
        Ok(keys)
    }

    fn ctfe_keys_with_ids(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut result = Vec::new();
        for ctlog in &self.ctlogs {
            if let Some(public_key) = &ctlog.public_key {
                if let Some(key_bytes) = &public_key.raw_bytes {
                    // Compute SHA-256 hash of the public key to get the log ID
                    let log_id = sigstore_crypto::sha256(key_bytes).as_bytes().to_vec();
                    result.push((log_id, key_bytes.clone()));
                }
            }
        }
        Ok(result)
    }

    fn tsa_certs_with_validity(&self) -> Result<Vec<TsaCertWithValidity>> {
        let mut result = Vec::new();

        for tsa in &self.timestamp_authorities {
            if let Some(cert_chain) = &tsa.cert_chain {
                let (start, end) = time_range_to_datetimes(tsa.valid_for.as_ref());

                for cert in &cert_chain.certificates {
                    let cert_der = CertificateDer::from(cert.raw_bytes.as_slice()).into_owned();
                    result.push((cert_der, start, end));
                }
            }
        }

        Ok(result)
    }

    fn tsa_root_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut roots = Vec::new();
        for tsa in &self.timestamp_authorities {
            if let Some(cert_chain) = &tsa.cert_chain {
                // The last certificate in the chain is typically the root
                if let Some(cert) = cert_chain.certificates.last() {
                    roots.push(CertificateDer::from(cert.raw_bytes.as_slice()).into_owned());
                }
            }
        }
        Ok(roots)
    }

    fn tsa_intermediate_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut intermediates = Vec::new();
        for tsa in &self.timestamp_authorities {
            if let Some(cert_chain) = &tsa.cert_chain {
                let chain_len = cert_chain.certificates.len();
                if chain_len > 2 {
                    for cert in &cert_chain.certificates[1..chain_len - 1] {
                        intermediates
                            .push(CertificateDer::from(cert.raw_bytes.as_slice()).into_owned());
                    }
                }
            }
        }
        Ok(intermediates)
    }

    fn tsa_leaf_certs(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut leaves = Vec::new();
        for tsa in &self.timestamp_authorities {
            if let Some(cert_chain) = &tsa.cert_chain {
                if let Some(cert) = cert_chain.certificates.first() {
                    leaves.push(CertificateDer::from(cert.raw_bytes.as_slice()).into_owned());
                }
            }
        }
        Ok(leaves)
    }

    fn has_rekor_key(&self, key_id: &str) -> bool {
        // Try to decode as base64 first, then hex
        let Ok(key_id_bytes) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_id)
                .or_else(|_| hex::decode(key_id))
        else {
            return false;
        };

        self.tlogs.iter().any(|tlog| {
            tlog.log_id
                .as_ref()
                .map(|id| id.key_id == key_id_bytes)
                .unwrap_or(false)
        })
    }

    fn is_timestamp_within_tsa_validity(&self, timestamp: DateTime<Utc>) -> bool {
        // If no TSAs are configured, no validity check needed
        if self.timestamp_authorities.is_empty() {
            return true;
        }

        for tsa in &self.timestamp_authorities {
            // If a TSA has no valid_for constraint, it's valid for all time
            let Some(valid_for) = &tsa.valid_for else {
                return true;
            };

            let (start, end) = time_range_to_datetimes(Some(valid_for));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_trusted_root() {
        let root = TrustedRoot::production().unwrap();
        assert!(!root.tlogs.is_empty());
        assert!(!root.certificate_authorities.is_empty());
        assert!(!root.ctlogs.is_empty());
    }

    #[test]
    fn test_staging_trusted_root() {
        let root = TrustedRoot::staging().unwrap();
        assert!(!root.tlogs.is_empty());
        assert!(!root.certificate_authorities.is_empty());
        assert!(!root.ctlogs.is_empty());
    }

    #[test]
    fn test_fulcio_certs() {
        let root = TrustedRoot::production().unwrap();
        let certs = root.fulcio_certs().unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_rekor_keys() {
        let root = TrustedRoot::production().unwrap();
        let keys = root.rekor_keys().unwrap();
        assert!(!keys.is_empty());
    }

    #[test]
    fn test_ctfe_keys() {
        let root = TrustedRoot::production().unwrap();
        let keys = root.ctfe_keys().unwrap();
        assert!(!keys.is_empty());
    }
}
