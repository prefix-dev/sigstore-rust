//! Rekor client for transparency log operations

use crate::entry::{
    DsseEntry, HashedRekord, HashedRekordV2, LogEntry, LogEntryResponse, LogInfo, SearchIndex,
};
use crate::error::{Error, Result};

/// A client for interacting with Rekor
pub struct RekorClient {
    /// Base URL of the Rekor instance
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl RekorClient {
    /// Create a new Rekor client
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for the public Sigstore Rekor instance
    pub fn public() -> Self {
        Self::new("https://rekor.sigstore.dev")
    }

    /// Create a client for the Sigstore staging Rekor instance
    pub fn staging() -> Self {
        Self::new("https://rekor.sigstage.dev")
    }

    /// Get log info (tree size, root hash, etc.)
    pub async fn get_log_info(&self) -> Result<LogInfo> {
        let url = format!("{}/api/v1/log", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get log info: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Get a log entry by UUID
    pub async fn get_entry_by_uuid(&self, uuid: &str) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries/{}", self.url, uuid);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get entry {}: {}",
                uuid,
                response.status()
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        // Extract the single entry from the response
        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Get a log entry by index
    pub async fn get_entry_by_index(&self, index: i64) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries?logIndex={}", self.url, index);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get entry at index {}: {}",
                index,
                response.status()
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Create a new log entry (V1)
    pub async fn create_entry(&self, entry: HashedRekord) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries", self.url);
        let response = self
            .client
            .post(&url)
            .json(&entry)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create entry: {} - {}",
                status, body
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Create a new log entry (V2)
    pub async fn create_entry_v2(&self, entry: HashedRekordV2) -> Result<LogEntry> {
        let url = format!("{}/api/v2/log/entries", self.url);
        let response = self
            .client
            .post(&url)
            .json(&entry)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create entry: {} - {}",
                status, body
            )));
        }

        let response_text = response
            .text()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        let entry_v2: crate::entry::LogEntryV2 = serde_json::from_str(&response_text)
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        // Convert V2 entry to LogEntry
        let log_index = entry_v2.log_index.parse::<i64>().unwrap_or_default();
        let integrated_time = entry_v2.integrated_time.parse::<i64>().unwrap_or_default();

        let verification = Some(crate::entry::Verification {
            inclusion_proof: entry_v2
                .inclusion_proof
                .map(|p| crate::entry::InclusionProof {
                    checkpoint: p.checkpoint.envelope,
                    hashes: p.hashes.clone(),
                    log_index: p.log_index.parse::<i64>().unwrap_or_default(),
                    root_hash: p.root_hash,
                    tree_size: p.tree_size.parse::<i64>().unwrap_or_default(),
                }),
            signed_entry_timestamp: entry_v2.inclusion_promise.map(|p| p.signed_entry_timestamp),
        });

        Ok(LogEntry {
            uuid: Default::default(), // V2 response doesn't include UUID in body
            body: entry_v2.canonicalized_body,
            integrated_time,
            log_id: entry_v2.log_id.key_id.into_string().into(),
            log_index,
            verification,
        })
    }

    /// Create a new DSSE log entry
    pub async fn create_dsse_entry(&self, entry: DsseEntry) -> Result<LogEntry> {
        let url = format!("{}/api/v1/log/entries", self.url);
        let response = self
            .client
            .post(&url)
            .json(&entry)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "failed to create DSSE entry: {} - {}",
                status, body
            )));
        }

        let entries: LogEntryResponse = response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))?;

        let (entry_uuid, mut entry) = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Api("empty response".to_string()))?;

        entry.uuid = entry_uuid.into();
        Ok(entry)
    }

    /// Search the index for entries
    pub async fn search_index(&self, query: SearchIndex) -> Result<Vec<String>> {
        let url = format!("{}/api/v1/index/retrieve", self.url);
        let response = self
            .client
            .post(&url)
            .json(&query)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!("search failed: {}", response.status())));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Http(format!("failed to parse JSON: {}", e)))
    }

    /// Search by hash (hex encoded)
    pub async fn search_by_hash(&self, hash: &str) -> Result<Vec<String>> {
        self.search_index(SearchIndex {
            hash: Some(format!("sha256:{}", hash)),
            email: None,
            public_key: None,
        })
        .await
    }

    /// Get the public key of the log
    pub async fn get_public_key(&self) -> Result<String> {
        let url = format!("{}/api/v1/log/publicKey", self.url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "failed to get public key: {}",
                response.status()
            )));
        }

        response
            .text()
            .await
            .map_err(|e| Error::Http(e.to_string()))
    }
}

/// Convenience function to get log info from the public Rekor instance
pub async fn get_public_log_info() -> Result<LogInfo> {
    RekorClient::public().get_log_info().await
}
