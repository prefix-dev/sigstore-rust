//! OAuth flow implementation for interactive token acquisition
//!
//! This module implements the OAuth 2.0 device code flow for obtaining
//! identity tokens from Sigstore's OAuth provider.

use crate::error::{Error, Result};
use crate::token::IdentityToken;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// OAuth configuration for a provider
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Authorization endpoint
    pub auth_url: String,
    /// Token endpoint
    pub token_url: String,
    /// Device authorization endpoint
    pub device_auth_url: String,
    /// Client ID
    pub client_id: String,
    /// Scopes to request
    pub scopes: Vec<String>,
}

impl OAuthConfig {
    /// Create configuration for Sigstore's public OAuth provider
    pub fn sigstore() -> Self {
        Self {
            auth_url: "https://oauth2.sigstore.dev/auth/auth".to_string(),
            token_url: "https://oauth2.sigstore.dev/auth/token".to_string(),
            device_auth_url: "https://oauth2.sigstore.dev/auth/device/code".to_string(),
            client_id: "sigstore".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
        }
    }
}

/// Device code flow response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    /// The device code
    pub device_code: String,
    /// User code to enter
    pub user_code: String,
    /// Verification URI
    pub verification_uri: String,
    /// Complete verification URI with code
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Expiration in seconds
    pub expires_in: u64,
    /// Polling interval in seconds
    pub interval: u64,
}

/// Token response from the OAuth server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Expiration in seconds
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// ID token (this is what we want for Sigstore)
    #[serde(default)]
    pub id_token: Option<String>,
}

/// OAuth client for device code flow
pub struct OAuthClient {
    config: OAuthConfig,
    client: reqwest::Client,
}

impl OAuthClient {
    /// Create a new OAuth client with the given configuration
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Create a client for Sigstore's OAuth provider
    pub fn sigstore() -> Self {
        Self::new(OAuthConfig::sigstore())
    }

    /// Start the device code flow
    ///
    /// Returns the device code response which contains the user code
    /// and verification URI to show to the user, along with the PKCE verifier.
    pub async fn start_device_flow(&self) -> Result<(DeviceCodeResponse, String)> {
        // Generate PKCE pair
        let mut rng = rand::rng();
        let mut verifier_bytes = [0u8; 32];
        rng.fill(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // Compute PKCE challenge using SHA-256
        let challenge_bytes = sigstore_crypto::sha256(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("scope", &self.config.scopes.join(" ")),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ];

        let response = self
            .client
            .post(&self.config.device_auth_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::OAuth(format!(
                "device auth failed: {} - {}",
                status, body
            )));
        }

        let response_data = response
            .json()
            .await
            .map_err(|e| Error::OAuth(format!("failed to parse device code response: {}", e)))?;

        Ok((response_data, verifier))
    }

    /// Poll for the token after user authorization
    ///
    /// This should be called after showing the user the verification URI.
    /// It will poll the token endpoint until the user completes authorization
    /// or the device code expires.
    pub async fn poll_for_token(
        &self,
        device_code: &str,
        verifier: &str,
        interval: u64,
    ) -> Result<IdentityToken> {
        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("code_verifier", verifier),
        ];

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

            let response = self
                .client
                .post(&self.config.token_url)
                .form(&params)
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;

            if response.status().is_success() {
                let token_response: TokenResponse = response
                    .json()
                    .await
                    .map_err(|e| Error::OAuth(format!("failed to parse token response: {}", e)))?;

                let id_token = token_response
                    .id_token
                    .ok_or_else(|| Error::OAuth("no id_token in response".to_string()))?;

                return IdentityToken::from_jwt(&id_token);
            }

            // Check for polling errors
            #[derive(Deserialize)]
            struct ErrorResponse {
                error: String,
            }

            let error: ErrorResponse = response
                .json()
                .await
                .map_err(|e| Error::OAuth(format!("failed to parse error response: {}", e)))?;

            match error.error.as_str() {
                "authorization_pending" => {
                    // Keep polling
                    continue;
                }
                "slow_down" => {
                    // Increase interval and continue
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
                "expired_token" => {
                    return Err(Error::OAuth("device code expired".to_string()));
                }
                "access_denied" => {
                    return Err(Error::OAuth("user denied authorization".to_string()));
                }
                _ => {
                    return Err(Error::OAuth(format!("token error: {}", error.error)));
                }
            }
        }
    }

    /// Perform the complete device code flow
    ///
    /// This combines `start_device_flow` and `poll_for_token` with a callback
    /// to display the verification URL to the user.
    pub async fn device_flow<F>(&self, display: F) -> Result<IdentityToken>
    where
        F: FnOnce(&DeviceCodeResponse),
    {
        let (device_response, verifier) = self.start_device_flow().await?;
        display(&device_response);
        self.poll_for_token(
            &device_response.device_code,
            &verifier,
            device_response.interval,
        )
        .await
    }
}

/// Convenience function to get an identity token using the device code flow
pub async fn get_identity_token<F>(display: F) -> Result<IdentityToken>
where
    F: FnOnce(&DeviceCodeResponse),
{
    OAuthClient::sigstore().device_flow(display).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_config_sigstore() {
        let config = OAuthConfig::sigstore();
        assert_eq!(config.client_id, "sigstore");
        assert!(config.scopes.contains(&"openid".to_string()));
        assert!(config.scopes.contains(&"email".to_string()));
    }
}
