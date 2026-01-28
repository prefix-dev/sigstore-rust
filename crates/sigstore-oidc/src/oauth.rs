//! OAuth flow implementation for interactive token acquisition
//!
//! This module implements OAuth 2.0 flows for obtaining identity tokens
//! from Sigstore's OAuth provider:
//!
//! - **Authorization Code Flow with PKCE**: Uses a local redirect server for
//!   seamless browser-based authentication. This is the preferred method.
//!
//! - **Device Code Flow**: Fallback for environments where a local server
//!   cannot be started. User manually enters a code.

use crate::error::{Error, Result};
use crate::token::IdentityToken;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[cfg(feature = "interactive")]
use std::io::{BufRead, BufReader, Write};
#[cfg(feature = "interactive")]
use tokio::net::TcpListener;
#[cfg(feature = "interactive")]
use url::Url;

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

/// Result of attempting to open a browser
#[cfg(feature = "interactive")]
#[derive(Debug)]
pub enum BrowserResult {
    /// Browser was opened successfully
    Opened,
    /// Failed to open browser, user should open URL manually
    Failed(String),
}

/// Callback for interactive authentication status updates
#[cfg(feature = "interactive")]
pub trait InteractiveCallback: crate::templates::HtmlTemplates {
    /// Called when the auth URL is ready
    fn auth_url_ready(&self, url: &str, browser_result: BrowserResult);

    /// Called when waiting for user to complete authentication
    fn waiting_for_auth(&self);

    /// Called when authentication is successful
    fn auth_complete(&self);
}

/// Default callback that prints to stdout and uses Sigstore-branded templates
#[cfg(feature = "interactive")]
pub struct DefaultInteractiveCallback;

#[cfg(feature = "interactive")]
impl crate::templates::HtmlTemplates for DefaultInteractiveCallback {
    fn success_html(&self) -> &str {
        crate::templates::DEFAULT_SUCCESS_HTML
    }

    fn error_html(&self, error: &str) -> String {
        crate::templates::DefaultTemplates.error_html(error)
    }
}

#[cfg(feature = "interactive")]
impl InteractiveCallback for DefaultInteractiveCallback {
    fn auth_url_ready(&self, url: &str, browser_result: BrowserResult) {
        match browser_result {
            BrowserResult::Opened => {
                println!("Opening browser for authentication...");
                println!();
                println!("If the browser doesn't open, visit:");
                println!("  {}", url);
            }
            BrowserResult::Failed(_) => {
                println!("Please open this URL in your browser:");
                println!();
                println!("  {}", url);
            }
        }
        println!();
    }

    fn waiting_for_auth(&self) {
        println!("Waiting for authentication in browser...");
    }

    fn auth_complete(&self) {
        println!("Authentication successful!");
    }
}

#[cfg(feature = "interactive")]
impl OAuthClient {
    /// Perform interactive authentication using the authorization code flow with PKCE.
    ///
    /// This method:
    /// 1. Starts a local HTTP server on an available port
    /// 2. Opens the user's browser to the authorization URL
    /// 3. Waits for the OAuth callback with the authorization code
    /// 4. Exchanges the code for tokens
    ///
    /// If the browser cannot be opened, the URL is printed for manual navigation.
    ///
    /// Requires the `interactive` feature.
    pub async fn interactive_auth(
        &self,
        callback: impl InteractiveCallback,
    ) -> Result<IdentityToken> {
        // Start local server on a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| Error::OAuth(format!("failed to start local server: {}", e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::OAuth(format!("failed to get local address: {}", e)))?;

        let redirect_uri = format!("http://127.0.0.1:{}/callback", local_addr.port());

        // Generate PKCE pair
        let mut rng = rand::rng();
        let mut verifier_bytes = [0u8; 32];
        rng.fill(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // Compute PKCE challenge using SHA-256
        let challenge_bytes = sigstore_crypto::sha256(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

        // Generate state for CSRF protection
        let mut state_bytes = [0u8; 16];
        rng.fill(&mut state_bytes);
        let state = URL_SAFE_NO_PAD.encode(state_bytes);

        // Build authorization URL
        let mut auth_url = Url::parse(&self.config.auth_url)
            .map_err(|e| Error::OAuth(format!("invalid auth URL: {}", e)))?;
        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state);
        let auth_url = auth_url.to_string();

        // Try to open browser
        let browser_result = match open::that(&auth_url) {
            Ok(()) => BrowserResult::Opened,
            Err(e) => BrowserResult::Failed(e.to_string()),
        };

        callback.auth_url_ready(&auth_url, browser_result);
        callback.waiting_for_auth();

        // Wait for the callback
        let code = self.wait_for_callback(&listener, &state, &callback).await?;

        // Exchange code for token
        let token = self.exchange_code(&code, &verifier, &redirect_uri).await?;

        callback.auth_complete();
        Ok(token)
    }

    /// Wait for the OAuth callback on the local server
    async fn wait_for_callback(
        &self,
        listener: &TcpListener,
        expected_state: &str,
        callback: &impl InteractiveCallback,
    ) -> Result<String> {
        // Accept a single connection
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| Error::OAuth(format!("failed to accept connection: {}", e)))?;

        // Convert to std TcpStream for synchronous reading
        let std_stream = stream
            .into_std()
            .map_err(|e| Error::OAuth(format!("failed to convert stream: {}", e)))?;

        std_stream
            .set_nonblocking(false)
            .map_err(|e| Error::OAuth(format!("failed to set blocking mode: {}", e)))?;

        let mut reader = BufReader::new(&std_stream);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .map_err(|e| Error::OAuth(format!("failed to read request: {}", e)))?;

        // Parse the request path
        let path = request_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| Error::OAuth("invalid HTTP request".to_string()))?;

        let url = Url::parse(&format!("http://localhost{}", path))
            .map_err(|e| Error::OAuth(format!("failed to parse callback URL: {}", e)))?;

        // Extract code and state from query parameters
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut error_description = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                "error_description" => error_description = Some(value.into_owned()),
                _ => {}
            }
        }

        // Send response to browser using templates
        let (status, html) = if let Some(ref err) = error {
            let error_msg = error_description.as_deref().unwrap_or(err);
            ("400 Bad Request", callback.error_html(error_msg))
        } else {
            ("200 OK", callback.success_html().to_string())
        };

        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            html.len(),
            html
        );

        // Use the raw stream for writing
        let mut write_stream = std_stream;
        write_stream
            .write_all(response.as_bytes())
            .map_err(|e| Error::OAuth(format!("failed to send response: {}", e)))?;
        write_stream
            .flush()
            .map_err(|e| Error::OAuth(format!("failed to flush response: {}", e)))?;

        // Check for errors
        if let Some(err) = error {
            let msg = error_description.unwrap_or(err);
            return Err(Error::OAuth(format!("authorization failed: {}", msg)));
        }

        // Verify state to prevent CSRF attacks
        let received_state =
            state.ok_or_else(|| Error::OAuth("missing state parameter".to_string()))?;
        if received_state != expected_state {
            return Err(Error::OAuth(
                "state mismatch - possible CSRF attack".to_string(),
            ));
        }

        code.ok_or_else(|| Error::OAuth("missing authorization code".to_string()))
    }

    /// Exchange authorization code for tokens
    async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<IdentityToken> {
        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("code", code),
            ("code_verifier", verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];

        let response = self
            .client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::OAuth(format!(
                "token exchange failed: {} - {}",
                status, body
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| Error::OAuth(format!("failed to parse token response: {}", e)))?;

        let id_token = token_response
            .id_token
            .ok_or_else(|| Error::OAuth("no id_token in response".to_string()))?;

        IdentityToken::from_jwt(&id_token)
    }
}

/// Get an identity token using interactive browser-based authentication.
///
/// This is the recommended method for interactive CLI usage. It:
/// 1. Starts a local server to receive the OAuth callback
/// 2. Opens the user's browser for authentication
/// 3. Automatically receives the token without manual code entry
///
/// If the browser cannot be opened, the URL is printed for manual navigation.
///
/// Requires the `interactive` feature.
#[cfg(feature = "interactive")]
pub async fn get_interactive_token() -> Result<IdentityToken> {
    OAuthClient::sigstore()
        .interactive_auth(DefaultInteractiveCallback)
        .await
}

/// Get an identity token using interactive authentication with a custom callback.
///
/// This allows customizing the messages shown during authentication.
///
/// Requires the `interactive` feature.
#[cfg(feature = "interactive")]
pub async fn get_interactive_token_with_callback(
    callback: impl InteractiveCallback,
) -> Result<IdentityToken> {
    OAuthClient::sigstore().interactive_auth(callback).await
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
