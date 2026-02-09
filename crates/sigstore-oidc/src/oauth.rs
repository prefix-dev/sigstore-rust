//! OAuth flow implementation for interactive token acquisition
//!
//! This module implements OAuth 2.0 Authorization Code Flow with PKCE for obtaining
//! identity tokens from Sigstore's OAuth provider.
//!
//! The flow automatically selects between:
//! - **Browser mode**: Opens the user's browser and receives the code via a local redirect server
//! - **Out-of-band (OOB) mode**: User manually visits the URL and enters the code
//!
//! OOB mode is used when the browser cannot be opened (headless environment, remote machine)
//! or when the `browser` feature is not enabled.

use crate::error::{Error, Result};
use crate::token::IdentityToken;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

/// Standard OAuth out-of-band redirect URI
const OOB_REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";

/// Timeout for waiting for the browser callback (5 minutes)
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// OAuth configuration for a provider
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Authorization endpoint
    pub auth_url: String,
    /// Token endpoint
    pub token_url: String,
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
            client_id: "sigstore".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
        }
    }
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

/// The authentication mode being used
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// Browser was opened, redirect server is waiting for callback
    BrowserRedirect,
    /// Out-of-band mode - user must manually visit URL and enter code
    OutOfBand,
}

/// Options for authentication
#[derive(Debug, Clone, Default)]
pub struct AuthOptions {
    /// Force OOB mode even when browser opening might succeed
    pub force_oob: bool,
}

/// Callback trait for customizing the authentication UX
pub trait AuthCallback: crate::templates::HtmlTemplates {
    /// Called when the auth URL is ready
    ///
    /// In `BrowserRedirect` mode, the browser has been opened.
    /// In `OutOfBand` mode, the user must navigate to the URL manually.
    fn auth_url_ready(&self, url: &str, mode: AuthMode);

    /// Called in OOB mode to prompt user for the authorization code.
    ///
    /// This should read user input (e.g., from stdin) and return the code.
    /// Only called when mode is `OutOfBand`.
    fn prompt_for_code(&self) -> std::io::Result<String>;

    /// Called when waiting for the redirect callback (BrowserRedirect mode only)
    fn waiting_for_redirect(&self);

    /// Called when authentication completes successfully
    fn auth_complete(&self);
}

/// Default callback that prints to stdout and uses Sigstore-branded templates
pub struct DefaultAuthCallback;

impl crate::templates::HtmlTemplates for DefaultAuthCallback {
    fn success_html(&self) -> &str {
        crate::templates::default_success_html()
    }

    fn error_html(&self, error: &str) -> String {
        crate::templates::DefaultTemplates.error_html(error)
    }
}

impl AuthCallback for DefaultAuthCallback {
    fn auth_url_ready(&self, url: &str, mode: AuthMode) {
        match mode {
            AuthMode::BrowserRedirect => {
                println!("Opening browser for authentication...");
                println!();
                println!("If the browser doesn't open, visit:");
                println!("  {}", url);
            }
            AuthMode::OutOfBand => {
                println!("Go to the following link in your browser:");
                println!();
                println!("  {}", url);
            }
        }
        println!();
    }

    fn prompt_for_code(&self) -> std::io::Result<String> {
        use std::io;
        print!("Enter verification code: ");
        io::stdout().flush()?;
        let mut code = String::new();
        io::stdin().lock().read_line(&mut code)?;
        Ok(code.trim().to_string())
    }

    fn waiting_for_redirect(&self) {
        println!("Waiting for authentication in browser...");
    }

    fn auth_complete(&self) {
        println!("Authentication successful!");
    }
}

/// OAuth client for authorization code flow
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

    /// Generate a PKCE verifier and challenge
    fn generate_pkce() -> (String, String) {
        let mut rng = rand::rng();
        let mut verifier_bytes = [0u8; 32];
        rng.fill(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        let challenge_bytes = sigstore_crypto::sha256(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

        (verifier, challenge)
    }

    /// Generate a random state for CSRF protection
    fn generate_state() -> String {
        let mut rng = rand::rng();
        let mut state_bytes = [0u8; 16];
        rng.fill(&mut state_bytes);
        URL_SAFE_NO_PAD.encode(state_bytes)
    }

    /// Build the authorization URL
    fn build_auth_url(&self, redirect_uri: &str, challenge: &str, state: &str) -> Result<String> {
        let mut auth_url = Url::parse(&self.config.auth_url)
            .map_err(|e| Error::OAuth(format!("invalid auth URL: {}", e)))?;
        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state);
        Ok(auth_url.to_string())
    }

    /// Check if we should attempt browser opening
    #[cfg(feature = "browser")]
    fn should_try_browser() -> bool {
        true
    }

    #[cfg(not(feature = "browser"))]
    fn should_try_browser() -> bool {
        false
    }

    /// Perform authentication using the authorization code flow with PKCE.
    ///
    /// This method automatically selects between browser and OOB mode:
    /// 1. If `browser` feature is enabled, attempts to open the browser
    /// 2. If browser opens successfully, waits for the redirect callback
    /// 3. If browser fails or feature is disabled, falls back to OOB mode
    pub async fn auth(&self, callback: impl AuthCallback) -> Result<IdentityToken> {
        self.auth_with_options(callback, AuthOptions::default())
            .await
    }

    /// Perform authentication with custom options
    pub async fn auth_with_options(
        &self,
        callback: impl AuthCallback,
        options: AuthOptions,
    ) -> Result<IdentityToken> {
        let (verifier, challenge) = Self::generate_pkce();
        let state = Self::generate_state();

        let use_oob = options.force_oob || !Self::should_try_browser();

        if use_oob {
            self.auth_oob(&callback, &verifier, &challenge, &state)
                .await
        } else {
            self.auth_browser(&callback, &verifier, &challenge, &state)
                .await
        }
    }

    /// Browser-based auth flow with redirect server
    async fn auth_browser(
        &self,
        callback: &impl AuthCallback,
        verifier: &str,
        challenge: &str,
        state: &str,
    ) -> Result<IdentityToken> {
        // Start local server on a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| Error::OAuth(format!("failed to start local server: {}", e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::OAuth(format!("failed to get local address: {}", e)))?;

        let redirect_uri = format!("http://127.0.0.1:{}/callback", local_addr.port());

        // Build authorization URL
        let auth_url = self.build_auth_url(&redirect_uri, challenge, state)?;

        // Try to open browser
        #[cfg(feature = "browser")]
        let browser_opened = open::that(&auth_url).is_ok();
        #[cfg(not(feature = "browser"))]
        let browser_opened = false;

        if browser_opened {
            callback.auth_url_ready(&auth_url, AuthMode::BrowserRedirect);
            callback.waiting_for_redirect();

            // Wait for the callback with timeout
            let code = tokio::time::timeout(
                CALLBACK_TIMEOUT,
                self.wait_for_callback(&listener, state, callback),
            )
            .await
            .map_err(|_| {
                Error::OAuth(format!(
                    "timed out waiting for browser callback after {} seconds",
                    CALLBACK_TIMEOUT.as_secs()
                ))
            })??;

            // Exchange code for token
            let token = self.exchange_code(&code, verifier, &redirect_uri).await?;

            callback.auth_complete();
            Ok(token)
        } else {
            // Fall back to OOB mode
            drop(listener);
            self.auth_oob(callback, verifier, challenge, state).await
        }
    }

    /// Out-of-band auth flow where user manually enters the code
    async fn auth_oob(
        &self,
        callback: &impl AuthCallback,
        verifier: &str,
        challenge: &str,
        state: &str,
    ) -> Result<IdentityToken> {
        // Build auth URL with OOB redirect
        let auth_url = self.build_auth_url(OOB_REDIRECT_URI, challenge, state)?;

        callback.auth_url_ready(&auth_url, AuthMode::OutOfBand);

        // Get code from user (this briefly blocks the async runtime, but it's
        // acceptable for interactive user input of a single line)
        let code = callback
            .prompt_for_code()
            .map_err(|e| Error::OAuth(format!("failed to read code: {}", e)))?;

        // Exchange code for token
        let token = self
            .exchange_code(&code, verifier, OOB_REDIRECT_URI)
            .await?;

        callback.auth_complete();
        Ok(token)
    }

    /// Wait for the OAuth callback on the local server
    async fn wait_for_callback(
        &self,
        listener: &TcpListener,
        expected_state: &str,
        callback: &impl AuthCallback,
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

/// Get an identity token using interactive authentication.
///
/// This function automatically selects between browser and OOB mode:
/// 1. If `browser` feature is enabled, attempts to open the browser
/// 2. If browser opens successfully, receives the token via redirect
/// 3. If browser fails or feature is disabled, prompts for manual code entry
///
/// # Example
///
/// ```no_run
/// use sigstore_oidc::get_identity_token;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let token = get_identity_token().await?;
///     println!("Got token for: {}", token.subject());
///     Ok(())
/// }
/// ```
pub async fn get_identity_token() -> Result<IdentityToken> {
    OAuthClient::sigstore().auth(DefaultAuthCallback).await
}

/// Get an identity token with a custom callback for UX customization.
pub async fn get_identity_token_with_callback(
    callback: impl AuthCallback,
) -> Result<IdentityToken> {
    OAuthClient::sigstore().auth(callback).await
}

/// Get an identity token with options.
///
/// Use this to force OOB mode or customize other behavior.
pub async fn get_identity_token_with_options(options: AuthOptions) -> Result<IdentityToken> {
    OAuthClient::sigstore()
        .auth_with_options(DefaultAuthCallback, options)
        .await
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

    #[test]
    fn test_pkce_generation() {
        let (verifier, challenge) = OAuthClient::generate_pkce();
        // Verifier should be 43 chars (32 bytes base64url encoded)
        assert_eq!(verifier.len(), 43);
        // Challenge should be 43 chars (32 bytes SHA256 then base64url encoded)
        assert_eq!(challenge.len(), 43);
        // They should be different
        assert_ne!(verifier, challenge);
    }

    #[test]
    fn test_state_generation() {
        let state1 = OAuthClient::generate_state();
        let state2 = OAuthClient::generate_state();
        // State should be 22 chars (16 bytes base64url encoded)
        assert_eq!(state1.len(), 22);
        // Should be random
        assert_ne!(state1, state2);
    }
}
