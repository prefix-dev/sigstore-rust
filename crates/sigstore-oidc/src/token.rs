//! Identity token handling

use crate::error::{Error, Result};
use ambient_id::Detector;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// An OIDC identity token
#[derive(Debug, Clone)]
pub struct IdentityToken {
    /// The raw JWT token
    raw: String,
    /// Parsed claims
    claims: TokenClaims,
}

/// Standard OIDC claims we care about
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Issuer
    pub iss: String,
    /// Subject
    pub sub: String,
    /// Audience (can be string or array)
    #[serde(default)]
    pub aud: Audience,
    /// Expiration time
    pub exp: u64,
    /// Issued at
    #[serde(default)]
    pub iat: u64,
    /// Email (Sigstore-specific)
    #[serde(default)]
    pub email: Option<String>,
    /// Email verified
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Federated claims (for GitHub Actions, etc.)
    #[serde(default)]
    pub federated_claims: Option<FederatedClaims>,
}

/// Audience can be a single string or array of strings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum Audience {
    #[default]
    None,
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    /// Check if the audience contains a specific value
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::None => false,
            Audience::Single(s) => s == value,
            Audience::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}

/// Federated claims for CI/CD environments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedClaims {
    /// Connector ID
    #[serde(default)]
    pub connector_id: Option<String>,
    /// User ID
    #[serde(default)]
    pub user_id: Option<String>,
}

impl IdentityToken {
    /// Parse a JWT token string
    pub fn from_jwt(token: &str) -> Result<Self> {
        // JWT format: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Token("invalid JWT format".to_string()));
        }

        // Decode the payload (middle part)
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| Error::Token(format!("failed to decode payload: {}", e)))?;

        // Parse the claims
        let claims: TokenClaims = serde_json::from_slice(&payload)
            .map_err(|e| Error::Token(format!("failed to parse claims: {}", e)))?;

        Ok(Self {
            raw: token.to_string(),
            claims,
        })
    }

    /// Detect and retrieve an ambient identity token from the current environment
    ///
    /// This attempts to find OIDC credentials in environments like GitHub Actions,
    /// GitLab CI, Buildkite, etc. using the `ambient-id` crate.
    pub async fn detect_ambient() -> Result<Option<Self>> {
        match Detector::new().detect("sigstore").await {
            Ok(Some(token)) => Self::from_jwt(token.reveal()).map(Some),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Token(format!(
                "failed to detect ambient credentials: {}",
                e
            ))),
        }
    }

    /// Create from raw token string without parsing
    pub fn new(token: impl Into<String>) -> Self {
        let raw = token.into();
        // Try to parse, fall back to empty claims
        let claims = Self::parse_claims(&raw).unwrap_or_else(|_| TokenClaims {
            iss: String::new(),
            sub: String::new(),
            aud: Audience::None,
            exp: 0,
            iat: 0,
            email: None,
            email_verified: None,
            federated_claims: None,
        });
        Self { raw, claims }
    }

    fn parse_claims(token: &str) -> Result<TokenClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Token("invalid JWT format".to_string()));
        }
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| Error::Token(format!("failed to decode payload: {}", e)))?;
        serde_json::from_slice(&payload)
            .map_err(|e| Error::Token(format!("failed to parse claims: {}", e)))
    }

    /// Get the raw JWT string
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Get the token string (alias for raw)
    pub fn token(&self) -> &str {
        &self.raw
    }

    /// Get the issuer
    pub fn issuer(&self) -> &str {
        &self.claims.iss
    }

    /// Get the subject
    pub fn subject(&self) -> &str {
        &self.claims.sub
    }

    /// Get the email if present
    pub fn email(&self) -> Option<&str> {
        self.claims.email.as_deref()
    }

    /// Check if the email is verified
    pub fn email_verified(&self) -> bool {
        self.claims.email_verified.unwrap_or(false)
    }

    /// Get the expiration time
    pub fn expiration(&self) -> u64 {
        self.claims.exp
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.claims.exp < now
    }

    /// Get the claims
    pub fn claims(&self) -> &TokenClaims {
        &self.claims
    }

    /// Get the identity for Sigstore (email or subject)
    pub fn identity(&self) -> &str {
        self.claims.email.as_deref().unwrap_or(&self.claims.sub)
    }
}

/// Known OIDC issuers
pub mod issuers {
    /// Sigstore's public Dex instance
    pub const SIGSTORE_OAUTH: &str = "https://oauth2.sigstore.dev/auth";
    /// GitHub Actions OIDC
    pub const GITHUB_ACTIONS: &str = "https://token.actions.githubusercontent.com";
    /// Google Accounts
    pub const GOOGLE: &str = "https://accounts.google.com";
    /// Microsoft
    pub const MICROSOFT: &str = "https://login.microsoftonline.com";
    /// GitLab
    pub const GITLAB: &str = "https://gitlab.com";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_contains() {
        let single = Audience::Single("test".to_string());
        assert!(single.contains("test"));
        assert!(!single.contains("other"));

        let multiple = Audience::Multiple(vec!["a".to_string(), "b".to_string()]);
        assert!(multiple.contains("a"));
        assert!(multiple.contains("b"));
        assert!(!multiple.contains("c"));
    }

    #[test]
    fn test_parse_jwt() {
        // Create a test JWT (header.payload.signature)
        // Header: {"alg":"none"}
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        // Payload with required claims
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{"iss":"https://test.com","sub":"user123","exp":9999999999,"email":"test@example.com"}"#,
        );
        let signature = "signature";
        let jwt = format!("{}.{}.{}", header, payload, signature);

        let token = IdentityToken::from_jwt(&jwt).unwrap();
        assert_eq!(token.issuer(), "https://test.com");
        assert_eq!(token.subject(), "user123");
        assert_eq!(token.email(), Some("test@example.com"));
        assert!(!token.is_expired());
    }
}
