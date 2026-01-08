//! OpenID Connect identity provider for Sigstore
//!
//! This crate handles identity token acquisition through various OIDC flows
//! including interactive browser-based OAuth and ambient credential detection.

pub mod error;
pub mod oauth;
pub mod token;

pub use error::{Error, Result};
pub use oauth::{get_identity_token, DeviceCodeResponse, OAuthClient, OAuthConfig};
pub use token::{issuers, Audience, FederatedClaims, IdentityToken, TokenClaims};

/// Parse an identity token from a JWT string
pub fn parse_identity_token(token: &str) -> Result<IdentityToken> {
    IdentityToken::from_jwt(token)
}
