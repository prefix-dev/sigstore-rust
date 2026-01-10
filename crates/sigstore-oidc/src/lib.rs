//! OpenID Connect identity provider for Sigstore
//!
//! This crate handles identity token acquisition through various OIDC flows
//! including interactive browser-based OAuth and ambient credential detection.

pub mod ambient;
pub mod error;
pub mod oauth;
pub mod token;

pub use ambient::{
    detect_environment, get_ambient_token, get_ambient_token_with_audience, is_ci_environment,
    CiEnvironment, SIGSTORE_AUDIENCE,
};
pub use error::{Error, Result};
pub use oauth::{get_identity_token, DeviceCodeResponse, OAuthClient, OAuthConfig};
pub use token::{issuers, Audience, FederatedClaims, IdentityToken, TokenClaims};

/// Parse an identity token from a JWT string
pub fn parse_identity_token(token: &str) -> Result<IdentityToken> {
    IdentityToken::from_jwt(token)
}
