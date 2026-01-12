//! Ambient credential detection for CI/CD environments
//!
//! This module provides detection and retrieval of OIDC tokens from
//! various CI/CD environments like GitHub Actions, GitLab CI, BuildKite, etc.
//!
//! It uses the [`ambient_id`] crate which provides robust support for:
//! - GitHub Actions (requires `id-token: write` permission)
//! - GitLab CI (using `<AUDIENCE>_ID_TOKEN` environment variables)
//! - BuildKite (using `buildkite-agent` command)

use crate::error::{Error, Result};
use crate::token::IdentityToken;

/// Default audience for Sigstore OIDC tokens
pub const SIGSTORE_AUDIENCE: &str = "sigstore";

/// Detected CI/CD environment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiEnvironment {
    /// GitHub Actions
    GitHubActions,
    /// GitLab CI
    GitLabCi,
    /// Buildkite
    Buildkite,
}

impl std::fmt::Display for CiEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiEnvironment::GitHubActions => write!(f, "GitHub Actions"),
            CiEnvironment::GitLabCi => write!(f, "GitLab CI"),
            CiEnvironment::Buildkite => write!(f, "Buildkite"),
        }
    }
}

/// Check if an environment variable is set to "true"
///
/// This matches the detection logic used by `ambient-id`.
fn env_is_true(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Detect the current CI/CD environment
///
/// Returns the detected CI environment, or `None` if not running in a
/// supported CI/CD environment.
///
/// # Supported environments
///
/// - **GitHub Actions**: Detected when `GITHUB_ACTIONS=true`
/// - **GitLab CI**: Detected when `GITLAB_CI=true`
/// - **Buildkite**: Detected when `BUILDKITE=true`
///
/// Note: The environment variable must be exactly `"true"` (lowercase).
/// This matches the behavior of the underlying `ambient-id` crate.
pub fn detect_environment() -> Option<CiEnvironment> {
    if env_is_true("GITHUB_ACTIONS") {
        Some(CiEnvironment::GitHubActions)
    } else if env_is_true("GITLAB_CI") {
        Some(CiEnvironment::GitLabCi)
    } else if env_is_true("BUILDKITE") {
        Some(CiEnvironment::Buildkite)
    } else {
        None
    }
}

/// Get an ambient identity token from the current environment
///
/// This function attempts to retrieve an OIDC token from the current CI/CD
/// environment. It uses the default Sigstore audience (`"sigstore"`).
///
/// # Supported environments
///
/// - **GitHub Actions**: Requests token from the Actions OIDC provider
///   (requires `id-token: write` permission in workflow)
/// - **GitLab CI**: Retrieves token from `SIGSTORE_ID_TOKEN` environment variable
///   (requires `id_tokens` configuration in `.gitlab-ci.yml`)
/// - **Buildkite**: Uses `buildkite-agent oidc request-token` command
///
/// # Example
///
/// ```no_run
/// use sigstore_oidc::{get_ambient_token, is_ci_environment};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// if is_ci_environment() {
///     let token = get_ambient_token().await?;
///     println!("Got token for: {}", token.subject());
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - No CI/CD environment is detected
/// - The environment is detected but token retrieval fails
/// - The retrieved token is not a valid JWT
pub async fn get_ambient_token() -> Result<IdentityToken> {
    get_ambient_token_with_audience(SIGSTORE_AUDIENCE).await
}

/// Get an ambient identity token with a custom audience
///
/// Similar to [`get_ambient_token`], but allows specifying a custom audience
/// for the OIDC token request.
///
/// # Arguments
///
/// * `audience` - The audience claim for the OIDC token (e.g., "sigstore")
///
/// # Example
///
/// ```no_run
/// use sigstore_oidc::get_ambient_token_with_audience;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let token = get_ambient_token_with_audience("my-custom-audience").await?;
/// # Ok(())
/// # }
/// ```
pub async fn get_ambient_token_with_audience(audience: &str) -> Result<IdentityToken> {
    let detector = ambient_id::Detector::new();

    let id_token = detector
        .detect(audience)
        .await
        .map_err(|e| Error::Token(format!("failed to detect ambient credentials: {}", e)))?
        .ok_or_else(|| Error::Token("no ambient credentials detected".to_string()))?;

    // Extract the token string from the SecretString
    let token_str = id_token.reveal();

    IdentityToken::from_jwt(token_str)
}

/// Check if we're running in a supported CI/CD environment
///
/// This is a convenience function that returns `true` if [`detect_environment`]
/// would return `Some(_)`.
///
/// # Example
///
/// ```
/// use sigstore_oidc::is_ci_environment;
///
/// if is_ci_environment() {
///     println!("Running in CI/CD");
/// } else {
///     println!("Not in CI/CD, will use interactive auth");
/// }
/// ```
pub fn is_ci_environment() -> bool {
    detect_environment().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detect_environment_none() {
        // In a test environment without CI vars set to "true", should return None
        let env = detect_environment();
        // Just verify it doesn't panic
        let _ = env;

        // Check that it's as expected when running in Github CI (our test environment)
        if env_is_true("GITHUB_ACTIONS") {
            assert_eq!(detect_environment(), Some(CiEnvironment::GitHubActions));

            // Grab a token
            let token = get_ambient_token().await;
            assert!(token.is_ok());
        }
    }
}
