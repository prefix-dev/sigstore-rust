//! HTML templates for OAuth callback pages
//!
//! This module provides customizable HTML templates for the authentication
//! success and error pages shown in the browser after OAuth callback.

/// Default success page HTML with Sigstore branding
pub const DEFAULT_SUCCESS_HTML: &str = include_str!("templates/success.html");

/// Default error page HTML with Sigstore branding
pub const DEFAULT_ERROR_HTML: &str = include_str!("templates/error.html");

/// Trait for customizing the HTML pages shown during OAuth callback.
///
/// Implement this trait to provide custom HTML for the success and error pages.
/// The default implementation uses the built-in Sigstore-branded templates.
pub trait HtmlTemplates {
    /// Returns the HTML to show when authentication succeeds.
    fn success_html(&self) -> &str {
        DEFAULT_SUCCESS_HTML
    }

    /// Returns the HTML to show when authentication fails.
    ///
    /// The `error` parameter contains the error message that occurred.
    /// You can embed this in your HTML template.
    fn error_html(&self, _error: &str) -> String {
        DEFAULT_ERROR_HTML.to_string()
    }
}

/// Default HTML templates with Sigstore branding.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultTemplates;

impl HtmlTemplates for DefaultTemplates {
    fn success_html(&self) -> &str {
        DEFAULT_SUCCESS_HTML
    }

    fn error_html(&self, error: &str) -> String {
        // Inject the error message into the template
        let html = DEFAULT_ERROR_HTML.replace(
            r#"<div class="error-details" id="error-details" style="display: none;">"#,
            &format!(
                r#"<div class="error-details" id="error-details">{}"#,
                html_escape(error)
            ),
        );
        html
    }
}

/// Simple HTML templates without Sigstore branding.
///
/// Use this for a minimal, lightweight response.
#[derive(Debug, Clone, Copy, Default)]
pub struct MinimalTemplates;

impl HtmlTemplates for MinimalTemplates {
    fn success_html(&self) -> &str {
        r#"<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
<div style="text-align: center;">
<h1 style="color: #10b981;">&#10003; Authentication Successful</h1>
<p>You may now close this window and return to your terminal.</p>
</div>
</body>
</html>"#
    }

    fn error_html(&self, error: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
<div style="text-align: center;">
<h1 style="color: #ef4444;">&#10007; Authentication Failed</h1>
<p>{}</p>
<p>Please close this window and try again.</p>
</div>
</body>
</html>"#,
            html_escape(error)
        )
    }
}

/// Escape HTML special characters to prevent XSS
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_default_templates_success() {
        let templates = DefaultTemplates;
        let html = templates.success_html();
        assert!(html.contains("Authentication Successful"));
        assert!(html.contains("sigstore"));
    }

    #[test]
    fn test_default_templates_error() {
        let templates = DefaultTemplates;
        let html = templates.error_html("test error message");
        assert!(html.contains("Authentication Failed"));
        assert!(html.contains("test error message"));
    }

    #[test]
    fn test_minimal_templates() {
        let templates = MinimalTemplates;
        assert!(templates
            .success_html()
            .contains("Authentication Successful"));
        assert!(templates.error_html("oops").contains("oops"));
    }
}
