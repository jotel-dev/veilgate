//! Security and privacy middleware for all HTTP responses.
//!
//! Enforces strict Content-Security-Policy, Permissions-Policy, COOP, CORP,
//! HSTS (when non-localhost), anti-tracking, nosniff, noindex,
//! and ensures that no sensitive request information is logged.

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

use crate::web::handlers::AppState;

pub async fn security_headers_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let host = req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
    let is_host_localhost = if host.is_empty() {
        state.is_localhost
    } else {
        host.starts_with("localhost")
            || host.starts_with("127.0.0.1")
            || host.starts_with("[::1]")
    };

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    // CSP: strictly 'self' for styles, images, scripts, connect, form-action;
    // 'none' for default, font, frame, object, media, base-uri.
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );

    // Permissions-Policy: camera, microphone, geolocation, payment, usb all denied
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );

    // Cross-Origin policies
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );

    // Strict-Transport-Security (max-age 31536000) only when not localhost
    if !state.is_localhost && !is_host_localhost {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }

    // Anti-tracking & sniffing headers
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));

    // Pages handling invoice data, authentication, health checks, or demo interaction must not be indexed or cached
    let is_sensitive = path.starts_with("/pay")
        || path.starts_with("/api/invoice")
        || path.starts_with("/merchant")
        || path.starts_with("/demo")
        || path == "/healthz";

    if is_sensitive {
        headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
    }

    resp
}
