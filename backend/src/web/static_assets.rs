//! Embedded static assets for VeilGate.
//! All assets are baked directly into the executable at compile time.

use std::collections::HashMap;
use std::sync::OnceLock;

use axum::extract::Query;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

pub const LOGO_DARK_PNG: &[u8] = include_bytes!("static/logo-dark.png");
pub const LOGO_LIGHT_PNG: &[u8] = include_bytes!("static/logo-light.png");
pub const SHIELD_MARK_PNG: &[u8] = include_bytes!("static/shield-mark.png");
pub const FAVICON_PNG: &[u8] = include_bytes!("static/favicon.png");
pub const APPLE_TOUCH_ICON_PNG: &[u8] = include_bytes!("static/apple-touch-icon.png");
pub const STYLE_CSS: &str = include_str!("static/style.css");
pub const APP_JS: &str = include_str!("static/app.js");

const CACHE_VERSIONED: &str = "public, max-age=86400, immutable";
const CACHE_UNVERSIONED: &str = "no-cache";

/// Short content hash (first 8 hex chars of SHA-256) used as a cache-busting version.
pub fn content_version(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn asset_bytes(filename: &str) -> Option<&'static [u8]> {
    match filename {
        "logo-dark.png" => Some(LOGO_DARK_PNG),
        "logo-light.png" => Some(LOGO_LIGHT_PNG),
        "shield-mark.png" => Some(SHIELD_MARK_PNG),
        "favicon.png" => Some(FAVICON_PNG),
        "apple-touch-icon.png" => Some(APPLE_TOUCH_ICON_PNG),
        "style.css" => Some(STYLE_CSS.as_bytes()),
        "app.js" => Some(APP_JS.as_bytes()),
        _ => None,
    }
}

/// Version of a known asset, computed once at startup (first use).
pub fn asset_version(filename: &str) -> Option<&'static str> {
    static VERSIONS: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    let map = VERSIONS.get_or_init(|| {
        [
            "logo-dark.png",
            "logo-light.png",
            "shield-mark.png",
            "favicon.png",
            "apple-touch-icon.png",
            "style.css",
            "app.js",
        ]
        .into_iter()
        .filter_map(|n| asset_bytes(n).map(|b| (n, content_version(b))))
        .collect()
    });
    map.get(filename).map(|s| s.as_str())
}

/// Versioned URL for a static asset, e.g. `static_url("style.css")` -> `/static/style.css?v=0123abcd`.
/// Favicon and apple-touch-icon are served from the site root.
pub fn static_url(filename: &str) -> String {
    let base = match filename {
        "favicon.png" | "apple-touch-icon.png" => format!("/{filename}"),
        _ => format!("/static/{filename}"),
    };
    match asset_version(filename) {
        Some(v) => format!("{base}?v={v}"),
        None => base,
    }
}

/// `immutable` only when the request carries the current content version.
fn cache_header(filename: &str, query: &HashMap<String, String>) -> &'static str {
    match (query.get("v"), asset_version(filename)) {
        (Some(req), Some(cur)) if req == cur => CACHE_VERSIONED,
        _ => CACHE_UNVERSIONED,
    }
}

fn respond(filename: &str, content_type: &'static str, query: &HashMap<String, String>) -> Response {
    match asset_bytes(filename) {
        Some(body) => (
            StatusCode::OK,
            [
                (CONTENT_TYPE, content_type),
                (CACHE_CONTROL, cache_header(filename, query)),
            ],
            body,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

pub async fn serve_static(
    axum::extract::Path(filename): axum::extract::Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let content_type = match filename.as_str() {
        "logo-dark.png" | "logo-light.png" | "shield-mark.png" | "favicon.png"
        | "apple-touch-icon.png" => "image/png",
        "style.css" => "text/css; charset=utf-8",
        "app.js" => "application/javascript; charset=utf-8",
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    respond(&filename, content_type, &query)
}

pub async fn serve_favicon(Query(query): Query<HashMap<String, String>>) -> Response {
    respond("favicon.png", "image/png", &query)
}

pub async fn serve_apple_touch_icon(Query(query): Query<HashMap<String, String>>) -> Response {
    respond("apple-touch-icon.png", "image/png", &query)
}
