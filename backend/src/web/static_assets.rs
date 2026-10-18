//! Embedded static assets for VeilGate.
//! All assets are baked directly into the executable at compile time.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub const LOGO_DARK_PNG: &[u8] = include_bytes!("static/logo-dark.png");
pub const LOGO_LIGHT_PNG: &[u8] = include_bytes!("static/logo-light.png");
pub const SHIELD_MARK_PNG: &[u8] = include_bytes!("static/shield-mark.png");
pub const FAVICON_PNG: &[u8] = include_bytes!("static/favicon.png");
pub const APPLE_TOUCH_ICON_PNG: &[u8] = include_bytes!("static/apple-touch-icon.png");
pub const STYLE_CSS: &str = include_str!("static/style.css");
pub const APP_JS: &str = include_str!("static/app.js");

pub async fn serve_static(axum::extract::Path(filename): axum::extract::Path<String>) -> Response {
    let (content_type, body): (&str, Vec<u8>) = match filename.as_str() {
        "logo-dark.png" => ("image/png", LOGO_DARK_PNG.to_vec()),
        "logo-light.png" => ("image/png", LOGO_LIGHT_PNG.to_vec()),
        "shield-mark.png" => ("image/png", SHIELD_MARK_PNG.to_vec()),
        "favicon.png" => ("image/png", FAVICON_PNG.to_vec()),
        "apple-touch-icon.png" => ("image/png", APPLE_TOUCH_ICON_PNG.to_vec()),
        "style.css" => ("text/css; charset=utf-8", STYLE_CSS.as_bytes().to_vec()),
        "app.js" => ("application/javascript; charset=utf-8", APP_JS.as_bytes().to_vec()),
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, content_type),
            (CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        body,
    )
        .into_response()
}

pub async fn serve_favicon() -> Response {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "image/png"),
            (CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        FAVICON_PNG,
    )
        .into_response()
}

pub async fn serve_apple_touch_icon() -> Response {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "image/png"),
            (CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        APPLE_TOUCH_ICON_PNG,
    )
        .into_response()
}
