//! Web module for VeilGate website, checkout, merchant dashboard, and status API.

pub mod amount;
pub mod auth;
pub mod handlers;
pub mod icons;
pub mod middleware;
pub mod qr;
pub mod rate_limit;
pub mod static_assets;
pub mod templates;
#[cfg(test)]
pub mod tests;

use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::{BoxError, Router};
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;

pub use auth::hash_password;
pub use handlers::AppState;
use handlers::*;
use middleware::security_headers_middleware;
use static_assets::*;

/// Builds the Axum application router with all routes, security middleware, and Tower layers.
pub fn build_app(state: AppState) -> Router {
    let tower_layers = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|err: BoxError| async move {
            if err.is::<tower::timeout::error::Elapsed>() {
                (StatusCode::REQUEST_TIMEOUT, "Request timed out")
            } else {
                (StatusCode::SERVICE_UNAVAILABLE, "Service overloaded")
            }
        }))
        .layer(TimeoutLayer::new(Duration::from_secs(15)))
        .layer(ConcurrencyLimitLayer::new(256));

    Router::new()
        .route("/", get(landing_handler))
        .route("/static/{filename}", get(serve_static))
        .route("/favicon.png", get(serve_favicon))
        .route("/apple-touch-icon.png", get(serve_apple_touch_icon))
        .route("/privacy", get(privacy_handler))
        .route("/pay/{public_id}", get(pay_handler))
        .route("/api/invoice/{public_id}/status", get(invoice_status_handler))
        .route("/merchant/login", get(merchant_login_get).post(merchant_login_post))
        .route("/merchant", get(merchant_dashboard_get))
        .route("/merchant/invoices", post(merchant_create_invoice_post))
        .route("/merchant/logout", post(merchant_logout_post))
        .route("/demo", get(demo_get).post(demo_post))
        .layer(DefaultBodyLimit::max(8192))
        .layer(from_fn_with_state(state.clone(), security_headers_middleware))
        .layer(tower_layers)
        .with_state(state)
}
