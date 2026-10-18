//! Axum route handlers for VeilGate web interface.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Form, FromRef, Path, Query, State};
use axum::http::header::{HeaderMap, HeaderValue, CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::{Deserialize, Serialize};
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::Network;

use crate::invoices::{create_demo_invoice, create_invoice, Store};
use crate::scanner::InvoicePaymentState;
use crate::web::amount::parse_zec_amount;
use crate::web::auth::{
    constant_time_compare, is_valid_csrf_token, verify_password, SessionManager, CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECS,
};
use crate::web::qr::render_qr_svg;
use crate::web::rate_limit::RateLimiter;
use crate::web::templates::{
    render_demo_page, render_landing_page, render_login_page, render_merchant_dashboard,
    render_pay_page, render_privacy_page,
};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub uivk: Arc<UnifiedIncomingViewingKey>,
    pub network: Network,
    pub confirmations: u32,
    pub repo_url: Option<String>,
    pub demo_enabled: bool,
    pub password_hash: Option<String>,
    pub session_manager: Arc<SessionManager>,
    pub rate_limiter: Arc<RateLimiter>,
    pub is_localhost: bool,
    pub trusted_proxy_header: Option<String>,
}



/// Extractor for client identity.
///
/// Uses TCP peer address from axum's `ConnectInfo` by default.
/// If `trusted_proxy_header` is configured on `AppState`, reads from that header instead
/// (using the LAST comma-separated entry).
pub struct ClientIdentity(pub String);

impl<S> axum::extract::FromRequestParts<S> for ClientIdentity
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let connect_info = parts.extensions.get::<ConnectInfo<SocketAddr>>();
        let client_id = resolve_client_identity(
            &parts.headers,
            connect_info,
            app_state.trusted_proxy_header.as_deref(),
        );
        Ok(ClientIdentity(client_id))
    }
}

// --- Cookie and Client Helpers ---

fn get_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            if k == name {
                return Some(v);
            }
        }
    }
    None
}

/// Retrieves the CSRF cookie value ONLY if it matches exactly 64 lowercase hex characters.
/// Returns None if missing or invalid, ensuring unvalidated values are never accepted or reflected.
fn get_valid_csrf_cookie<'a>(headers: &'a HeaderMap) -> Option<&'a str> {
    let raw = get_cookie(headers, CSRF_COOKIE_NAME)?;
    if is_valid_csrf_token(raw) {
        Some(raw)
    } else {
        None
    }
}

/// Resolves the client identity for rate-limiting.
///
/// Uses the TCP peer address by default. Ignores `X-Forwarded-For` and `X-Real-IP`
/// unless `trusted_proxy_header` matches the incoming header.
/// When `x-forwarded-for` is trusted, uses the LAST entry (appended by the proxy).
pub fn resolve_client_identity(
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
    trusted_proxy_header: Option<&str>,
) -> String {
    if let Some(trusted_name) = trusted_proxy_header {
        let name_lower = trusted_name.to_ascii_lowercase();
        if let Some(val) = headers.get(&name_lower).and_then(|h| h.to_str().ok()) {
            if name_lower == "x-forwarded-for" {
                if let Some(last) = val.split(',').next_back() {
                    let trimmed = last.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            } else {
                let trimmed = val.split(',').next_back().unwrap_or(val).trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    if let Some(ConnectInfo(addr)) = connect_info {
        return addr.ip().to_string();
    }

    "127.0.0.1".to_string()
}

fn has_valid_session(headers: &HeaderMap, session_manager: &SessionManager) -> bool {
    if let Some(token) = get_cookie(headers, SESSION_COOKIE_NAME) {
        session_manager.get_session(token).is_some()
    } else {
        false
    }
}

fn make_cookie(name: &str, value: &str, max_age_secs: u64, is_localhost: bool) -> HeaderValue {
    let secure_flag = if is_localhost { "" } else { "; Secure" };
    let s = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        name, value, max_age_secs, secure_flag
    );
    HeaderValue::from_str(&s).unwrap()
}

fn delete_cookie(name: &str, is_localhost: bool) -> HeaderValue {
    let secure_flag = if is_localhost { "" } else { "; Secure" };
    let s = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        name, secure_flag
    );
    HeaderValue::from_str(&s).unwrap()
}

// --- Status API Formats ---

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct InvoiceStatusJson {
    pub state: String,
    pub amount: u64,
    pub received: u64,
    pub confirmations_remaining: u32,
}

// --- Handlers ---

/// `GET /` Landing Page
pub async fn landing_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let has_session = has_valid_session(&headers, &state.session_manager);
    Html(render_landing_page(state.repo_url.as_deref(), has_session))
}

/// `GET /privacy` Privacy Model Page
pub async fn privacy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let has_session = has_valid_session(&headers, &state.session_manager);
    Html(render_privacy_page(state.repo_url.as_deref(), has_session))
}

/// `GET /pay/{public_id}` Customer Pay Page
pub async fn pay_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(public_id): Path<String>,
) -> Response {
    let inv = match state.store.get_by_public_id(&public_id) {
        Ok(Some(i)) => i,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Html("<!DOCTYPE html><html><head><title>Invoice Not Found</title></head><body><h1>404 &mdash; Invoice Not Found</h1></body></html>"),
            )
                .into_response()
        }
    };

    let tip = state.store.get_chain_tip().unwrap_or(None).unwrap_or(0);
    let payment_state = crate::scanner::invoice_payment_state(
        &state.store,
        inv.address_index,
        tip,
        state.confirmations,
    )
    .unwrap_or(InvoicePaymentState::NoPayment);

    let (status_label, status_class, status_desc, received_zatoshi): (Cow<'static, str>, _, _, _) = match payment_state {
        InvoicePaymentState::Paid { received, late, .. } => {
            if late {
                (
                    Cow::Borrowed("Paid (late)"),
                    "status-paid",
                    "Payment confirmed on-chain after expiry.",
                    received,
                )
            } else {
                (
                    Cow::Borrowed("Paid"),
                    "status-paid",
                    "Payment confirmed on-chain. Invoice is complete.",
                    received,
                )
            }
        }
        InvoicePaymentState::Detected {
            received,
            confirmations_remaining,
        } => {
            let label = if confirmations_remaining == 1 {
                "Payment detected (1 confirmation remaining)".to_string()
            } else {
                format!(
                    "Payment detected ({} confirmations remaining)",
                    confirmations_remaining
                )
            };
            (
                Cow::Owned(label),
                "status-detected",
                "Payment detected in recent blocks. Awaiting confirmation...",
                received,
            )
        }
        InvoicePaymentState::Underpaid { received, missing } => {
            let label = format!(
                "Underpaid (missing {})",
                crate::web::amount::format_zec_display(missing)
            );
            (
                Cow::Owned(label),
                "status-underpaid",
                "Partial payment received. Please send remaining balance.",
                received,
            )
        }
        InvoicePaymentState::NoPayment => {
            if inv.status == crate::invoices::InvoiceStatus::Expired {
                (
                    Cow::Borrowed("Expired"),
                    "status-expired",
                    "This invoice has expired. Do not send funds to this address.",
                    0,
                )
            } else {
                (
                    Cow::Borrowed("Awaiting payment"),
                    "status-awaiting",
                    "Send payment from your Zcash shielded wallet.",
                    0,
                )
            }
        }
    };

    let zip321 = inv.payment_uri(&state.network);
    let qr_svg = match render_qr_svg(&zip321) {
        Ok(svg) => svg,
        Err(_) => r#"<div class="form-error">QR code generation failed</div>"#.to_string(),
    };

    let has_session = has_valid_session(&headers, &state.session_manager);
    let html = render_pay_page(
        &inv,
        &qr_svg,
        status_label,
        status_class,
        status_desc,
        received_zatoshi,
        &zip321,
        state.repo_url.as_deref(),
        has_session,
    );

    Html(html).into_response()
}

/// `GET /api/invoice/{public_id}/status` Status API
pub async fn invoice_status_handler(
    State(state): State<AppState>,
    ClientIdentity(client_id): ClientIdentity,
    Path(public_id): Path<String>,
) -> Response {
    let key = state.rate_limiter.client_key("status", &client_id);
    if !state
        .rate_limiter
        .check_and_record(&key, 60, Duration::from_secs(60))
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(CONTENT_TYPE, "application/json")],
            r#"{"error":"too_many_requests"}"#,
        )
            .into_response();
    }

    let inv = match state.store.get_by_public_id(&public_id) {
        Ok(Some(i)) => i,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                [(CONTENT_TYPE, "application/json")],
                r#"{"error":"not_found"}"#,
            )
                .into_response();
        }
    };

    let tip = state.store.get_chain_tip().unwrap_or(None).unwrap_or(0);
    let payment_state = crate::scanner::invoice_payment_state(
        &state.store,
        inv.address_index,
        tip,
        state.confirmations,
    )
    .unwrap_or(InvoicePaymentState::NoPayment);

    let (state_str, received, confs_remaining) = match payment_state {
        InvoicePaymentState::Paid { received, .. } => ("paid".to_string(), received, 0),
        InvoicePaymentState::Detected {
            received,
            confirmations_remaining,
        } => (
            "payment_detected".to_string(),
            received,
            confirmations_remaining,
        ),
        InvoicePaymentState::Underpaid { received, .. } => {
            ("underpaid".to_string(), received, 0)
        }
        InvoicePaymentState::NoPayment => {
            if inv.status == crate::invoices::InvoiceStatus::Expired {
                ("expired".to_string(), 0, 0)
            } else {
                ("awaiting_payment".to_string(), 0, state.confirmations)
            }
        }
    };

    let resp = InvoiceStatusJson {
        state: state_str,
        amount: inv.amount_zatoshi,
        received,
        confirmations_remaining: confs_remaining,
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        serde_json::to_string(&resp).unwrap(),
    )
        .into_response()
}

// --- Forms ---

#[derive(Deserialize)]
pub struct LoginForm {
    pub csrf_token: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateInvoiceForm {
    pub csrf_token: String,
    pub amount: String,
    pub validity_minutes: u64,
}

#[derive(Deserialize)]
pub struct LogoutForm {
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct DemoForm {
    pub csrf_token: String,
    pub amount: String,
    pub validity_minutes: u64,
}

#[derive(Deserialize, Default)]
pub struct DashboardQuery {
    pub filter: Option<String>,
    pub show_demo: Option<bool>,
}

// --- Merchant Area ---

/// `GET /merchant/login`
pub async fn merchant_login_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Some(session_token) = get_cookie(&headers, SESSION_COOKIE_NAME) {
        if state.session_manager.get_session(session_token).is_some() {
            return (StatusCode::SEE_OTHER, [(LOCATION, "/merchant")]).into_response();
        }
    }

    let (csrf_token, set_cookie_opt) = match get_valid_csrf_cookie(&headers) {
        Some(t) => (t.to_string(), None),
        None => {
            let t = SessionManager::generate_token();
            let c = make_cookie(CSRF_COOKIE_NAME, &t, SESSION_MAX_AGE_SECS, state.is_localhost);
            (t, Some(c))
        }
    };

    let html = render_login_page(&csrf_token, None, state.repo_url.as_deref());
    let mut resp = Html(html).into_response();
    if let Some(c) = set_cookie_opt {
        resp.headers_mut().insert(SET_COOKIE, c);
    }
    resp
}

/// `POST /merchant/login`
pub async fn merchant_login_post(
    State(state): State<AppState>,
    ClientIdentity(client_id): ClientIdentity,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // Global login limiter across all clients (10 attempts per minute)
    if !state
        .rate_limiter
        .check_and_record("global:login", 10, Duration::from_secs(60))
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html("<h1>429 &mdash; Too Many Login Attempts. Try again in 1 minute.</h1>"),
        )
            .into_response();
    }

    // Per-client login limiter (5 attempts per minute)
    let client_key = state.rate_limiter.client_key("login", &client_id);
    if !state
        .rate_limiter
        .check_and_record(&client_key, 5, Duration::from_secs(60))
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html("<h1>429 &mdash; Too Many Login Attempts. Try again in 1 minute.</h1>"),
        )
            .into_response();
    }

    // Constant-time CSRF check
    let cookie_csrf = get_valid_csrf_cookie(&headers);
    if cookie_csrf.is_none()
        || !is_valid_csrf_token(&form.csrf_token)
        || !constant_time_compare(cookie_csrf.unwrap(), &form.csrf_token)
    {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 &mdash; Invalid or missing CSRF token</h1>"),
        )
            .into_response();
    }

    let valid_csrf = cookie_csrf.unwrap();

    // Generic error: never reveal env var names or internal details
    let expected_hash = match &state.password_hash {
        Some(h) => h,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Merchant login is currently unavailable. Please try again later.</h1>"),
            )
                .into_response()
        }
    };

    if !verify_password(&form.password, expected_hash) {
        let html = render_login_page(
            valid_csrf,
            Some("Invalid merchant password."),
            state.repo_url.as_deref(),
        );
        return (StatusCode::UNAUTHORIZED, Html(html)).into_response();
    }

    let session = state.session_manager.create_session();
    let session_cookie = make_cookie(
        SESSION_COOKIE_NAME,
        &session.token,
        SESSION_MAX_AGE_SECS,
        state.is_localhost,
    );

    (
        StatusCode::SEE_OTHER,
        [(LOCATION, "/merchant"), (SET_COOKIE, session_cookie.to_str().unwrap())],
    )
        .into_response()
}

/// `GET /merchant`
pub async fn merchant_dashboard_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DashboardQuery>,
) -> Response {
    let session_token = match get_cookie(&headers, SESSION_COOKIE_NAME) {
        Some(t) => t,
        None => return (StatusCode::SEE_OTHER, [(LOCATION, "/merchant/login")]).into_response(),
    };

    let session = match state.session_manager.get_session(session_token) {
        Some(s) => s,
        None => return (StatusCode::SEE_OTHER, [(LOCATION, "/merchant/login")]).into_response(),
    };

    let all_invoices = state.store.list_invoices().unwrap_or_default();
    let show_demo_flag = query.show_demo.unwrap_or(false);
    let validated_filter = match query.filter.as_deref() {
        Some("demo") => "demo",
        Some("all") => "all",
        _ => if show_demo_flag { "all" } else { "merchant" },
    };
    let filtered_invoices: Vec<crate::invoices::Invoice> = match validated_filter {
        "demo" => all_invoices.into_iter().filter(|i| i.is_demo).collect(),
        "all" => all_invoices,
        _ => all_invoices.into_iter().filter(|i| !i.is_demo).collect(),
    };

    let dashboard_items = build_dashboard_items(&state, filtered_invoices);
    let scanner_health = state.store.get_scanner_health().ok();
    let html = render_merchant_dashboard(
        &dashboard_items,
        &session.csrf_token,
        None,
        state.repo_url.as_deref(),
        Some(validated_filter),
        scanner_health.as_ref(),
    );
    Html(html).into_response()
}

fn build_dashboard_items(
    state: &AppState,
    invoices: Vec<crate::invoices::Invoice>,
) -> Vec<crate::web::templates::DashboardInvoiceItem> {
    let chain_tip = state.store.get_chain_tip().ok().flatten().unwrap_or(0);
    invoices
        .into_iter()
        .map(|inv| {
            let pstate = state
                .store
                .invoice_payment_state(inv.address_index, chain_tip, state.confirmations)
                .ok();
            let payments = state
                .store
                .get_payments_for_invoice(inv.address_index)
                .unwrap_or_default();
            let total_received: u64 = payments.iter().map(|p| p.value_zatoshi).sum();
            let (received, excess, state_name) = match inv.status {
                crate::invoices::InvoiceStatus::Paid => {
                    let name = if inv.is_late { "Paid late" } else { "Paid" };
                    let excess = total_received.saturating_sub(inv.amount_zatoshi);
                    (
                        total_received.max(inv.amount_zatoshi),
                        excess,
                        name.to_string(),
                    )
                }
                crate::invoices::InvoiceStatus::Expired => {
                    let excess = total_received.saturating_sub(inv.amount_zatoshi);
                    (total_received, excess, "Expired".to_string())
                }
                crate::invoices::InvoiceStatus::Pending => match pstate {
                    Some(crate::scanner::InvoicePaymentState::Detected { received, .. }) => {
                        let excess = received.saturating_sub(inv.amount_zatoshi);
                        (received, excess, "Detected".to_string())
                    }
                    Some(crate::scanner::InvoicePaymentState::Underpaid { received, .. }) => {
                        (received, 0, "Underpaid".to_string())
                    }
                    Some(crate::scanner::InvoicePaymentState::Paid {
                        received,
                        excess,
                        late,
                    }) => {
                        let name = if late { "Paid late" } else { "Paid" };
                        (received, excess, name.to_string())
                    }
                    _ => (0, 0, "Awaiting".to_string()),
                },
            };
            crate::web::templates::DashboardInvoiceItem {
                invoice: inv,
                received_zatoshi: received,
                excess_zatoshi: excess,
                payment_state: state_name,
            }
        })
        .collect()
}

/// `POST /merchant/invoices`
pub async fn merchant_create_invoice_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateInvoiceForm>,
) -> Response {
    let session_token = match get_cookie(&headers, SESSION_COOKIE_NAME) {
        Some(t) => t,
        None => return (StatusCode::SEE_OTHER, [(LOCATION, "/merchant/login")]).into_response(),
    };

    let session = match state.session_manager.get_session(session_token) {
        Some(s) => s,
        None => return (StatusCode::SEE_OTHER, [(LOCATION, "/merchant/login")]).into_response(),
    };

    if !constant_time_compare(&session.csrf_token, &form.csrf_token) {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 &mdash; Invalid CSRF token</h1>"),
        )
            .into_response();
    }

    let scanner_health = state.store.get_scanner_health().ok();

    let amount_zatoshi = match parse_zec_amount(&form.amount) {
        Ok(z) => z,
        Err(_) => {
            let invoices = state.store.list_invoices().unwrap_or_default();
            let items = build_dashboard_items(&state, invoices);
            let html = render_merchant_dashboard(
                &items,
                &session.csrf_token,
                Some("Could not create the invoice. Please try again."),
                state.repo_url.as_deref(),
                Some("all"),
                scanner_health.as_ref(),
            );
            return (StatusCode::BAD_REQUEST, Html(html)).into_response();
        }
    };

    let validity_minutes = form.validity_minutes.clamp(1, 1440);
    let validity_seconds = validity_minutes * 60;

    match create_invoice(
        &state.store,
        &state.uivk,
        &state.network,
        amount_zatoshi,
        validity_seconds,
    ) {
        Ok(inv) => {
            let target = format!("/pay/{}", inv.public_id);
            (StatusCode::SEE_OTHER, [(LOCATION, target)]).into_response()
        }
        Err(_) => {
            let invoices = state.store.list_invoices().unwrap_or_default();
            let items = build_dashboard_items(&state, invoices);
            let html = render_merchant_dashboard(
                &items,
                &session.csrf_token,
                Some("Could not create the invoice. Please try again."),
                state.repo_url.as_deref(),
                Some("all"),
                scanner_health.as_ref(),
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
        }
    }
}

/// `POST /merchant/logout`
pub async fn merchant_logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let session_token = match get_cookie(&headers, SESSION_COOKIE_NAME) {
        Some(t) => t,
        None => return (StatusCode::SEE_OTHER, [(LOCATION, "/merchant/login")]).into_response(),
    };

    let session = match state.session_manager.get_session(session_token) {
        Some(s) => s,
        None => return (StatusCode::SEE_OTHER, [(LOCATION, "/merchant/login")]).into_response(),
    };

    if !constant_time_compare(&session.csrf_token, &form.csrf_token) {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 &mdash; Invalid CSRF token</h1>"),
        )
            .into_response();
    }

    state.session_manager.remove_session(session_token);
    let clear_cookie = delete_cookie(SESSION_COOKIE_NAME, state.is_localhost);

    (
        StatusCode::SEE_OTHER,
        [(LOCATION, "/merchant/login"), (SET_COOKIE, clear_cookie.to_str().unwrap())],
    )
        .into_response()
}

// --- Demo Mode ---

/// `GET /demo`
pub async fn demo_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.demo_enabled {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let (csrf_token, set_cookie_opt) = match get_valid_csrf_cookie(&headers) {
        Some(t) => (t.to_string(), None),
        None => {
            let t = SessionManager::generate_token();
            let c = make_cookie(CSRF_COOKIE_NAME, &t, SESSION_MAX_AGE_SECS, state.is_localhost);
            (t, Some(c))
        }
    };

    let has_session = has_valid_session(&headers, &state.session_manager);
    let html = render_demo_page(&csrf_token, None, state.repo_url.as_deref(), has_session);
    let mut resp = Html(html).into_response();
    if let Some(c) = set_cookie_opt {
        resp.headers_mut().insert(SET_COOKIE, c);
    }
    resp
}

/// `POST /demo`
pub async fn demo_post(
    State(state): State<AppState>,
    ClientIdentity(client_id): ClientIdentity,
    headers: HeaderMap,
    Form(form): Form<DemoForm>,
) -> Response {
    if !state.demo_enabled {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let has_session = has_valid_session(&headers, &state.session_manager);

    // Global demo creation limit: 60 per hour across all clients
    if !state
        .rate_limiter
        .check_and_record("global:demo", 60, Duration::from_secs(3600))
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html("<h1>429 &mdash; Too Many Demo Invoices. Try again in 1 hour.</h1>"),
        )
            .into_response();
    }

    // Per-client demo creation limit (5 attempts per minute)
    let client_key = state.rate_limiter.client_key("demo", &client_id);
    if !state
        .rate_limiter
        .check_and_record(&client_key, 5, Duration::from_secs(60))
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html("<h1>429 &mdash; Too Many Demo Invoices. Try again in 1 minute.</h1>"),
        )
            .into_response();
    }

    // Constant-time CSRF check
    let cookie_csrf = get_valid_csrf_cookie(&headers);
    if cookie_csrf.is_none()
        || !is_valid_csrf_token(&form.csrf_token)
        || !constant_time_compare(cookie_csrf.unwrap(), &form.csrf_token)
    {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>403 &mdash; Invalid or missing CSRF token</h1>"),
        )
            .into_response();
    }

    let valid_csrf = cookie_csrf.unwrap();

    // Cap pending demo invoices at 100 (counts ONLY demo invoices)
    let invoices = state.store.list_invoices().unwrap_or_default();
    let pending_demo_count = invoices
        .iter()
        .filter(|i| i.is_demo && i.status == crate::invoices::InvoiceStatus::Pending)
        .count();

    if pending_demo_count >= 100 {
        let html = render_demo_page(
            valid_csrf,
            Some("Maximum pending demo invoices reached (100). Please wait or pay existing invoices."),
            state.repo_url.as_deref(),
            has_session,
        );
        return (StatusCode::TOO_MANY_REQUESTS, Html(html)).into_response();
    }

    // Amount: between 0.001 and 10 ZEC
    let amount_zatoshi = match parse_zec_amount(&form.amount) {
        Ok(z) => z,
        Err(_) => {
            let html = render_demo_page(
                valid_csrf,
                Some("Invalid demo amount. Please enter an amount between 0.001 and 10 ZEC."),
                state.repo_url.as_deref(),
                has_session,
            );
            return (StatusCode::BAD_REQUEST, Html(html)).into_response();
        }
    };

    let min_demo = 100_000; // 0.001 ZEC
    let max_demo = 1_000_000_000; // 10 ZEC
    if amount_zatoshi < min_demo || amount_zatoshi > max_demo {
        let html = render_demo_page(
            valid_csrf,
            Some("Demo amount must be between 0.001 and 10 ZEC."),
            state.repo_url.as_deref(),
            has_session,
        );
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    // Validity: up to 60 minutes
    if form.validity_minutes < 1 || form.validity_minutes > 60 {
        let html = render_demo_page(
            valid_csrf,
            Some("Demo invoice validity must be between 1 and 60 minutes."),
            state.repo_url.as_deref(),
            has_session,
        );
        return (StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    let validity_seconds = form.validity_minutes * 60;
    match create_demo_invoice(
        &state.store,
        &state.uivk,
        &state.network,
        amount_zatoshi,
        validity_seconds,
    ) {
        Ok(inv) => {
            let target = format!("/pay/{}", inv.public_id);
            (StatusCode::SEE_OTHER, [(LOCATION, target)]).into_response()
        }
        Err(_) => {
            let html = render_demo_page(
                valid_csrf,
                Some("Could not create the invoice. Please try again."),
                state.repo_url.as_deref(),
                has_session,
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
        }
    }
}
