//! Unit tests for VeilGate web interface, security headers, privacy model, and edge cases.
//! Runs completely offline (no network).

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::Network;

use crate::invoices::{
    create_demo_invoice, create_invoice, open_store, prune_expired_demo_invoices, Store,
};
use crate::web::amount::{parse_zec_amount, AmountParseError};
use crate::web::auth::{
    constant_time_compare, hash_password, is_valid_csrf_token, SessionManager, CSRF_COOKIE_NAME,
    MAX_LIVE_SESSIONS, SESSION_COOKIE_NAME, SESSION_DURATION, SESSION_MAX_AGE_SECS,
};
use crate::web::handlers::{resolve_client_identity, AppState};
use crate::web::rate_limit::RateLimiter;
use crate::web::templates::esc;
use crate::web::{build_app, templates};

fn test_uivk(network: &Network) -> UnifiedIncomingViewingKey {
    use bip0039::{English, Mnemonic};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    let mnemonic = Mnemonic::<English>::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    )
    .unwrap();
    let seed = mnemonic.to_seed("");
    let usk = UnifiedSpendingKey::from_seed(network, &seed, AccountId::try_from(0).unwrap()).unwrap();
    usk.to_unified_full_viewing_key().to_unified_incoming_viewing_key()
}

fn setup_test_app_custom(
    demo_enabled: bool,
    is_localhost: bool,
    trusted_proxy_header: Option<String>,
) -> (axum::Router, Arc<Store>, Arc<SessionManager>, Arc<RateLimiter>, String, String) {
    let store = Arc::new(open_store(":memory:").expect("open in-memory store"));
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    let password = "correct_horse_battery_staple";
    let password_hash = hash_password(password).expect("hash password");
    let session_manager = Arc::new(SessionManager::new());
    let rate_limiter = Arc::new(RateLimiter::new());

    let state = AppState {
        store: Arc::clone(&store),
        uivk: Arc::new(uivk.clone()),
        network,
        confirmations: 3,
        repo_url: None,
        demo_enabled,
        password_hash: Some(password_hash),
        session_manager: Arc::clone(&session_manager),
        rate_limiter: Arc::clone(&rate_limiter),
        is_localhost,
        trusted_proxy_header,
    };

    // Create a sample invoice in store
    let inv = create_invoice(&store, &uivk, &network, 150_000_000, 3600).expect("create test invoice");
    let public_id = inv.public_id;

    let app = build_app(state);
    (app, store, session_manager, rate_limiter, public_id, password.to_string())
}

fn setup_test_app(demo_enabled: bool) -> (axum::Router, Arc<Store>, String, String) {
    let (app, store, _mgr, _lim, public_id, password) =
        setup_test_app_custom(demo_enabled, true, None);
    (app, store, public_id, password)
}

async fn response_body_string(res: axum::response::Response) -> String {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// --- 1. Status JSON forbidden fields test ---
#[tokio::test]
async fn test_status_json_has_no_forbidden_fields() {
    let (app, _store, public_id, _pw) = setup_test_app(false);

    let req = Request::builder()
        .uri(format!("/api/invoice/{public_id}/status"))
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = response_body_string(res).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");

    assert!(json.is_object());
    let obj = json.as_object().unwrap();

    // MUST ONLY contain: state, amount, received, confirmations_remaining
    let mut keys: Vec<String> = obj.keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "amount".to_string(),
            "confirmations_remaining".to_string(),
            "received".to_string(),
            "state".to_string(),
        ]
    );

    // Explicitly verify forbidden fields are NOT present
    let forbidden = [
        "address", "address_index", "invoice_index", "public_id", "txid", "keys", "seed",
        "uivk", "memo", "created_at", "expires_at", "ip",
    ];
    for f in forbidden {
        assert!(!obj.contains_key(f), "Forbidden field '{}' found in status JSON", f);
    }
}

// --- 2. Merchant routes need login ---
#[tokio::test]
async fn test_merchant_routes_need_login() {
    let (app, _store, _pid, _pw) = setup_test_app(false);

    // GET /merchant without session
    let req = Request::builder()
        .uri("/merchant")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get("location").unwrap(), "/merchant/login");

    // POST /merchant/invoices without session
    let req = Request::builder()
        .method("POST")
        .uri("/merchant/invoices")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("amount=1.0&validity_minutes=30&csrf_token=fake"))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get("location").unwrap(), "/merchant/login");

    // POST /merchant/logout without session
    let req = Request::builder()
        .method("POST")
        .uri("/merchant/logout")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("csrf_token=fake"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get("location").unwrap(), "/merchant/login");
}

// --- 3. Wrong password rejected ---
#[tokio::test]
async fn test_wrong_password_rejected() {
    let (app, _store, _pid, _pw) = setup_test_app(false);

    // First fetch login page to get CSRF token
    let req = Request::builder()
        .uri("/merchant/login")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = res.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let csrf_token = cookie.split(';').next().unwrap().split('=').nth(1).unwrap();

    // Now submit wrong password
    let req = Request::builder()
        .method("POST")
        .uri("/merchant/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
        .body(Body::from(format!("password=definitely_wrong_password&csrf_token={csrf_token}")))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// --- 4. POST without CSRF rejected ---
#[tokio::test]
async fn test_post_without_csrf_rejected() {
    let (app, _store, _pid, _pw) = setup_test_app(true);

    // POST /merchant/login without CSRF
    let req = Request::builder()
        .method("POST")
        .uri("/merchant/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("password=correct_horse_battery_staple&csrf_token=invalid_csrf"))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // POST /demo without CSRF
    let req = Request::builder()
        .method("POST")
        .uri("/demo")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("amount=1.0&validity_minutes=15&csrf_token=missing_or_invalid"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// --- 5. Amount parsing edge cases ---
#[test]
fn test_amount_parsing_edge_cases() {
    assert_eq!(parse_zec_amount(""), Err(AmountParseError::Empty));
    assert_eq!(parse_zec_amount("   "), Err(AmountParseError::Empty));
    assert_eq!(parse_zec_amount("0"), Err(AmountParseError::ZeroAmount));
    assert_eq!(parse_zec_amount("0.0"), Err(AmountParseError::ZeroAmount));
    assert_eq!(parse_zec_amount("-1"), Err(AmountParseError::Negative));
    assert_eq!(parse_zec_amount("+1"), Err(AmountParseError::InvalidCharacter('+')));
    assert_eq!(parse_zec_amount("1.2.3"), Err(AmountParseError::MultipleDecimals));
    assert_eq!(parse_zec_amount("abc"), Err(AmountParseError::InvalidCharacter('a')));
    assert_eq!(parse_zec_amount("1.000000001"), Err(AmountParseError::TooManyDecimals));
    assert_eq!(parse_zec_amount("21000001"), Err(AmountParseError::ExceedsMaxSupply));

    // Valid inputs
    assert_eq!(parse_zec_amount("0.00000001"), Ok(1));
    assert_eq!(parse_zec_amount("0.001"), Ok(100_000));
    assert_eq!(parse_zec_amount("1"), Ok(100_000_000));
    assert_eq!(parse_zec_amount("1.5"), Ok(150_000_000));
    assert_eq!(parse_zec_amount("1.50000000"), Ok(150_000_000));
    assert_eq!(parse_zec_amount(".5"), Ok(50_000_000));
    assert_eq!(parse_zec_amount("21000000"), Ok(2_100_000_000_000_000));
}

// --- 6. Unknown IDs give identical 404 ---
#[tokio::test]
async fn test_unknown_ids_give_identical_404() {
    let (app, _store, _pid, _pw) = setup_test_app(false);

    let id1 = "00000000000000000000000000000001";
    let id2 = "ffffffffffffffffffffffffffffffff";

    // Test /api/invoice/{id}/status
    let req1 = Request::builder()
        .uri(format!("/api/invoice/{id1}/status"))
        .body(Body::empty())
        .unwrap();
    let res1 = app.clone().oneshot(req1).await.unwrap();

    let req2 = Request::builder()
        .uri(format!("/api/invoice/{id2}/status"))
        .body(Body::empty())
        .unwrap();
    let res2 = app.clone().oneshot(req2).await.unwrap();

    assert_eq!(res1.status(), StatusCode::NOT_FOUND);
    assert_eq!(res2.status(), StatusCode::NOT_FOUND);

    let body1 = response_body_string(res1).await;
    let body2 = response_body_string(res2).await;
    assert_eq!(body1, body2);
    assert_eq!(body1, r#"{"error":"not_found"}"#);

    // Test /pay/{id}
    let req3 = Request::builder()
        .uri(format!("/pay/{id1}"))
        .body(Body::empty())
        .unwrap();
    let res3 = app.clone().oneshot(req3).await.unwrap();

    let req4 = Request::builder()
        .uri(format!("/pay/{id2}"))
        .body(Body::empty())
        .unwrap();
    let res4 = app.oneshot(req4).await.unwrap();

    assert_eq!(res3.status(), StatusCode::NOT_FOUND);
    assert_eq!(res4.status(), StatusCode::NOT_FOUND);

    let body3 = response_body_string(res3).await;
    let body4 = response_body_string(res4).await;
    assert_eq!(body3, body4);
}

// --- 7. Security headers on every response ---
#[tokio::test]
async fn test_security_headers_on_every_response() {
    let (app, _store, public_id, _pw) = setup_test_app(false);

    let pay_path = format!("/pay/{public_id}");
    let status_path = format!("/api/invoice/{public_id}/status");
    let paths = vec![
        "/",
        "/privacy",
        pay_path.as_str(),
        status_path.as_str(),
        "/merchant/login",
    ];

    for path in paths {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let headers = res.headers();

        let csp = headers.get("content-security-policy").expect("CSP header");
        let csp_str = csp.to_str().unwrap();
        assert!(csp_str.contains("default-src 'none'"));
        assert!(csp_str.contains("style-src 'self'"));
        assert!(csp_str.contains("img-src 'self'"));
        assert!(csp_str.contains("script-src 'self'"));
        assert!(csp_str.contains("connect-src 'self'"));
        assert!(csp_str.contains("form-action 'self'"));
        assert!(csp_str.contains("base-uri 'none'"));
        assert!(csp_str.contains("frame-ancestors 'none'"));

        assert_eq!(
            headers.get("referrer-policy").unwrap(),
            "no-referrer"
        );
        assert_eq!(
            headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );

        if path.starts_with("/pay") || path.starts_with("/api/invoice") || path.starts_with("/merchant") {
            assert_eq!(headers.get("x-robots-tag").unwrap(), "noindex");
            assert_eq!(headers.get("cache-control").unwrap(), "no-store");
        }
    }
}

// --- 8. Rendered pages contain no off-site URLs, no emojis, no banned words ---
fn has_emoji(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        // Check common emoji and pictorial symbol unicode blocks
        (0x1F300..=0x1F9FF).contains(&u)
            || (0x2600..=0x26FF).contains(&u)
            || (0x2700..=0x27BF).contains(&u)
            || (0x1F600..=0x1F64F).contains(&u)
            || (0x1F680..=0x1F6FF).contains(&u)
    })
}

#[tokio::test]
async fn test_rendered_pages_integrity_and_banned_words() {
    let landing = templates::render_landing_page(None, false);
    let privacy = templates::render_privacy_page(None, false);
    let demo = templates::render_demo_page("test_csrf", None, None, false, None);
    let login = templates::render_login_page("test_csrf", None, None);

    let pages = vec![
        ("landing", &landing),
        ("privacy", &privacy),
        ("demo", &demo),
        ("login", &login),
    ];

    for (name, html) in &pages {
        // No emojis
        assert!(!has_emoji(html), "Page '{}' contains emoji characters", name);

        // No off-site URLs in href, src, etc. (faucet links on demo are permitted)
        let filtered_html = html
            .replace(r#"href="https://faucet.testnet.valargroup.dev""#, "")
            .replace(r#"href="https://fauzec.com""#, "");
        assert!(
            !filtered_html.contains("href=\"http://") && !filtered_html.contains("href=\"https://"),
            "Page '{}' contains off-site href link",
            name
        );
        assert!(
            !html.contains("src=\"http://") && !html.contains("src=\"https://"),
            "Page '{}' contains off-site src link",
            name
        );

        // No inline scripts or style attributes
        for script_chunk in html.split("<script").skip(1) {
            assert!(
                script_chunk.starts_with(" src=\"/static/app.js?v=") && script_chunk.contains("\" defer></script>"),
                "Page '{}' contains non-standard script tag",
                name
            );
        }
        assert!(
            !html.contains("style="),
            "Page '{}' contains forbidden inline style attribute",
            name
        );
    }

    // Banned landing page words
    let banned_words = ["Solana", "USDC", "Pricing", "30,000", "uptime"];
    for word in banned_words {
        assert!(
            !landing.contains(word),
            "Landing page contains banned word '{}'",
            word
        );
    }
}

// --- 9. Demo mode is off by default and capped when on ---
#[tokio::test]
async fn test_demo_mode_off_by_default_and_capped() {
    // 9a: Off by default
    let (app_off, _store, _pid, _pw) = setup_test_app(false);

    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app_off.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    let req_post = Request::builder()
        .method("POST")
        .uri("/demo")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("amount=1.0&validity_minutes=15&csrf_token=abc"))
        .unwrap();
    let res_post = app_off.oneshot(req_post).await.unwrap();
    assert_eq!(res_post.status(), StatusCode::NOT_FOUND);

    // 9b: On and capped at 100 pending invoices
    let (app_on, store, _pid, _pw) = setup_test_app(true);

    // GET /demo should work when enabled
    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app_on.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = res.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let csrf_token = cookie.split(';').next().unwrap().split('=').nth(1).unwrap();

    // Fill store to 100 pending invoices
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    // Fill store with 100 pending demo invoices
    for _ in 0..100 {
        crate::invoices::create_demo_invoice(&store, &uivk, &network, 100_000, 3600).unwrap();
    }

    // Now try creating 101st demo invoice
    let req_post = Request::builder()
        .method("POST")
        .uri("/demo")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
        .body(Body::from(format!("amount=0.5&validity_minutes=15&csrf_token={csrf_token}")))
        .unwrap();
    let res_post = app_on.oneshot(req_post).await.unwrap();
    assert_eq!(res_post.status(), StatusCode::TOO_MANY_REQUESTS);
}

// =========================================================================
// Fix 1: Client identity
// =========================================================================

#[test]
fn test_fix1_client_identity_resolution() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "203.0.113.195, 70.41.3.18, 150.172.238.178".parse().unwrap(),
    );
    headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());
    headers.insert("fly-client-ip", "137.117.23.44".parse().unwrap());

    let peer: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let conn_info = ConnectInfo(peer);

    // Default: ignores headers, uses TCP peer
    let id_default = resolve_client_identity(&headers, Some(&conn_info), None);
    assert_eq!(id_default, "192.168.1.100");

    // Fallback when no ConnectInfo
    let id_fallback = resolve_client_identity(&headers, None, None);
    assert_eq!(id_fallback, "127.0.0.1");

    // Trusted X-Forwarded-For: extracts LAST entry (appended by proxy)
    let id_xff = resolve_client_identity(&headers, Some(&conn_info), Some("x-forwarded-for"));
    assert_eq!(id_xff, "150.172.238.178");

    // Single entry X-Forwarded-For
    let mut headers_single = HeaderMap::new();
    headers_single.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
    let id_single = resolve_client_identity(&headers_single, Some(&conn_info), Some("x-forwarded-for"));
    assert_eq!(id_single, "198.51.100.1");

    // Trusted fly-client-ip
    let id_fly = resolve_client_identity(&headers, Some(&conn_info), Some("fly-client-ip"));
    assert_eq!(id_fly, "137.117.23.44");
}

#[tokio::test]
async fn test_fix1_proxy_header_rate_limit_bucket() {
    // 1. Without trusted proxy header: spoofing does NOT change rate-limit bucket
    let (app_no_proxy, _store, _mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, None);

    // Get CSRF cookie first
    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app_no_proxy.clone().oneshot(req).await.unwrap();
    let cookie = res.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let csrf_token = cookie.split(';').next().unwrap().split('=').nth(1).unwrap().to_string();

    // Submit 5 POSTs with different spoofed X-Forwarded-For headers
    for i in 0..5 {
        let req = Request::builder()
            .method("POST")
            .uri("/demo")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-forwarded-for", format!("198.51.100.{}", i))
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
            .body(Body::from(format!("amount=0.1&validity_minutes=15&csrf_token={csrf_token}")))
            .unwrap();
        let res = app_no_proxy.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }

    // 6th POST with yet another spoofed header is throttled because bucket is still 127.0.0.1
    let req_spoofed = Request::builder()
        .method("POST")
        .uri("/demo")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-forwarded-for", "198.51.100.99")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
        .body(Body::from(format!("amount=0.1&validity_minutes=15&csrf_token={csrf_token}")))
        .unwrap();
    let res_throttled = app_no_proxy.oneshot(req_spoofed).await.unwrap();
    assert_eq!(res_throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // 2. With trusted proxy header: LAST entry sets the bucket
    let (app_with_proxy, _store, _mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, Some("x-forwarded-for".to_string()));

    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app_with_proxy.clone().oneshot(req).await.unwrap();
    let cookie = res.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let csrf_token2 = cookie.split(';').next().unwrap().split('=').nth(1).unwrap().to_string();

    // 5 attempts from proxy with last entry 10.0.0.1
    for i in 0..5 {
        let req = Request::builder()
            .method("POST")
            .uri("/demo")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-forwarded-for", format!("spoofed_{}, 10.0.0.1", i))
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token2))
            .body(Body::from(format!("amount=0.1&validity_minutes=15&csrf_token={csrf_token2}")))
            .unwrap();
        let res = app_with_proxy.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }

    // 6th attempt with same LAST entry is throttled
    let req_throttled = Request::builder()
        .method("POST")
        .uri("/demo")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-forwarded-for", "spoofed_other, 10.0.0.1")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token2))
        .body(Body::from(format!("amount=0.1&validity_minutes=15&csrf_token={csrf_token2}")))
        .unwrap();
    let res_throttled = app_with_proxy.clone().oneshot(req_throttled).await.unwrap();
    assert_eq!(res_throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // But attempt with different LAST entry 10.0.0.2 is allowed
    let req_other = Request::builder()
        .method("POST")
        .uri("/demo")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-forwarded-for", "spoofed_other, 10.0.0.2")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token2))
        .body(Body::from(format!("amount=0.1&validity_minutes=15&csrf_token={csrf_token2}")))
        .unwrap();
    let res = app_with_proxy.oneshot(req_other).await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

// =========================================================================
// Fix 2: Rate limiter hygiene
// =========================================================================

#[test]
fn test_fix2_rate_limiter_hygiene() {
    // 1. Salted hashes: raw IP never appears in keys
    let limiter = RateLimiter::new_with_capacity(5);
    let raw_ip = "192.168.1.123";
    let key = limiter.client_key("login", raw_ip);
    assert!(!key.contains(raw_ip));
    assert!(key.starts_with("login:"));
    assert_eq!(key.len(), "login:".len() + 64); // SHA-256 hex is 64 chars

    // 2. Capacity cap: stays bounded under churn and drops oldest
    for i in 0..15 {
        let k = limiter.client_key("login", &format!("10.0.0.{}", i));
        limiter.check_and_record(&k, 5, Duration::from_secs(60));
    }
    assert!(limiter.key_count() <= 5);
    assert!(!limiter.contains_raw_string_in_any_key("10.0.0."));

    // 3. Expired keys are purged
    let short_limiter = RateLimiter::new();
    let k1 = short_limiter.client_key("test", "client1");
    short_limiter.check_and_record(&k1, 5, Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(5));
    short_limiter.purge_expired();
    assert_eq!(short_limiter.key_count(), 0);
}

#[tokio::test]
async fn test_fix2_global_login_limiter() {
    let (app, _store, _mgr, _lim, _pid, password) =
        setup_test_app_custom(false, true, Some("x-forwarded-for".to_string()));

    // Get CSRF token
    let req = Request::builder().uri("/merchant/login").body(Body::empty()).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let cookie = res.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let csrf_token = cookie.split(';').next().unwrap().split('=').nth(1).unwrap().to_string();

    // 10 failed login attempts from 10 different IP addresses
    for i in 0..10 {
        let req = Request::builder()
            .method("POST")
            .uri("/merchant/login")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-forwarded-for", format!("10.1.1.{}", i))
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
            .body(Body::from(format!("password=wrong&csrf_token={csrf_token}")))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // 11th attempt from an 11th distinct IP is blocked by the global login limiter (10/min)
    let req_11 = Request::builder()
        .method("POST")
        .uri("/merchant/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-forwarded-for", "10.1.1.99")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
        .body(Body::from(format!("password={password}&csrf_token={csrf_token}")))
        .unwrap();
    let res_11 = app.oneshot(req_11).await.unwrap();
    assert_eq!(res_11.status(), StatusCode::TOO_MANY_REQUESTS);
}

// =========================================================================
// Fix 3: Templates leak
// =========================================================================

#[test]
fn test_fix3_templates_render_pay_page_no_leak() {
    let store = open_store(":memory:").expect("open store");
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);
    let inv = create_invoice(&store, &uivk, &network, 250_000_000, 3600).unwrap();

    // Render Detected state repeatedly without any memory leak
    for i in 1..=100 {
        let label = format!("Payment detected ({} confirmations remaining)", i % 3 + 1);
        let html = templates::render_pay_page(
            &inv,
            "<svg></svg>",
            Cow::Owned(label.clone()),
            "status-detected",
            "Awaiting confirmation",
            100_000_000,
            "zcash:test",
            None,
            false,
            false,
        );
        assert!(html.contains(&label));
    }

    // Render Underpaid state repeatedly without any memory leak
    for i in 1..=100 {
        let label = format!("Underpaid (missing 0.{} ZEC)", i);
        let html = templates::render_pay_page(
            &inv,
            "<svg></svg>",
            Cow::Owned(label.clone()),
            "status-underpaid",
            "Partial payment received",
            50_000_000,
            "zcash:test",
            None,
            false,
            false,
        );
        assert!(html.contains(&label));
    }
}

// =========================================================================
// Fix 4: Generic error messages
// =========================================================================

#[tokio::test]
async fn test_fix4_generic_error_messages() {
    let (app, _store, session_mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, None);

    let session = session_mgr.create_session();

    // Submit invalid invoice creation data (invalid amount)
    let req = Request::builder()
        .method("POST")
        .uri("/merchant/invoices")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::from(format!("amount=not_a_number&validity_minutes=30&csrf_token={}", session.csrf_token)))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let body = response_body_string(res).await;
    // Friendly error message present
    assert!(body.contains("Could not create the invoice. Please try again."));

    // Internal leak checks
    assert!(!body.contains("VEILGATE_"));
    assert!(!body.contains("DATABASE_URL"));
    assert!(!body.contains(".rs:"));
    assert!(!body.contains("sqlite3_"));
    assert!(!body.contains("backend/src"));
}

// =========================================================================
// Fix 5: Constant-time & session hygiene
// =========================================================================

#[test]
fn test_fix5_constant_time_compare() {
    assert!(constant_time_compare("abc123xyz", "abc123xyz"));
    assert!(!constant_time_compare("abc123xyz", "abc123xyw"));
    assert!(!constant_time_compare("abc123xyz", "abc123xy"));
    assert!(!constant_time_compare("short", "longer_secret"));
    assert!(constant_time_compare("", ""));
}

#[test]
fn test_fix5_session_expiry_and_cap() {
    assert_eq!(SESSION_MAX_AGE_SECS, 14400);
    assert_eq!(SESSION_DURATION, Duration::from_secs(14400));
    assert_eq!(MAX_LIVE_SESSIONS, 20);

    let mgr = SessionManager::new();

    // Create 25 sessions
    let mut tokens = Vec::new();
    for _ in 0..25 {
        let s = mgr.create_session();
        tokens.push(s.token);
    }

    // Live session cap is 20: oldest 5 should be evicted
    assert_eq!(mgr.session_count(), 20);
    for token in &tokens[..5] {
        assert!(mgr.get_session(token).is_none(), "Oldest session should have been evicted");
    }
    for token in &tokens[5..] {
        assert!(mgr.get_session(token).is_some(), "Recent session should be valid");
    }
}

// =========================================================================
// Fix 6: Demo isolation
// =========================================================================

#[tokio::test]
async fn test_fix6_demo_isolation_and_accounting() {
    let (app, store, session_mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, None);

    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    // Create 1 demo invoice (2 ZEC = 200_000_000 zatoshi)
    let demo_inv = create_demo_invoice(&store, &uivk, &network, 200_000_000, 3600).unwrap();
    assert!(demo_inv.is_demo);

    let session = session_mgr.create_session();

    // 1. Default dashboard view (/merchant) counts ONLY merchant invoices
    let req_default = Request::builder()
        .uri("/merchant")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_default).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_body_string(res).await;

    // Total Invoices should be 1 (the initial test invoice from setup), not 2
    assert!(body.contains(r#"<div class="total-value">1</div>"#));
    // Demo row not shown in default merchant view
    assert!(!body.contains(&demo_inv.public_id[..8]));

    // 2. Filter = all shows BOTH invoices (Total Invoices: 2)
    let req_all = Request::builder()
        .uri("/merchant?filter=all")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req_all).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_all = response_body_string(res).await;
    assert!(body_all.contains(r#"<div class="total-value">2</div>"#));
    assert!(body_all.contains(&demo_inv.public_id[..8]));

    // 3. Filter = demo shows ONLY demo invoice
    let req_demo = Request::builder()
        .uri("/merchant?filter=demo")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req_demo).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_demo = response_body_string(res).await;
    assert!(body_demo.contains(r#"<div class="total-value">1</div>"#));
    assert!(body_demo.contains(&demo_inv.public_id[..8]));
}

#[test]
fn test_fix6_prune_expired_demo_invoices() {
    let store = open_store(":memory:").expect("open store");
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    // Create 1 merchant invoice and 1 demo invoice, both expiring immediately
    let merchant_inv = create_invoice(&store, &uivk, &network, 100_000, 0).unwrap();
    let demo_inv = create_demo_invoice(&store, &uivk, &network, 100_000, 0).unwrap();

    // Prune expired demo invoices older than 0 seconds
    let pruned = prune_expired_demo_invoices(&store, 0).unwrap();
    assert_eq!(pruned, 1);

    // Demo invoice is gone
    assert!(store.get_by_public_id(&demo_inv.public_id).unwrap().is_none());
    // Merchant invoice is strictly preserved
    assert!(store.get_by_public_id(&merchant_inv.public_id).unwrap().is_some());

    // Monotonic next index in invoice_meta is strictly preserved: next invoice receives demo_inv.address_index + 1
    let next_inv = create_invoice(&store, &uivk, &network, 100_000, 3600).unwrap();
    assert_eq!(next_inv.address_index, demo_inv.address_index + 1);
}

#[tokio::test]
async fn test_fix6_global_demo_limit() {
    let (app, _store, _mgr, rate_limiter, _pid, _pw) =
        setup_test_app_custom(true, true, Some("x-forwarded-for".to_string()));

    // Verify rate_limiter global:demo checks 60/hr
    for _ in 0..60 {
        assert!(rate_limiter.check_and_record("global:demo", 60, Duration::from_secs(3600)));
    }
    // 61st call fails
    assert!(!rate_limiter.check_and_record("global:demo", 60, Duration::from_secs(3600)));

    // App returns 429 when global:demo is exhausted
    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let cookie = res.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let csrf_token = cookie.split(';').next().unwrap().split('=').nth(1).unwrap().to_string();

    let req_post = Request::builder()
        .method("POST")
        .uri("/demo")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
        .body(Body::from(format!("amount=0.5&validity_minutes=15&csrf_token={csrf_token}")))
        .unwrap();
    let res_post = app.oneshot(req_post).await.unwrap();
    assert_eq!(res_post.status(), StatusCode::TOO_MANY_REQUESTS);
}

// =========================================================================
// Fix 7: Security headers and tower layers
// =========================================================================

#[tokio::test]
async fn test_fix7_security_headers_and_hsts_behavior() {
    // 1. Localhost app: HSTS omitted
    let (app_local, _store, _pid, _pw) = setup_test_app(false);
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res = app_local.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    assert_eq!(
        res.headers().get("permissions-policy").unwrap(),
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    );
    assert_eq!(
        res.headers().get("cross-origin-opener-policy").unwrap(),
        "same-origin"
    );
    assert_eq!(
        res.headers().get("cross-origin-resource-policy").unwrap(),
        "same-origin"
    );
    assert!(res.headers().get("strict-transport-security").is_none());

    // 2. Non-localhost app: HSTS present
    let (app_prod, _store, _mgr, _lim, _pid, _pw) =
        setup_test_app_custom(false, false, None);
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res = app_prod.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000"
    );
}

#[tokio::test]
async fn test_fix7_body_limit_8kb() {
    let (app, _store, _pid, _pw) = setup_test_app(false);

    // Request body exceeding 8 KB (9000 bytes)
    let large_body = "x".repeat(9000);
    let req = Request::builder()
        .method("POST")
        .uri("/merchant/login")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(large_body))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// =========================================================================
// Fix 8: Small Polish
// =========================================================================

#[tokio::test]
async fn test_fix8_polish_header_button_and_totals() {
    let (app, store, session_mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, None);

    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);
    let _demo_inv = create_demo_invoice(&store, &uivk, &network, 100_000, 3600).unwrap();

    // 1. Without session cookie: header button says "Open dashboard"
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let body = response_body_string(res).await;
    assert!(body.contains("Open dashboard"));
    assert!(!body.contains(r#">Dashboard</a>"#));

    // 2. With valid session cookie: header button says "Dashboard"
    let session = session_mgr.create_session();
    let req_auth = Request::builder()
        .uri("/")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();
    let res_auth = app.clone().oneshot(req_auth).await.unwrap();
    let body_auth = response_body_string(res_auth).await;
    assert!(body_auth.contains(r#">Dashboard</a>"#));
    assert!(!body_auth.contains("Open dashboard"));

    // 3. Merchant dashboard displays "Total invoiced", not "Total volume"
    let req_dash = Request::builder()
        .uri("/merchant?filter=all")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();
    let res_dash = app.oneshot(req_dash).await.unwrap();
    let body_dash = response_body_string(res_dash).await;
    assert!(body_dash.contains("Total invoiced"));
    assert!(!body_dash.contains("Total volume"));

    // 4. Demo badge rendered for demo invoices
    assert!(body_dash.contains(r#"<span class="status-pill status-demo">Demo</span>"#));
}

// =========================================================================
// Fixes 9-14: Security, Escaping, CSRF, Error Messages & Injection Tests
// =========================================================================

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn assert_no_on_event_attributes(html: &str, route: &str) {
    let lower = html.to_ascii_lowercase();
    assert!(!lower.contains("style=\""), "Page {route} contains style=\"");
    assert!(!lower.contains("onclick="), "Page {route} contains onclick=");

    // Scan for any on* attribute (e.g. " onclick=", " onload=", " onerror=")
    for prefix in [" on", "\ton", "\non", "<svg on", "<img on", "<body on"] {
        for (idx, _) in lower.match_indices(prefix) {
            let rest = &lower[idx + prefix.len()..];
            if let Some(eq_idx) = rest.find('=') {
                let attr = &rest[..eq_idx];
                if !attr.is_empty() && attr.len() < 30 && attr.chars().all(|c| c.is_ascii_alphabetic()) {
                    panic!("Page {route} contains prohibited on* attribute: on{attr}=");
                }
            }
        }
    }
}

#[tokio::test]
async fn test_fix9_html_escaping() {
    // 1. esc function unit tests
    assert_eq!(esc(""), "");
    assert_eq!(esc("hello world"), "hello world");
    assert_eq!(esc("&"), "&amp;");
    assert_eq!(esc("<"), "&lt;");
    assert_eq!(esc(">"), "&gt;");
    assert_eq!(esc("\""), "&quot;");
    assert_eq!(esc("'"), "&#x27;");
    assert_eq!(
        esc("<script>alert('xss & \"more\"')</script>"),
        "&lt;script&gt;alert(&#x27;xss &amp; &quot;more&quot;&#x27;)&lt;/script&gt;"
    );

    // 2. Templates escape dynamic strings
    // Error messages in demo page
    let demo_html = templates::render_demo_page(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        Some("<bad'err\"&>"),
        None,
        false,
        None,
    );
    assert!(!demo_html.contains("<bad'err\"&>"));
    assert!(demo_html.contains("&lt;bad&#x27;err&quot;&amp;&gt;"));

    // Error messages in login page
    let login_html = templates::render_login_page(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        Some("<bad'err\"&>"),
        None,
    );
    assert!(!login_html.contains("<bad'err\"&>"));
    assert!(login_html.contains("&lt;bad&#x27;err&quot;&amp;&gt;"));

    // Dashboard dynamic values (errors, filter)
    let dash_html = templates::render_merchant_dashboard(
        &[],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        Some("<bad'err\"&>"),
        None,
        Some("all"),
        None,
    );
    assert!(!dash_html.contains("<bad'err\"&>"));
    assert!(dash_html.contains("&lt;bad&#x27;err&quot;&amp;&gt;"));
}

#[tokio::test]
async fn test_fix10_csrf_cookie_validation() {
    // 1. Token format validation: exactly 64 lowercase hex characters
    assert!(is_valid_csrf_token("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    // 63 characters
    assert!(!is_valid_csrf_token("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"));
    // 65 characters
    assert!(!is_valid_csrf_token("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"));
    // Uppercase hex
    assert!(!is_valid_csrf_token("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"));
    // Non-hex
    assert!(!is_valid_csrf_token("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"));
    assert!(!is_valid_csrf_token("><script>alert(1)</script>"));
    assert!(!is_valid_csrf_token(""));

    // 2. Server ignores invalid CSRF cookie and issues a new one
    let (app, _store, _pid, _pw) = setup_test_app(true);

    // Invalid cookie on GET /demo
    let invalid_cookie_val = "bad_cookie_value_12345";
    let req = Request::builder()
        .uri("/demo")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, invalid_cookie_val))
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Must issue a new cookie via Set-Cookie
    let set_cookie = res.headers().get(SET_COOKIE).expect("Set-Cookie header must be present").to_str().unwrap();
    assert!(set_cookie.contains(CSRF_COOKIE_NAME));

    let html = response_body_string(res).await;
    // Must never contain unvalidated cookie value
    assert!(!html.contains(invalid_cookie_val));

    // Extract the token placed in the page
    let marker = r#"<input type="hidden" name="csrf_token" value=""#;
    let idx = html.find(marker).expect("csrf hidden input in html");
    let token_in_page = &html[idx + marker.len()..idx + marker.len() + 64];
    assert!(is_valid_csrf_token(token_in_page));
    assert_ne!(token_in_page, invalid_cookie_val);

    // Invalid cookie on GET /merchant/login
    let xss_cookie = "><script>alert(1)</script>";
    let req2 = Request::builder()
        .uri("/merchant/login")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, xss_cookie))
        .body(Body::empty())
        .unwrap();

    let res2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK);
    let set_cookie2 = res2.headers().get(SET_COOKIE).expect("Set-Cookie present").to_str().unwrap().to_string();
    let html2 = response_body_string(res2).await;
    assert!(!html2.contains(xss_cookie));
    assert!(!html2.contains("alert(1)"));
    assert!(set_cookie2.contains(CSRF_COOKIE_NAME));
}

#[tokio::test]
async fn test_fix11_fixed_generic_error_messages() {
    // 1. AmountParseError::user_message() never reflects user input
    let err_char = AmountParseError::InvalidCharacter('x');
    // Display contains 'x'
    assert!(format!("{}", err_char).contains("'x'"));
    // user_message does NOT contain 'x'
    assert!(!err_char.user_message().contains('x'));
    assert_eq!(
        err_char.user_message(),
        "Amount contains an invalid character. Please enter a valid number."
    );

    // 2. POST /demo with invalid amount inputs produces fixed generic messages without reflecting input
    let (app, _store, session_mgr, _lim, _pid, _password) =
        setup_test_app_custom(true, true, None);

    // Get a valid CSRF token
    let req_demo = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res_demo = app.clone().oneshot(req_demo).await.unwrap();
    let set_cookie = res_demo.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
    let csrf_val = set_cookie.split(';').next().unwrap().split('=').nth(1).unwrap().to_string();

    let invalid_amount_input = "12.34xyz56";
    let body = format!("csrf_token={}&amount={}&validity_minutes=15", csrf_val, invalid_amount_input);
    let req_post = Request::builder()
        .method("POST")
        .uri("/demo")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_val))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let res_post = app.clone().oneshot(req_post).await.unwrap();
    assert_eq!(res_post.status(), StatusCode::BAD_REQUEST);
    let html_post = response_body_string(res_post).await;
    // Must NOT contain the user's invalid input
    assert!(!html_post.contains(invalid_amount_input));
    assert!(!html_post.contains("xyz"));
    // Must contain fixed generic error text
    assert!(html_post.contains("Invalid demo amount. Please enter an amount between 0.001 and 10 ZEC."));

    // 3. POST /merchant/invoices with invalid amount also returns fixed generic text
    let session = session_mgr.create_session();
    let invalid_merchant_amount = "99.bad99";
    let body_m = format!("csrf_token={}&amount={}&validity_minutes=30", session.csrf_token, invalid_merchant_amount);
    let req_m = Request::builder()
        .method("POST")
        .uri("/merchant/invoices")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body_m))
        .unwrap();

    let res_m = app.clone().oneshot(req_m).await.unwrap();
    assert_eq!(res_m.status(), StatusCode::BAD_REQUEST);
    let html_m = response_body_string(res_m).await;
    assert!(!html_m.contains(invalid_merchant_amount));
    assert!(!html_m.contains("bad"));
    assert!(html_m.contains("Could not create the invoice. Please try again."));
}

#[tokio::test]
async fn test_fix12_no_inline_style_attributes() {
    let (app, _store, session_mgr, _lim, public_id, _pw) =
        setup_test_app_custom(true, true, None);

    let session = session_mgr.create_session();

    // 1. Merchant dashboard has class mb-4 and no inline style
    let req_dash = Request::builder()
        .uri("/merchant")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();
    let res_dash = app.clone().oneshot(req_dash).await.unwrap();
    let body_dash = response_body_string(res_dash).await;
    assert!(body_dash.contains(r#"class="checkout-card mb-4""#));
    assert!(!body_dash.contains("style="));

    // 2. Verify static style.css contains .mb-4 class definition
    let req_css = Request::builder().uri("/static/style.css").body(Body::empty()).unwrap();
    let res_css = app.clone().oneshot(req_css).await.unwrap();
    assert_eq!(res_css.status(), StatusCode::OK);
    let css_body = response_body_string(res_css).await;
    assert!(css_body.contains(".mb-4"));
    assert!(css_body.contains("margin-bottom: 1.5rem;"));

    // 3. None of the templates contains any style="..." attribute
    let pages = vec![
        "/".to_string(),
        "/privacy".to_string(),
        "/demo".to_string(),
        format!("/pay/{public_id}"),
        "/merchant/login".to_string(),
    ];

    for path in pages {
        let req = Request::builder().uri(&path).body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let body = response_body_string(res).await;
        assert!(
            !body.contains("style=\""),
            "Page {} contained style=\" attribute",
            path
        );
    }
}

#[tokio::test]
async fn test_fix13_injection_payloads_never_raw_in_html() {
    let payloads = ["><script>alert(1)</script>", "'\"&<>"];

    for payload in payloads {
        let (app, _store, session_mgr, _lim, _public_id, _pw) =
            setup_test_app_custom(true, true, None);
        let session = session_mgr.create_session();

        // Obtain a valid CSRF token from /demo
        let req_csrf = Request::builder().uri("/demo").body(Body::empty()).unwrap();
        let res_csrf = app.clone().oneshot(req_csrf).await.unwrap();
        let set_cookie_str = res_csrf.headers().get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
        let valid_csrf = set_cookie_str.split(';').next().unwrap().split('=').nth(1).unwrap().to_string();

        // Vector 1: Login password
        let req_pwd = Request::builder()
            .method("POST")
            .uri("/merchant/login")
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, valid_csrf))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={}&password={}", valid_csrf, percent_encode(payload))))
            .unwrap();
        let res_pwd = app.clone().oneshot(req_pwd).await.unwrap();
        let body_pwd = response_body_string(res_pwd).await;
        assert!(!body_pwd.contains(payload), "Raw payload reflected in login password response");

        // Vector 2: Login csrf field
        let req_csrf_field = Request::builder()
            .method("POST")
            .uri("/merchant/login")
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, valid_csrf))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={}&password=somepass", percent_encode(payload))))
            .unwrap();
        let res_csrf_field = app.clone().oneshot(req_csrf_field).await.unwrap();
        let body_csrf_field = response_body_string(res_csrf_field).await;
        assert!(!body_csrf_field.contains(payload), "Raw payload reflected in login csrf field response");

        // Vector 3: The CSRF cookie (in GET /demo, GET /merchant/login, POST /demo, POST /merchant/login)
        let req_c1 = Request::builder()
            .uri("/demo")
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, payload))
            .body(Body::empty())
            .unwrap();
        let res_c1 = app.clone().oneshot(req_c1).await.unwrap();
        let body_c1 = response_body_string(res_c1).await;
        assert!(!body_c1.contains(payload), "Raw payload reflected from CSRF cookie in /demo");

        let req_c2 = Request::builder()
            .uri("/merchant/login")
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, payload))
            .body(Body::empty())
            .unwrap();
        let res_c2 = app.clone().oneshot(req_c2).await.unwrap();
        let body_c2 = response_body_string(res_c2).await;
        assert!(!body_c2.contains(payload), "Raw payload reflected from CSRF cookie in /merchant/login");

        let req_c3 = Request::builder()
            .method("POST")
            .uri("/demo")
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, payload))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={}&amount=1.0&validity_minutes=15", valid_csrf)))
            .unwrap();
        let res_c3 = app.clone().oneshot(req_c3).await.unwrap();
        let body_c3 = response_body_string(res_c3).await;
        assert!(!body_c3.contains(payload), "Raw payload reflected from CSRF cookie in POST /demo");

        // Vector 4: Demo amount field
        let req_d_amt = Request::builder()
            .method("POST")
            .uri("/demo")
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, valid_csrf))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={}&amount={}&validity_minutes=15", valid_csrf, percent_encode(payload))))
            .unwrap();
        let res_d_amt = app.clone().oneshot(req_d_amt).await.unwrap();
        let body_d_amt = response_body_string(res_d_amt).await;
        assert!(!body_d_amt.contains(payload), "Raw payload reflected in demo amount response");

        // Vector 5: Merchant amount field
        let req_m_amt = Request::builder()
            .method("POST")
            .uri("/merchant/invoices")
            .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={}&amount={}&validity_minutes=30", session.csrf_token, percent_encode(payload))))
            .unwrap();
        let res_m_amt = app.clone().oneshot(req_m_amt).await.unwrap();
        let body_m_amt = response_body_string(res_m_amt).await;
        assert!(!body_m_amt.contains(payload), "Raw payload reflected in merchant amount response");

        // Vector 6: Validity field (demo and merchant)
        let req_d_val = Request::builder()
            .method("POST")
            .uri("/demo")
            .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, valid_csrf))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={}&amount=1.0&validity_minutes={}", valid_csrf, percent_encode(payload))))
            .unwrap();
        let res_d_val = app.clone().oneshot(req_d_val).await.unwrap();
        let body_d_val = response_body_string(res_d_val).await;
        assert!(!body_d_val.contains(payload), "Raw payload reflected in demo validity response");

        let req_m_val = Request::builder()
            .method("POST")
            .uri("/merchant/invoices")
            .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={}&amount=1.0&validity_minutes={}", session.csrf_token, percent_encode(payload))))
            .unwrap();
        let res_m_val = app.clone().oneshot(req_m_val).await.unwrap();
        let body_m_val = response_body_string(res_m_val).await;
        assert!(!body_m_val.contains(payload), "Raw payload reflected in merchant validity response");

        // Vector 7: Unknown ids in /pay
        let req_pay_id = Request::builder()
            .uri(format!("/pay/{}", percent_encode(payload)))
            .body(Body::empty())
            .unwrap();
        let res_pay_id = app.clone().oneshot(req_pay_id).await.unwrap();
        let body_pay_id = response_body_string(res_pay_id).await;
        assert!(!body_pay_id.contains(payload), "Raw payload reflected in unknown /pay/<id>");

        // Vector 8: Unknown ids in status route
        let req_status_id = Request::builder()
            .uri(format!("/api/invoice/{}/status", percent_encode(payload)))
            .body(Body::empty())
            .unwrap();
        let res_status_id = app.clone().oneshot(req_status_id).await.unwrap();
        let body_status_id = response_body_string(res_status_id).await;
        assert!(!body_status_id.contains(payload), "Raw payload reflected in unknown status route");

        // Vector 9: All query strings
        let query_routes = [
            format!("/?q={}", percent_encode(payload)),
            format!("/privacy?q={}", percent_encode(payload)),
            format!("/demo?amount={}&q={}", percent_encode(payload), percent_encode(payload)),
            format!("/merchant/login?q={}", percent_encode(payload)),
        ];

        for route in query_routes {
            let req_q = Request::builder().uri(&route).body(Body::empty()).unwrap();
            let res_q = app.clone().oneshot(req_q).await.unwrap();
            let body_q = response_body_string(res_q).await;
            assert!(!body_q.contains(payload), "Raw payload reflected in query string on {}", route);
        }

        // Query string on merchant dashboard
        let req_dash_q = Request::builder()
            .uri(format!("/merchant?filter={}&show_demo={}", percent_encode(payload), percent_encode(payload)))
            .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
            .body(Body::empty())
            .unwrap();
        let res_dash_q = app.clone().oneshot(req_dash_q).await.unwrap();
        let body_dash_q = response_body_string(res_dash_q).await;
        assert!(!body_dash_q.contains(payload), "Raw payload reflected in merchant query string");
    }
}

#[tokio::test]
async fn test_fix14_csp_clean_attributes() {
    let (app, _store, public_id, _pw) = setup_test_app(true);

    let endpoints = [
        "/".to_string(),
        "/privacy".to_string(),
        "/demo".to_string(),
        format!("/pay/{public_id}"),
        "/merchant/login".to_string(),
    ];

    for endpoint in endpoints {
        let req = Request::builder().uri(&endpoint).body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();

        assert_eq!(
            res.status(),
            StatusCode::OK,
            "Endpoint {} did not return 200 OK",
            endpoint
        );

        let body = response_body_string(res).await;

        // 1. Must not contain style="
        assert!(
            !body.contains("style=\""),
            "Endpoint {} contains style=\" attribute: {}",
            endpoint,
            body
        );

        // 2. Must not contain onclick=
        assert!(
            !body.contains("onclick="),
            "Endpoint {} contains onclick= attribute: {}",
            endpoint,
            body
        );

        // 3. Must not contain any on*= event attribute
        assert_no_on_event_attributes(&body, &endpoint);
    }
}

#[tokio::test]
async fn test_scanner_health_storage_and_retrieval() {
    let store = open_store(":memory:").expect("open store");

    // Initially unset
    assert_eq!(store.get_last_success_unix_time().unwrap(), None);
    assert_eq!(store.get_last_error_category().unwrap(), None);

    let initial_health = store.get_scanner_health().unwrap();
    assert_eq!(initial_health.last_scanned_block, None);
    assert_eq!(initial_health.chain_tip, None);
    assert_eq!(initial_health.blocks_behind, 0);
    assert_eq!(initial_health.last_success_unix_time, None);
    assert_eq!(initial_health.last_error_category, None);

    // Update values
    store.set_last_scanned_height(3120000).unwrap();
    store.set_chain_tip(3126000).unwrap();
    store.set_last_success_unix_time(1720001234).unwrap();
    store.set_last_error_category("timeout").unwrap();

    assert_eq!(store.get_last_success_unix_time().unwrap(), Some(1720001234));
    assert_eq!(store.get_last_error_category().unwrap(), Some("timeout".to_string()));

    let health = store.get_scanner_health().unwrap();
    assert_eq!(health.last_scanned_block, Some(3120000));
    assert_eq!(health.chain_tip, Some(3126000));
    assert_eq!(health.blocks_behind, 6000);
    assert_eq!(health.last_success_unix_time, Some(1720001234));
    assert_eq!(health.last_error_category, Some("timeout".to_string()));
}

#[tokio::test]
async fn test_scanner_panel_rendered_in_merchant_dashboard() {
    let health = crate::invoices::ScannerHealth {
        last_scanned_block: Some(3120000),
        chain_tip: Some(3126000),
        blocks_behind: 6000,
        last_success_unix_time: Some(1720001234),
        last_error_category: Some("<timeout>&injection".to_string()),
    };

    let dash_html = templates::render_merchant_dashboard(
        &[],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        None,
        None,
        Some("all"),
        Some(&health),
    );

    // Verify presence of Scanner panel and all stats
    assert!(dash_html.contains("id=\"scanner-health-panel\""));
    assert!(dash_html.contains("<h3>Scanner</h3>"));
    assert!(dash_html.contains("Last Scanned Block"));
    assert!(dash_html.contains("3120000"));
    assert!(dash_html.contains("Chain Tip"));
    assert!(dash_html.contains("3126000"));
    assert!(dash_html.contains("Blocks Behind"));
    assert!(dash_html.contains("6000"));
    assert!(dash_html.contains("Last Successful Scan"));
    assert!(dash_html.contains("2024-07-03 10:07 UTC"));
    assert!(dash_html.contains("Last Error Category"));

    // Verify HTML escaping
    assert!(!dash_html.contains("<timeout>&injection"));
    assert!(dash_html.contains("&lt;timeout&gt;&amp;injection"));
}

#[tokio::test]
async fn test_public_pages_do_not_expose_scanner_health() {
    let (app, store, _session_mgr, _limiter, public_id, _password) =
        setup_test_app_custom(true, true, None);

    // Set distinctive scanner health info in the store
    let secret_block = 3120000;
    let secret_tip = 3126000;
    let secret_time = 1720001234;
    let secret_error = "secret_db_failure_marker";

    store.set_last_scanned_height(secret_block).unwrap();
    store.set_chain_tip(secret_tip).unwrap();
    store.set_last_success_unix_time(secret_time).unwrap();
    store.set_last_error_category(secret_error).unwrap();

    let public_endpoints = vec![
        format!("/pay/{public_id}"),
        format!("/api/invoice/{public_id}/status"),
        "/demo".to_string(),
        "/".to_string(),
        "/privacy".to_string(),
    ];

    for endpoint in public_endpoints {
        let req = Request::builder()
            .uri(&endpoint)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Failed on endpoint {endpoint}");

        let body = response_body_string(res).await;

        assert!(!body.contains("scanner-health-panel"), "Found scanner-health-panel in {endpoint}");
        assert!(!body.contains("Last Scanned Block"), "Found Last Scanned Block in {endpoint}");
        assert!(!body.contains("Chain Tip"), "Found Chain Tip in {endpoint}");
        assert!(!body.contains("Blocks Behind"), "Found Blocks Behind in {endpoint}");
        assert!(!body.contains("Last Successful Scan"), "Found Last Successful Scan in {endpoint}");
        assert!(!body.contains("Last Error Category"), "Found Last Error Category in {endpoint}");
        assert!(!body.contains(secret_error), "Found secret_error in {endpoint}");
        assert!(!body.contains("3120000"), "Found secret_block in {endpoint}");
        assert!(!body.contains("3126000"), "Found secret_tip in {endpoint}");
    }
}

// =========================================================================
// Polish Pass Tests
// =========================================================================

#[test]
fn test_utc_and_remaining_time_formatting() {
    use crate::web::templates::{format_utc_timestamp, format_remaining_time};

    assert_eq!(format_utc_timestamp(0), "1970-01-01 00:00 UTC");
    assert_eq!(format_utc_timestamp(1720001234), "2024-07-03 10:07 UTC");
    assert_eq!(format_utc_timestamp(1792364760), "2026-10-18 23:06 UTC");

    assert_eq!(format_remaining_time(100, 200), "expires in 1 min");
    assert_eq!(format_remaining_time(100, 7300), "expires in 2 h 0 min");
    assert_eq!(format_remaining_time(100, 7360), "expires in 2 h 1 min");
    assert_eq!(format_remaining_time(200, 100), "expired");
    assert_eq!(format_remaining_time(100, 100), "expired");
}

#[tokio::test]
async fn test_no_page_contains_the_word_unix() {
    let (app, store, session_mgr, _lim, public_id, _pw) =
        setup_test_app_custom(true, true, None);

    store.set_last_scanned_height(3120000).unwrap();
    store.set_chain_tip(3126000).unwrap();
    store.set_last_success_unix_time(1720001234).unwrap();
    store.set_last_error_category("none").unwrap();

    let session = session_mgr.create_session();

    let pay_uri = format!("/pay/{public_id}");
    let pages = vec![
        ("/", None),
        ("/privacy", None),
        ("/demo", None),
        ("/merchant/login", None),
        (pay_uri.as_str(), None),
        ("/merchant?filter=all", Some(session.token.as_str())),
    ];

    for (path, cookie) in pages {
        let mut builder = Request::builder().uri(path);
        if let Some(tok) = cookie {
            builder = builder.header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, tok));
        }
        let req = builder.body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Status failed on {path}");
        let body = response_body_string(res).await;
        assert!(
            !body.contains("Unix"),
            "Page {path} contains the word 'Unix'"
        );
    }
}

#[tokio::test]
async fn test_no_page_names_orchard_pool_as_destination() {
    let (app, _store, session_mgr, _lim, public_id, _pw) =
        setup_test_app_custom(true, true, None);

    let session = session_mgr.create_session();

    let pay_uri = format!("/pay/{public_id}");
    let pages = vec![
        ("/", None),
        ("/privacy", None),
        ("/demo", None),
        ("/merchant/login", None),
        (pay_uri.as_str(), None),
        ("/merchant?filter=all", Some(session.token.as_str())),
    ];

    for (path, cookie) in pages {
        let mut builder = Request::builder().uri(path);
        if let Some(tok) = cookie {
            builder = builder.header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, tok));
        }
        let req = builder.body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Status failed on {path}");
        let body = response_body_string(res).await;
        assert!(
            !body.contains("Orchard shielded pool"),
            "Page {path} contains 'Orchard shielded pool'"
        );
        assert!(
            !body.contains("Shielded Orchard address"),
            "Page {path} contains 'Shielded Orchard address'"
        );
        assert!(
            !body.contains("Orchard pool"),
            "Page {path} contains 'Orchard pool'"
        );
    }
}

#[tokio::test]
async fn test_demo_page_contains_no_offsite_script_or_image() {
    let (app, _store, _pid, _pw) = setup_test_app(true);

    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_body_string(res).await;

    // Check all script tags
    for part in body.split("<script").skip(1) {
        if let Some(src_part) = part.split('>').next() {
            if src_part.contains("src=") {
                assert!(
                    src_part.contains(r#"src="/static/"#),
                    "Offsite script source found: {src_part}"
                );
                assert!(!src_part.contains("http://"), "Remote http script found: {src_part}");
                assert!(!src_part.contains("https://"), "Remote https script found: {src_part}");
                assert!(!src_part.contains(r#"src="//"#), "Protocol-relative script found: {src_part}");
            }
        }
    }

    // Check all img tags
    for part in body.split("<img").skip(1) {
        if let Some(src_part) = part.split('>').next() {
            if src_part.contains("src=") {
                assert!(
                    src_part.contains(r#"src="/static/"#) || src_part.contains(r#"src="/favicon"#),
                    "Offsite img source found: {src_part}"
                );
                assert!(!src_part.contains("http://"), "Remote http img found: {src_part}");
                assert!(!src_part.contains("https://"), "Remote https img found: {src_part}");
                assert!(!src_part.contains(r#"src="//"#), "Protocol-relative img found: {src_part}");
            }
        }
    }
}

#[tokio::test]
async fn test_faucet_links_carry_rel_noopener_noreferrer() {
    let (app, _store, public_id, _pw) = setup_test_app(true);

    let test_uris = vec!["/demo".to_string(), format!("/pay/{public_id}")];

    for uri in test_uris {
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = response_body_string(res).await;

        assert!(
            body.contains("https://faucet.testnet.valargroup.dev"),
            "Missing valargroup faucet link in {uri}"
        );
        assert!(
            body.contains("https://fauzec.com"),
            "Missing fauzec link in {uri}"
        );

        // Check for rel="noopener noreferrer" and target="_blank"
        assert!(
            body.contains(r#"href="https://faucet.testnet.valargroup.dev" target="_blank" rel="noopener noreferrer""#),
            "Valargroup faucet link missing required attributes in {uri}"
        );
        assert!(
            body.contains(r#"href="https://fauzec.com" target="_blank" rel="noopener noreferrer""#),
            "Fauzec link missing required attributes in {uri}"
        );
    }
}

#[tokio::test]
async fn test_copy_payment_link_button_exists_on_pay_page() {
    let (app, _store, public_id, _pw) = setup_test_app(true);

    let req = Request::builder()
        .uri(format!("/pay/{public_id}"))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_body_string(res).await;

    assert!(body.contains("id=\"copy-link-btn\""));
    assert!(body.contains("Copy payment link"));
    assert!(body.contains("id=\"wallet-hint\""));
    assert!(body.contains("Opens a Zcash wallet app that supports payment links. If nothing happens, scan the QR code or copy the address."));
}

#[tokio::test]
async fn test_logout_button_present_in_dashboard() {
    let (app, _store, session_mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, None);

    let session = session_mgr.create_session();
    let req = Request::builder()
        .uri("/merchant")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_body_string(res).await;

    assert!(body.contains("id=\"logout-btn\""));
    assert!(body.contains("Log out"));
    assert!(body.contains("id=\"logout-form\""));
    assert!(body.contains("class=\"dashboard-header\""));
}

#[tokio::test]
async fn test_dashboard_columns_and_payment_states() {
    let (app, _store, session_mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, None);

    let session = session_mgr.create_session();
    let req = Request::builder()
        .uri("/merchant?filter=all")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_body_string(res).await;

    // Verify columns exist in table header
    assert!(body.contains("<th>Invoice ID</th>"));
    assert!(body.contains("<th>Type</th>"));
    assert!(body.contains("<th>Amount</th>"));
    assert!(body.contains("<th>Received</th>"));
    assert!(body.contains("<th>Excess</th>"));
    assert!(body.contains("<th>State</th>"));
    assert!(body.contains("<th>Created</th>"));
    assert!(body.contains("<th>Action</th>"));

    // Verify payment state badge classes and names exist
    assert!(body.contains("status-awaiting"));
    assert!(body.contains("Awaiting"));
}

// =========================================================================
// PaaS / Render Container Deployment & Health Endpoint Tests
// =========================================================================

#[tokio::test]
async fn test_healthz_endpoint_status_body_and_headers() {
    let (app, _store, _pid, _pw) = setup_test_app(false);

    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Body must be "ok" only
    let body = response_body_string(res).await;
    assert_eq!(body, "ok");

    // Must not expose any scanner, block, or transaction details
    assert!(!body.contains("scanner"));
    assert!(!body.contains("tip"));
    assert!(!body.contains("height"));
    assert!(!body.contains("block"));
    assert!(!body.contains("behind"));
}

#[tokio::test]
async fn test_healthz_rate_limiting_and_no_store() {
    let (app, _store, _pid, _pw) = setup_test_app(false);

    // Initial 60 requests within window succeed
    for _ in 0..60 {
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("cache-control").unwrap(),
            "no-store"
        );
    }

    // 61st request from same client exceeds limit
    let req_blocked = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let res_blocked = app.oneshot(req_blocked).await.unwrap();
    assert_eq!(res_blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        res_blocked.headers().get("cache-control").unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn test_demo_page_notice_for_ephemeral_disk() {
    let (app, _store, _pid, _pw) = setup_test_app(true);

    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = response_body_string(res).await;
    assert!(
        body.contains("This demo instance may reset. Invoices are not guaranteed to persist."),
        "Demo page must contain ephemeral instance reset notice"
    );
}

#[test]
fn test_proxy_multi_header_and_comma_separated_last_entry() {
    let mut headers = HeaderMap::new();
    // Simulate reverse proxy appending its header as an additional header line
    headers.append(
        "x-forwarded-for",
        "1.1.1.1, 2.2.2.2".parse().unwrap(),
    );
    headers.append(
        "x-forwarded-for",
        "3.3.3.3, 4.4.4.4".parse().unwrap(),
    );

    let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let conn = ConnectInfo(peer);

    let client_id = resolve_client_identity(&headers, Some(&conn), Some("x-forwarded-for"));
    assert_eq!(client_id, "4.4.4.4", "Must use the LAST entry of x-forwarded-for");
}

#[tokio::test]
async fn test_dashboard_total_paid_volume_shows_actually_received() {
    let (app, store, session_mgr, _lim, _pid, _pw) =
        setup_test_app_custom(true, true, None);

    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    // Create an invoice for 1.0 ZEC (100_000_000 zatoshis)
    let inv = create_invoice(&store, &uivk, &network, 100_000_000, 3600).unwrap();

    // Customer overpays: pays 1.5 ZEC (150_000_000 zatoshis)
    {
        let conn = store.conn().lock().unwrap();
        conn.execute(
            "INSERT INTO payments (address_index, txid, output_index, pool, value_zatoshi, block_height, block_hash, block_time)
             VALUES (?1, 'dummy_txid_overpay_test', 0, 'orchard', 150000000, 100, 'hash100', 0)",
            [inv.address_index],
        )
        .unwrap();
    }

    // Mark invoice Paid
    store.mark_paid(&inv.public_id).unwrap();

    let session = session_mgr.create_session();
    let req = Request::builder()
        .uri("/merchant?filter=all")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_body_string(res).await;

    // Total Paid Volume must show the amount ACTUALLY received (1.5 ZEC), not invoice amount (1.0 ZEC)
    assert!(
        body.contains("<div class=\"total-label\">Total Paid Volume</div>\n            <div class=\"total-value\">1.5 ZEC</div>"),
        "Total paid volume card must show 1.5 ZEC actually received, got body: {body}"
    );
}

#[test]
fn test_open_store_creates_parent_directories() {
    let temp_dir = std::env::temp_dir();
    let nested_db_dir = temp_dir
        .join("test_veilgate_parent_dir_creation")
        .join("subfolder");
    let db_path = nested_db_dir.join("test.db");

    if nested_db_dir.exists() {
        let _ = std::fs::remove_dir_all(&nested_db_dir);
    }

    assert!(!nested_db_dir.exists());

    let store_res = open_store(&db_path);
    assert!(store_res.is_ok());
    assert!(nested_db_dir.exists(), "Parent directory must be created");

    drop(store_res);
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_dir_all(temp_dir.join("test_veilgate_parent_dir_creation"));
}

#[test]
fn test_resolve_listen_address_from_config() {
    use crate::web::handlers::resolve_listen_address_from_config;

    let cli_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

    // 1. When --listen is explicitly given on CLI, it takes precedence over PORT
    let res = resolve_listen_address_from_config(Some(cli_addr), Some("10000"), None, true).unwrap();
    assert_eq!(res, cli_addr);

    // 2. When --listen is NOT given on CLI, PORT is used (binds to 0.0.0.0:$PORT)
    let res_port = resolve_listen_address_from_config(None, Some("10000"), None, false).unwrap();
    assert_eq!(res_port, "0.0.0.0:10000".parse::<SocketAddr>().unwrap());

    // 3. When --listen is NOT given on CLI and PORT is not set, VEILGATE_LISTEN is used
    let res_env = resolve_listen_address_from_config(None, None, Some("192.168.1.10:8080"), false).unwrap();
    assert_eq!(res_env, "192.168.1.10:8080".parse::<SocketAddr>().unwrap());

    // 4. When nothing is set, defaults to 127.0.0.1:8080
    let res_default = resolve_listen_address_from_config(None, None, None, false).unwrap();
    assert_eq!(res_default, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());

    // 5. Invalid PORT returns an error
    let res_err = resolve_listen_address_from_config(None, Some("not_a_valid_port"), None, false);
    assert!(res_err.is_err());
}

#[test]
fn test_render_yaml_image_deploy_spec() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let render_yaml_path = repo_root.join("render.yaml");
    assert!(render_yaml_path.exists(), "render.yaml must exist");

    let content = std::fs::read_to_string(&render_yaml_path).expect("read render.yaml");

    // Must declare runtime: image with prebuilt ghcr.io image
    assert!(content.contains("runtime: image"), "render.yaml must use runtime: image");
    assert!(content.contains("url: ghcr.io/jotel-dev/veilgate:latest"), "render.yaml must reference prebuilt image");
    assert!(content.contains("plan: free"), "render.yaml must specify free plan");
    assert!(content.contains("healthCheckPath: /healthz"), "render.yaml must use /healthz health check");

    // Secrets must have sync: false
    assert!(content.contains("key: VEILGATE_VIEWING_KEY"));
    assert!(content.contains("key: VEILGATE_PASSWORD_HASH"));
    assert!(content.contains("sync: false"));

    // Required environment variables
    assert!(content.contains("key: VEILGATE_DEMO"));
    assert!(content.contains("key: VEILGATE_TRUSTED_PROXY_HEADER"));
    assert!(content.contains("value: x-forwarded-for"));
    assert!(content.contains("key: VEILGATE_LIGHTWALLETD_URL"));
    assert!(content.contains("key: VEILGATE_DB_PATH"));
}

#[test]
fn test_github_actions_docker_workflow_spec() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let workflow_path = repo_root.join(".github").join("workflows").join("docker.yml");
    assert!(workflow_path.exists(), ".github/workflows/docker.yml must exist");

    let content = std::fs::read_to_string(&workflow_path).expect("read docker.yml");

    // Triggers
    assert!(content.contains("push:"), "must trigger on push");
    assert!(content.contains("- main"), "must trigger on main branch");
    assert!(content.contains("workflow_dispatch:"), "must support workflow_dispatch");
    assert!(content.contains("'backend/**'") || content.contains("backend/**"));
    assert!(content.contains("'Dockerfile'") || content.contains("Dockerfile"));
    assert!(content.contains("'.dockerignore'") || content.contains(".dockerignore"));

    // Permissions limited to contents: read and packages: write
    assert!(content.contains("contents: read"));
    assert!(content.contains("packages: write"));

    // First job step runs cargo test
    assert!(content.contains("cargo test"), "must run cargo test before building");

    // Official pinned actions only
    assert!(content.contains("actions/checkout@v4"));
    assert!(content.contains("docker/setup-buildx-action@v3"));
    assert!(content.contains("docker/login-action@v3"));
    assert!(content.contains("docker/metadata-action@v5"));
    assert!(content.contains("docker/build-push-action@v6"));

    // Container registry target
    assert!(content.contains("ghcr.io"));
    assert!(content.contains("ghcr.io/jotel-dev/veilgate"));

    // Tag generation: latest and sha-<shortsha>
    assert!(content.contains("type=raw,value=latest"));
    assert!(content.contains("type=sha,prefix=sha-,format=short"));

    // Verification step
    assert!(content.contains(".veilgate"), "must check for .veilgate");
    assert!(content.contains("*.db"), "must check for *.db");
    assert!(content.contains(".env*"), "must check for .env*");
    assert!(content.contains("docs/design"), "must check for docs/design");
}

#[tokio::test]
async fn test_motion_polish_system_and_reduced_motion() {
    let (app, store, session_mgr, _lim, public_id, _pw) =
        setup_test_app_custom(true, true, None);
    let session = session_mgr.create_session();

    store.set_last_scanned_height(3120000).unwrap();
    store.set_chain_tip(3126000).unwrap();
    store.set_last_success_unix_time(1720001234).unwrap();
    store.set_last_error_category("none").unwrap();

    // 1. Verify no "style=" attribute in any rendered page
    let pages = vec![
        ("/".to_string(), None),
        ("/privacy".to_string(), None),
        ("/demo".to_string(), None),
        (format!("/pay/{public_id}"), None),
        ("/merchant/login".to_string(), None),
        ("/merchant?filter=all".to_string(), Some(session.token.as_str())),
    ];

    for (path, cookie) in &pages {
        let mut builder = Request::builder().uri(path);
        if let Some(tok) = cookie {
            builder = builder.header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, tok));
        }
        let req = builder.body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Failed to load {}", path);
        let body = response_body_string(res).await;

        assert!(!body.contains("style="), "Page {} contained style= attribute", path);
        assert!(!body.contains("style ="), "Page {} contained style = attribute", path);

        // Verify content renders without JavaScript (SSR complete content)
        assert!(
            body.contains("<main") || body.contains("checkout-card"),
            "Page {} missing content in raw HTML",
            path
        );

        // Verify banned words (including "Unix")
        let banned_words = ["Solana", "USDC", "Pricing", "30,000", "uptime", "Unix"];
        for word in banned_words {
            assert!(
                !body.contains(word),
                "Page {} contained banned word '{}'",
                path,
                word
            );
        }
    }

    // 2. Static style.css verification
    let req_css = Request::builder().uri("/static/style.css").body(Body::empty()).unwrap();
    let res_css = app.clone().oneshot(req_css).await.unwrap();
    assert_eq!(res_css.status(), StatusCode::OK);
    let css = response_body_string(res_css).await;

    // style.css contains a prefers-reduced-motion block that disables transforms and loops
    assert!(
        css.contains("@media (prefers-reduced-motion: reduce)"),
        "style.css missing @media (prefers-reduced-motion: reduce)"
    );
    assert!(
        css.contains("transform: none !important"),
        "prefers-reduced-motion block must set transform: none !important"
    );
    assert!(
        css.contains("animation: none !important"),
        "prefers-reduced-motion block must set animation: none !important"
    );

    // Hidden pre-reveal selectors are all scoped under .js (html.js)
    assert!(
        css.contains("html.js .hero-content > *"),
        "Pre-reveal hero items must be scoped under html.js"
    );
    assert!(
        css.contains("html.js .feature-card"),
        "Pre-reveal feature cards must be scoped under html.js"
    );
    assert!(
        css.contains("html.js .band-section"),
        "Pre-reveal band must be scoped under html.js"
    );
    assert!(
        css.contains("html.js .step-card"),
        "Pre-reveal step cards must be scoped under html.js"
    );

    // Stagger utility classes (.reveal-delay-1 to .reveal-delay-5)
    for i in 1..=5 {
        assert!(
            css.contains(&format!(".reveal-delay-{i}")),
            "style.css missing .reveal-delay-{}",
            i
        );
    }

    // 3. Static app.js verification
    let req_js = Request::builder().uri("/static/app.js").body(Body::empty()).unwrap();
    let res_js = app.clone().oneshot(req_js).await.unwrap();
    assert_eq!(res_js.status(), StatusCode::OK);
    let js = response_body_string(res_js).await;

    // app.js adds .js class to documentElement
    assert!(
        js.contains("document.documentElement.classList.add('js')"),
        "app.js must add 'js' class to documentElement"
    );

    // 4. Forbidden strings in CSS and JS
    let forbidden = ["framer", "gsap", "react", "@import", "http"];
    for word in forbidden {
        assert!(
            !css.to_lowercase().contains(word),
            "style.css contained forbidden string: {}",
            word
        );
        assert!(
            !js.to_lowercase().contains(word),
            "app.js contained forbidden string: {}",
            word
        );
    }

    // 5. Total added sizes
    // Original CSS: 25,330 bytes; budget: +10 KB (< 10,240 bytes) -> max 35,570 bytes
    // Original JS: 7,613 bytes; budget: +4 KB (< 4,096 bytes) -> max 11,709 bytes
    let css_len = css.as_bytes().len();
    let js_len = js.as_bytes().len();
    assert!(
        css_len <= 35570,
        "style.css exceeded size budget: {} bytes (max 35570)",
        css_len
    );
    assert!(
        js_len <= 11709,
        "app.js exceeded size budget: {} bytes (max 11709)",
        js_len
    );
}

#[tokio::test]
async fn test_demo_page_defaults_and_sentence() {
    let (app, _store, _pid, _pw) = setup_test_app(true);

    let req = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_body_string(res).await;

    // Default amount is 0.01 ZEC
    assert!(
        body.contains(r#"value="0.01""#) && body.contains(r#"placeholder="0.01""#),
        "Demo page must have default amount 0.01 ZEC"
    );

    // Default validity is 60 minutes
    assert!(
        body.contains(r#"name="validity_minutes" value="60""#),
        "Demo page must have default validity 60 minutes"
    );

    // Allowed range is 0.001 to 10 ZEC
    assert!(
        body.contains("Allowed range: 0.001 to 10 ZEC (testnet)"),
        "Demo page must state allowed range 0.001 to 10 ZEC"
    );

    // Sentence under the form
    assert!(
        body.contains("Testnet faucets pay between 0.1 and 1 test coin; a 0.01 invoice is covered by any of them."),
        "Demo page must contain exact sentence under the form"
    );
}

fn setup_test_app_empty(
    demo_enabled: bool,
) -> (
    axum::Router,
    Arc<Store>,
    Arc<SessionManager>,
    Arc<RateLimiter>,
    String,
) {
    let store = Arc::new(open_store(":memory:").expect("open in-memory store"));
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    let password = "correct_horse_battery_staple";
    let password_hash = hash_password(password).expect("hash password");
    let session_manager = Arc::new(SessionManager::new());
    let rate_limiter = Arc::new(RateLimiter::new());

    let state = AppState {
        store: Arc::clone(&store),
        uivk: Arc::new(uivk.clone()),
        network,
        confirmations: 3,
        repo_url: None,
        demo_enabled,
        password_hash: Some(password_hash),
        session_manager: Arc::clone(&session_manager),
        rate_limiter: Arc::clone(&rate_limiter),
        is_localhost: true,
        trusted_proxy_header: None,
    };

    let app = build_app(state);
    (app, store, session_manager, rate_limiter, password.to_string())
}

#[tokio::test]
async fn test_showcase_excluded_from_demo_pending_cap() {
    let (app, store, _session_mgr, _lim, _pw) = setup_test_app_empty(true);
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    // Seed showcase invoice
    let cfg = crate::invoices::ShowcaseConfig {
        index: 5,
        amount_zatoshi: 1_000_000,
        public_id: "00112233445566778899aabbccddeeff".to_string(),
        scan_from_height: 3_000_000,
        scan_to_height: 3_000_500,
        label: "Showcase demo".to_string(),
    };
    let seeded = crate::invoices::init_showcase_invoice(&store, &uivk, &network, &cfg).unwrap();
    assert!(seeded, "Showcase must be seeded on empty DB");

    // Now create 99 pending demo invoices
    for _ in 0..99 {
        create_demo_invoice(&store, &uivk, &network, 100_000, 3600).unwrap();
    }

    // Get a valid CSRF token from /demo
    let req_csrf = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res_csrf = app.clone().oneshot(req_csrf).await.unwrap();
    let csrf_cookie = res_csrf
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let csrf_token = csrf_cookie
        .split(';')
        .next()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();

    // POST /demo to create the 100th demo invoice.
    // If showcase were counted, total pending demo count would be 100 and this would fail with 429.
    // Because showcase is excluded, total pending demo count is 99, so this succeeds with 303 Redirect!
    let form_body = format!("csrf_token={}&amount=0.01&validity_minutes=60", csrf_token);
    let req_post = Request::builder()
        .method("POST")
        .uri("/demo")
        .header(COOKIE, format!("{}={}", CSRF_COOKIE_NAME, csrf_token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let res_post = app.clone().oneshot(req_post).await.unwrap();
    assert_eq!(
        res_post.status(),
        StatusCode::SEE_OTHER,
        "POST /demo must succeed when 99 demo invoices exist plus 1 showcase invoice"
    );
}

#[tokio::test]
async fn test_showcase_ui_card_pay_notice_and_dashboard_badge() {
    let (app, store, session_mgr, _lim, _pw) = setup_test_app_empty(true);
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);

    let showcase_pid = "aabbccddeeff00112233445566778899";
    let cfg = crate::invoices::ShowcaseConfig {
        index: 12,
        amount_zatoshi: 2_000_000,
        public_id: showcase_pid.to_string(),
        scan_from_height: 3_000_000,
        scan_to_height: 3_000_500,
        label: "Official Testnet Faucet Payment".to_string(),
    };
    let seeded = crate::invoices::init_showcase_invoice(&store, &uivk, &network, &cfg).unwrap();
    assert!(seeded, "Showcase must be seeded on empty DB");

    // 1. /demo page shows showcase card
    let req_demo = Request::builder().uri("/demo").body(Body::empty()).unwrap();
    let res_demo = app.clone().oneshot(req_demo).await.unwrap();
    assert_eq!(res_demo.status(), StatusCode::OK);
    let body_demo = response_body_string(res_demo).await;
    assert!(body_demo.contains("See a real completed payment"));
    assert!(body_demo.contains(&format!("/pay/{showcase_pid}")));
    assert!(body_demo.contains("Official Testnet Faucet Payment"));
    assert!(body_demo.contains("This invoice was paid on the Zcash testnet with a faucet payment; this server detected it with its watch-only key."));

    // 2. /pay/<showcase_public_id> while scanner is catching up (far behind tip)
    // Set cursor = 3_000_000, tip = 3_001_000 (1000 blocks behind >= 10)
    store.set_last_scanned_height(3_000_000).unwrap();
    store.set_chain_tip(3_001_000).unwrap();

    let req_pay = Request::builder()
        .uri(format!("/pay/{showcase_pid}"))
        .body(Body::empty())
        .unwrap();
    let res_pay = app.clone().oneshot(req_pay).await.unwrap();
    assert_eq!(res_pay.status(), StatusCode::OK);
    let body_pay = response_body_string(res_pay).await;
    // Shows normal Awaiting payment state
    assert!(body_pay.contains("Awaiting payment"));
    // Plus the re-reading line
    assert!(body_pay.contains("This example is being re-read from the chain after a restart"));

    // 3. When scanner caught up (e.g. cursor == tip), re-reading line is NOT shown
    store.set_last_scanned_height(3_001_000).unwrap();
    let req_pay_caught_up = Request::builder()
        .uri(format!("/pay/{showcase_pid}"))
        .body(Body::empty())
        .unwrap();
    let res_pay_caught_up = app.clone().oneshot(req_pay_caught_up).await.unwrap();
    let body_pay_caught_up = response_body_string(res_pay_caught_up).await;
    assert!(!body_pay_caught_up.contains("This example is being re-read from the chain after a restart"));

    // 4. In merchant dashboard (/merchant?filter=all), showcase is marked with Showcase badge
    let session = session_mgr.create_session();
    let req_dash = Request::builder()
        .uri("/merchant?filter=all")
        .header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, session.token))
        .body(Body::empty())
        .unwrap();
    let res_dash = app.clone().oneshot(req_dash).await.unwrap();
    assert_eq!(res_dash.status(), StatusCode::OK);
    let body_dash = response_body_string(res_dash).await;
    assert!(body_dash.contains(r#"<span class="status-pill status-showcase">Showcase</span>"#));
}

#[tokio::test]
async fn test_no_page_contains_the_viewing_key() {
    let (app, _store, session_mgr, _lim, public_id, _pw) =
        setup_test_app_custom(true, true, None);
    let session = session_mgr.create_session();

    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);
    let key_encoded = uivk.encode(&network);

    let pay_uri = format!("/pay/{public_id}");
    let pages = vec![
        ("/", None),
        ("/privacy", None),
        ("/demo", None),
        ("/merchant/login", None),
        (pay_uri.as_str(), None),
        ("/merchant", Some(session.token.as_str())),
        ("/merchant?filter=all", Some(session.token.as_str())),
    ];

    for (path, cookie) in pages {
        let mut builder = Request::builder().uri(path);
        if let Some(tok) = cookie {
            builder = builder.header(COOKIE, format!("{}={}", SESSION_COOKIE_NAME, tok));
        }
        let req = builder.body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "Failed on path {path}");
        let body = response_body_string(res).await;

        assert!(
            !body.contains("uivktest"),
            "Page {path} contains substring 'uivktest'!"
        );
        assert!(
            !body.contains("uviewtest"),
            "Page {path} contains substring 'uviewtest'!"
        );
        assert!(
            !body.contains(&key_encoded),
            "Page {path} contains full encoded viewing key string!"
        );
    }
}





// =========================================================================
// Motion system: app pages never depend on JavaScript to become visible
// =========================================================================

fn strip_css_comments(css: &str) -> String {
    let mut out = String::new();
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start..].find("*/") {
            Some(end) => rest = &rest[start + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Selectors (with the `html.js ` prefix removed) of every html.js rule that sets opacity: 0.
fn pre_reveal_selectors(css: &str) -> Vec<String> {
    let css = strip_css_comments(css);
    let mut found = Vec::new();
    for chunk in css.split('}') {
        let Some((sel, body)) = chunk.split_once('{') else { continue };
        if !body.contains("opacity: 0;") {
            continue;
        }
        for s in sel.split(',') {
            if let Some(rest) = s.trim().strip_prefix("html.js ") {
                found.push(rest.trim().to_string());
            }
        }
    }
    found
}

fn js_string_var(js: &str, name: &str) -> Vec<String> {
    let marker = format!("var {name} = {quote}", quote = '\'');
    let start = js.find(&marker).unwrap_or_else(|| panic!("app.js missing {name}")) + marker.len();
    let end = js[start..].find('\'').unwrap() + start;
    js[start..end].split(',').map(|s| s.trim().to_string()).collect()
}

#[test]
fn test_pre_reveal_selectors_are_observed_and_covered_by_failsafe() {
    use crate::web::static_assets::{APP_JS, STYLE_CSS};
    let pre = pre_reveal_selectors(STYLE_CSS);
    assert!(!pre.is_empty(), "expected landing pre-reveal selectors");
    let observed = js_string_var(APP_JS, "selector");
    let failsafe = js_string_var(APP_JS, "preReveal");

    // The element whose `revealed` class unlocks each pre-reveal state.
    let gate = |s: &str| -> String {
        match s {
            ".hero-content > *" => ".hero-content",
            ".feature-card" => ".features-grid",
            ".step-card" | ".step-number" => ".steps-grid",
            ".fact-item" => ".band-section",
            ".floating-badge" => ".hero-card-wrapper",
            other => other,
        }
        .to_string()
    };

    for s in &pre {
        assert!(
            observed.contains(&gate(s)),
            "pre-reveal selector '{s}' is not observed (gate '{}')",
            gate(s)
        );
        assert!(failsafe.contains(s), "pre-reveal selector '{s}' missing from failsafe list");
    }
    assert!(APP_JS.contains("setTimeout(revealAll, 1500)"));
    assert!(APP_JS.contains("'pageshow'"));
    assert!(APP_JS.contains("!('IntersectionObserver' in window)"));
}

#[test]
fn test_app_page_selectors_have_no_js_pre_reveal() {
    use crate::web::static_assets::STYLE_CSS;
    let app_selectors = [
        ".checkout-card",
        ".privacy-panel",
        ".table-container",
        ".totals-grid",
        ".scanner-stat",
        ".scanner-grid",
        ".site-footer",
    ];
    let pre = pre_reveal_selectors(STYLE_CSS);
    for sel in app_selectors {
        assert!(
            !pre.iter().any(|p| p.split_whitespace().any(|t| t == sel)),
            "app selector {sel} must not have an html.js opacity:0 state"
        );
    }
    // CSS-only load animation exists for app selectors and is disabled under reduced motion.
    let css = strip_css_comments(STYLE_CSS);
    assert!(css.contains("animation: app-in 300ms"));
    assert!(css.contains("@keyframes app-in"));
    let reduced = css.split("@media (prefers-reduced-motion: reduce)").last().unwrap();
    assert!(reduced.contains("animation: none !important"));
}

#[test]
fn test_app_pages_do_not_depend_on_revealed_class() {
    let store = open_store(":memory:").expect("open store");
    let network = Network::TestNetwork;
    let uivk = test_uivk(&network);
    let inv = create_invoice(&store, &uivk, &network, 250_000_000, 3600).unwrap();
    let csrf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let pages = vec![
        (
            "pay",
            templates::render_pay_page(
                &inv, "<svg></svg>", "Awaiting payment", "status-awaiting", "Waiting",
                0, "zcash:test", None, false, false,
            ),
        ),
        ("demo", templates::render_demo_page(csrf, None, None, false, None)),
        ("privacy", templates::render_privacy_page(None, false)),
        ("login", templates::render_login_page(csrf, None, None)),
        (
            "dashboard",
            templates::render_merchant_dashboard(&[], csrf, None, None, None, None),
        ),
    ];
    for (name, html) in &pages {
        let any_reveal_class = html
            .split("class=\"")
            .skip(1)
            .filter_map(|c| c.split('"').next())
            .any(|c| c.split_whitespace().any(|t| t.starts_with("reveal")));
        assert!(!any_reveal_class, "page '{name}' uses a reveal class");
    }
    // The landing page, in contrast, uses the marketing reveal on its footer.
    assert!(templates::render_landing_page(None, false).contains("site-footer reveal"));
}

#[test]
fn test_asset_urls_are_versioned_by_content() {
    use crate::web::static_assets::{content_version, static_url, APP_JS, STYLE_CSS};
    let landing = templates::render_landing_page(None, false);
    let css_url = format!("/static/style.css?v={}", content_version(STYLE_CSS.as_bytes()));
    let js_url = format!("/static/app.js?v={}", content_version(APP_JS.as_bytes()));
    assert_eq!(static_url("style.css"), css_url);
    assert_eq!(static_url("app.js"), js_url);
    assert!(landing.contains(&format!("href=\"{css_url}\"")));
    assert!(landing.contains(&format!("src=\"{js_url}\"")));
    assert!(landing.contains("/static/logo-light.png?v="));
    assert!(landing.contains("/static/shield-mark.png?v="));
    assert!(landing.contains("/favicon.png?v="));
    assert!(!landing.contains("\"/static/style.css\""));

    // The version changes whenever the content changes, and is stable otherwise.
    let a = content_version(b"body { color: red; }");
    let b = content_version(b"body { color: blue; }");
    assert_ne!(a, b);
    assert_eq!(a, content_version(b"body { color: red; }"));
    assert_eq!(a.len(), 8);
}

#[tokio::test]
async fn test_cache_headers_for_assets_and_html() {
    use crate::web::static_assets::static_url;
    let (app, _store, _pid, _pw) = setup_test_app(true);

    let get = |uri: String| {
        let app = app.clone();
        async move {
            let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
            app.oneshot(req).await.unwrap()
        }
    };

    let versioned = get(static_url("style.css")).await;
    assert_eq!(versioned.status(), StatusCode::OK);
    assert_eq!(
        versioned.headers().get("cache-control").unwrap(),
        "public, max-age=86400, immutable"
    );
    let unversioned = get("/static/style.css".to_string()).await;
    assert_eq!(unversioned.headers().get("cache-control").unwrap(), "no-cache");
    let stale = get("/static/app.js?v=00000000".to_string()).await;
    assert_eq!(stale.headers().get("cache-control").unwrap(), "no-cache");

    for path in ["/", "/privacy"] {
        let res = get(path.to_string()).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get("cache-control").unwrap(), "no-cache", "{path}");
    }
    let demo = get("/demo".to_string()).await;
    let cc = demo.headers().get("cache-control").unwrap().to_str().unwrap().to_string();
    assert!(cc == "no-cache" || cc == "no-store", "demo must not be cached");
}
