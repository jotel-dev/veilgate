//! Server-rendered HTML templates for VeilGate.
//!
//! Hard constraints:
//! - No inline styles (`style="..."` forbidden by CSP)
//! - No inline scripts (`<script>...</script>` without src forbidden by CSP)
//! - No third-party assets, fonts, or scripts
//! - No emojis anywhere in the markup
//! - Mobile-first responsive structure

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::web::amount::format_zec_display;
use crate::web::icons;
use crate::invoices::{Invoice, InvoiceStatus, ScannerHealth};

/// Escapes HTML special characters: `&`, `<`, `>`, `"`, and `'`.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Formats a Unix timestamp (seconds since epoch) as "YYYY-MM-DD HH:MM UTC".
pub fn format_utc_timestamp(timestamp: u64) -> String {
    let secs_of_day = (timestamp % 86400) as u32;
    let hours = secs_of_day / 3600;
    let minutes = (secs_of_day % 3600) / 60;

    let mut days = (timestamp / 86400) as i64;
    let mut year = 1970;
    loop {
        let leap = is_leap_year(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }
    let leap = is_leap_year(year);
    let days_in_months = [
        31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut month = 1;
    for &dim in &days_in_months {
        if days >= dim {
            days -= dim;
            month += 1;
        } else {
            break;
        }
    }
    let day = days + 1;
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02} UTC")
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Formats remaining time until expiration as e.g. "expires in 1 h 52 min" or "expires in 15 min".
pub fn format_remaining_time(now_secs: u64, expires_at: u64) -> String {
    if expires_at <= now_secs {
        "expired".to_string()
    } else {
        let diff = expires_at - now_secs;
        let hours = diff / 3600;
        let mins = (diff % 3600) / 60;
        if hours > 0 {
            format!("expires in {hours} h {mins} min")
        } else {
            format!("expires in {mins} min")
        }
    }
}

/// Item representing an invoice row in the merchant dashboard with computed payment state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardInvoiceItem {
    pub invoice: Invoice,
    pub received_zatoshi: u64,
    pub excess_zatoshi: u64,
    pub payment_state: String,
}

impl From<Invoice> for DashboardInvoiceItem {
    fn from(inv: Invoice) -> Self {
        let state = match inv.status {
            InvoiceStatus::Paid => {
                if inv.is_late {
                    "Paid late".to_string()
                } else {
                    "Paid".to_string()
                }
            }
            InvoiceStatus::Pending => "Awaiting".to_string(),
            InvoiceStatus::Expired => "Expired".to_string(),
        };
        let (received, excess) = if inv.status == InvoiceStatus::Paid {
            (inv.amount_zatoshi, 0)
        } else {
            (0, 0)
        };
        Self {
            invoice: inv,
            received_zatoshi: received,
            excess_zatoshi: excess,
            payment_state: state,
        }
    }
}

/// Base HTML layout wrapper for app pages (no JS-dependent reveal states).
pub fn layout(
    title: &str,
    content: &str,
    show_testnet_banner: bool,
    repo_url: Option<&str>,
    csrf_token: Option<&str>,
    meta_refresh_seconds: Option<u32>,
    has_session: bool,
) -> String {
    layout_with(
        title,
        content,
        show_testnet_banner,
        repo_url,
        csrf_token,
        meta_refresh_seconds,
        has_session,
        false,
    )
}

/// Layout wrapper; `landing` enables the scroll-reveal footer (marketing page only).
#[allow(clippy::too_many_arguments)]
fn layout_with(
    title: &str,
    content: &str,
    show_testnet_banner: bool,
    repo_url: Option<&str>,
    csrf_token: Option<&str>,
    meta_refresh_seconds: Option<u32>,
    has_session: bool,
    landing: bool,
) -> String {
    use super::static_assets::static_url;
    let css_url = static_url("style.css");
    let js_url = static_url("app.js");
    let favicon_url = static_url("favicon.png");
    let touch_url = static_url("apple-touch-icon.png");
    let logo_light_url = static_url("logo-light.png");
    let logo_dark_url = static_url("logo-dark.png");
    let footer_class = if landing { "site-footer reveal" } else { "site-footer" };
    let title_esc = esc(title);
    let testnet_bar = if show_testnet_banner {
        r#"<div class="testnet-banner" role="alert">Testnet Only &mdash; No real funds &mdash; Zcash Testnet coins only</div>"#
    } else {
        ""
    };

    let refresh_tag = if let Some(secs) = meta_refresh_seconds {
        format!(r#"<noscript><meta http-equiv="refresh" content="{secs}"></noscript>"#)
    } else {
        String::new()
    };

    let github_link = if let Some(url) = repo_url {
        format!(
            r#"<a href="{url}" class="footer-link" aria-label="GitHub Repository" rel="noopener noreferrer">{github_icon}</a>"#,
            url = esc(url),
            github_icon = icons::GITHUB
        )
    } else {
        String::new()
    };

    let csrf_cookie_script = if let Some(_csrf) = csrf_token {
        // CSRF token is passed via cookie and form input, no inline script needed.
        ""
    } else {
        ""
    };

    let dashboard_btn_text = if has_session {
        "Dashboard"
    } else {
        "Open dashboard"
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title_esc} &mdash; VeilGate</title>
    <meta name="description" content="VeilGate is a privacy-first shielded payment checkout for Zcash testnet.">
    {refresh_tag}
    <link rel="stylesheet" href="{css_url}">
    <link rel="icon" type="image/png" sizes="32x32" href="{favicon_url}">
    <link rel="apple-touch-icon" sizes="180x180" href="{touch_url}">
    <script src="{js_url}" defer></script>
</head>
<body>
    {testnet_bar}
    <header class="site-header">
        <div class="header-inner">
            <a href="/" class="logo-container" aria-label="VeilGate Home">
                <img src="{logo_light_url}" class="logo-light" alt="VeilGate" width="130" height="38">
                <img src="{logo_dark_url}" class="logo-dark" alt="VeilGate" width="130" height="38">
            </a>
            <nav class="nav-links" aria-label="Main Navigation">
                <a href="/">Home</a>
                <a href="/#how-it-works">How it works</a>
                <a href="/privacy">Privacy</a>
                <a href="/demo">Demo</a>
            </nav>
            <div class="header-actions">
                <button type="button" id="theme-toggle" class="btn-icon" aria-label="Toggle visual theme">
                    {sun_icon}
                    {moon_icon}
                </button>
                <a href="/merchant" class="btn-primary" id="open-dashboard-btn">{dashboard_btn_text}</a>
            </div>
        </div>
    </header>
    <main>
        {content}
    </main>
    <footer class="{footer_class}">
        <div class="footer-inner">
            <div class="footer-brand">
                <a href="/" class="logo-container" aria-label="VeilGate Home">
                    <img src="{logo_light_url}" class="logo-light" alt="VeilGate" width="110" height="32">
                    <img src="{logo_dark_url}" class="logo-dark" alt="VeilGate" width="110" height="32">
                </a>
            </div>
            <div class="footer-links">
                <a href="/">Home</a>
                <a href="/#how-it-works">How it works</a>
                <a href="/privacy">Privacy</a>
                <a href="/demo">Demo</a>
                {github_link}
            </div>
            <div class="footer-copy">
                &copy; 2026 VeilGate. Built for Zecathon 2026. Testnet only.
            </div>
        </div>
    </footer>
    {csrf_cookie_script}
</body>
</html>"#,
        sun_icon = icons::SUN,
        moon_icon = icons::MOON,
    )
}

/// Renders the Landing Page (`GET /`).
/// Must match exact text requirements from prompt:
/// - No emojis
/// - Exact text strings
/// - None of the banned words
pub fn render_landing_page(repo_url: Option<&str>, has_session: bool) -> String {
    let shield_url = super::static_assets::static_url("shield-mark.png");
    let content = format!(
        r#"<section class="hero-section">
    <div class="hero-grid">
        <div class="hero-content reveal-on-load">
            <span class="eyebrow">PRIVACY-FIRST PAYMENTS</span>
            <h1>Secure checkout. Private by design.</h1>
            <p class="hero-subtext">VeilGate is a shielded payment checkout for merchants. Create an invoice, share a link or QR code, and confirm payment with a watch-only key that cannot spend your funds.</p>
            <div class="hero-actions">
                <a href="/demo" class="btn-primary" id="try-demo-btn">Try the demo</a>
                <a href="/privacy" class="btn-secondary" id="read-privacy-btn">Read the privacy model</a>
            </div>
            <div class="check-row">
                <div class="check-item">{check_icon} <span>Shielded payments</span></div>
                <div class="check-item">{check_icon} <span>Watch-only server</span></div>
                <div class="check-item">{check_icon} <span>No trackers</span></div>
            </div>
        </div>
        <div class="hero-card-wrapper reveal-on-load">
            <div class="floating-badge">
                {lock_icon} <span>No account. No tracking.</span>
            </div>
            <div class="mockup-card" aria-label="Example invoice illustration">
                <div class="mockup-header">
                    <span class="mockup-brand">VeilGate</span>
                    <span class="mockup-badge">{shield_icon} Secure and private</span>
                </div>
                <div class="mockup-title">Complete your payment</div>
                <div class="mockup-label">Example invoice</div>
                <div class="mockup-amount-box">
                    <div class="mockup-amount">1.5 ZEC</div>
                    <div class="mockup-network">Zcash testnet</div>
                </div>
                <div class="mockup-btn">
                    {link_icon} <span>Open in wallet</span>
                </div>
                <div class="mockup-footer">
                    Powered by Zcash (testnet)
                </div>
            </div>
        </div>
    </div>
</section>

<section class="features-section">
    <div class="features-grid reveal">
        <div class="feature-card">
            <div class="feature-icon-wrapper">{shield_icon}</div>
            <h3>Shielded payments</h3>
            <p>Payments to a shielded address hide the sender, receiver and amount from public observers.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon-wrapper">{key_icon}</div>
            <h3>Watch-only server</h3>
            <p>The server holds an incoming viewing key. It can detect payments but cannot spend them.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon-wrapper">{qr_icon}</div>
            <h3>One address per invoice</h3>
            <p>Every invoice gets its own address, so payments are matched without relying on memos.</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon-wrapper">{lock_icon}</div>
            <h3>Open source</h3>
            <p>The code is public so you can verify these claims.</p>
        </div>
    </div>
</section>

<section class="band-section reveal">
    <div class="band-inner">
        <div class="band-content">
            <span class="eyebrow">BUILT FOR PRIVACY</span>
            <h2>Honest about what is private.</h2>
            <p>VeilGate shows what a public observer sees, what the merchant sees, and what the checkout itself exposes.</p>
        </div>
        <div class="band-facts">
            <div class="fact-item">{check_icon} <span>0 third-party requests</span></div>
            <div class="fact-item">{check_icon} <span>View-only server key</span></div>
            <div class="fact-item">{check_icon} <span>Open source code</span></div>
        </div>
    </div>
</section>

<section class="how-section" id="how-it-works">
    <div class="section-header reveal">
        <span class="eyebrow">HOW IT WORKS</span>
        <h2>Three steps to private checkout</h2>
    </div>
    <div class="steps-grid reveal">
        <div class="step-card">
            <div class="step-number">1</div>
            <h3>Create an invoice</h3>
            <p>Set an amount and expiry. VeilGate derives a fresh shielded address for it.</p>
        </div>
        <div class="step-card">
            <div class="step-number">2</div>
            <h3>Share the link or QR</h3>
            <p>The customer opens the page or scans the QR code with a Zcash wallet.</p>
        </div>
        <div class="step-card">
            <div class="step-number">3</div>
            <h3>Get paid</h3>
            <p>The scanner detects the payment with the viewing key and marks the invoice paid after confirmations.</p>
        </div>
    </div>
</section>

<section class="cta-section">
    <div class="cta-card reveal">
        <div class="cta-text">
            <h2>Ready to see it work?</h2>
            <p>Create a testnet invoice and pay it with a Zcash testnet wallet.</p>
            <a href="/demo" class="btn-primary" id="cta-demo-btn">Try the demo</a>
        </div>
        <div class="cta-shield">
            <img src="{shield_url}" alt="VeilGate Shield Mark" width="120" height="120">
        </div>
    </div>
</section>"#,
        check_icon = icons::CHECK,
        lock_icon = icons::LOCK,
        shield_icon = icons::SHIELD_CHECK,
        link_icon = icons::LINK,
        key_icon = icons::KEY,
        qr_icon = icons::QR_CODE,
    );

    layout_with("Privacy-First Zcash Merchant Checkout", &content, false, repo_url, None, None, has_session, true)
}

/// Renders Customer Payment Page (`GET /pay/{public_id}`).
pub fn render_pay_page<'a>(
    invoice: &Invoice,
    qr_svg: &str,
    status_label: impl Into<Cow<'a, str>>,
    status_class: &str,
    status_desc: &str,
    received_zatoshi: u64,
    zip321_uri: &str,
    repo_url: Option<&str>,
    has_session: bool,
    is_re_reading: bool,
) -> String {
    let status_label = status_label.into();
    let status_label_esc = esc(&status_label);
    let status_class_esc = esc(status_class);
    let status_desc_esc = esc(status_desc);
    let amount_formatted = esc(&format_zec_display(invoice.amount_zatoshi));
    let received_formatted = esc(&format_zec_display(received_zatoshi));
    let public_id_esc = esc(&invoice.public_id);
    let address_esc = esc(&invoice.address);
    let zip321_uri_esc = esc(zip321_uri);
    let expiry_utc = esc(&format_utc_timestamp(invoice.expires_at));

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let remaining_text = if invoice.status == InvoiceStatus::Pending && invoice.expires_at > now_secs {
        format!(" ({})", format_remaining_time(now_secs, invoice.expires_at))
    } else {
        String::new()
    };
    let remaining_text_esc = esc(&remaining_text);

    let faucet_help_html = if invoice.status == InvoiceStatus::Pending {
        r#"<details class="faucet-help" id="how-to-pay-section">
            <summary>How to pay on testnet</summary>
            <div class="faucet-help-content">
                <p>To pay this invoice on the Zcash testnet:</p>
                <ol>
                    <li><strong>Zcash testnet wallet:</strong> Use a wallet that supports the Zcash testnet and scan the QR code or click &ldquo;Open in wallet&rdquo;.</li>
                    <li><strong>No testnet wallet:</strong> Paste the invoice address into a public testnet faucet, for example <a href="https://faucet.testnet.valargroup.dev" target="_blank" rel="noopener noreferrer">faucet.testnet.valargroup.dev</a> or <a href="https://fauzec.com" target="_blank" rel="noopener noreferrer">fauzec.com</a>, which will pay the address directly (typical drips are 0.1 to 1 TAZ, so use small demo invoices).</li>
                </ol>
                <p class="form-help">These are third-party sites we do not control and that may be paused or rate limited.</p>
            </div>
        </details>"#
    } else {
        ""
    };

    let re_read_html = if is_re_reading {
        r#"<p class="form-help" id="showcase-re-read-notice">This example is being re-read from the chain after a restart</p>"#
    } else {
        ""
    };

    let content = format!(
        r#"<div class="container">
    <div class="checkout-card" id="pay-container" data-public-id="{public_id}">
        <div class="mockup-header">
            <span class="eyebrow">TESTNET INVOICE</span>
            <span class="status-pill {status_class}" id="pay-status-badge">{status_label}</span>
        </div>
        <h1 class="mockup-title">Complete your payment</h1>
        <p class="form-help" id="pay-status-desc">{status_desc}</p>
        {re_read_html}

        <div class="mockup-amount-box">
            <div class="form-help">Amount requested</div>
            <div class="mockup-amount" id="pay-requested-amount">{amount_formatted}</div>
            <div class="form-help">Amount confirmed received: <strong id="pay-received-amount">{received_formatted}</strong></div>
        </div>

        <div class="qr-box" id="pay-qr-code" aria-label="QR code for payment">
            {qr_svg}
        </div>

        <div class="hero-actions">
            <a href="{zip321_uri}" class="btn-primary" id="open-in-wallet-btn">
                {link_icon} <span>Open in wallet</span>
            </a>
            <button type="button" class="btn-secondary" id="copy-address-btn" data-copy-text="{address}" data-address="{address}" data-original-text="Copy address">
                {copy_icon} <span>Copy address</span>
            </button>
            <button type="button" class="btn-secondary" id="copy-link-btn" data-copy-text="{zip321_uri}" data-uri="{zip321_uri}" data-original-text="Copy payment link">
                {link_icon} <span>Copy payment link</span>
            </button>
        </div>
        <p class="form-help form-help-hint" id="wallet-hint">Opens a Zcash wallet app that supports payment links. If nothing happens, scan the QR code or copy the address.</p>

        {faucet_help_html}

        <div class="form-group">
            <label class="form-label" for="shielded-address-text">Shielded address</label>
            <div class="address-box" id="shielded-address-text">{address}</div>
        </div>

        <div class="check-row">
            <div class="check-item">{clock_icon} <span>Expires at: {expiry_utc}<span id="pay-expiry-remaining" data-expires-at="{expires_at}">{remaining_text}</span></span></div>
            <div class="check-item">{shield_icon} <span>Shielded address</span></div>
        </div>

        <div class="privacy-panel">
            <h4>Privacy Model &mdash; This Checkout</h4>
            <ul>
                <li><strong>What this page does NOT do:</strong> 0 third-party trackers, 0 external web fonts, 0 remote scripts, 0 analytics. Does not record your IP or store customer identities.</li>
                <li><strong>What the merchant sees:</strong> That this invoice was visited, and the payment amount and confirmation count once mined into a block. VeilGate's scanner reads compact blocks, which do not carry memos, so VeilGate neither reads nor stores memos. A holder of the viewing key could read memos by downloading full transactions. Fauzec's page states its payments carry a default receipt memo; VeilGate does not read it.</li>
                <li><strong>Network privacy:</strong> The merchant server sees HTTP connections to this invoice URL. Use Tor or a trusted VPN if you need network-level IP privacy against the host.</li>
                <li><strong>Pools &amp; receivers:</strong> The invoice address has an Orchard receiver; on the current network payments to it are recorded in the Ironwood pool.</li>
            </ul>
        </div>
    </div>
</div>"#,
        public_id = public_id_esc,
        address = address_esc,
        status_class = status_class_esc,
        status_label = status_label_esc,
        status_desc = status_desc_esc,
        amount_formatted = amount_formatted,
        received_formatted = received_formatted,
        qr_svg = qr_svg,
        zip321_uri = zip321_uri_esc,
        expiry_utc = expiry_utc,
        expires_at = invoice.expires_at,
        remaining_text = remaining_text_esc,
        faucet_help_html = faucet_help_html,
        link_icon = icons::LINK,
        copy_icon = icons::COPY,
        clock_icon = icons::CLOCK,
        shield_icon = icons::SHIELD_CHECK,
    );

    // Meta refresh fallback every 10 seconds for clients without JS
    layout("Complete Payment", &content, true, repo_url, None, Some(10), has_session)
}

/// Renders the Honest Privacy Model Page (`GET /privacy`).
pub fn render_privacy_page(repo_url: Option<&str>, has_session: bool) -> String {
    let content = format!(
        r#"<div class="container">
    <div class="checkout-card">
        <span class="eyebrow">HONEST PRIVACY MODEL</span>
        <h1>Privacy Model</h1>
        <p class="hero-subtext">VeilGate is designed for testnet shielded payments. Here is an honest, verifiable accounting of what is private and what is exposed.</p>

        <div class="privacy-panel">
            <h4>What a public observer sees</h4>
            <p>Public observers on the Zcash blockchain cannot see the sender, receiver or amount of a payment made from a shielded balance to a shielded address. Funds moved in from a transparent address are visible on-chain at the shielding step.</p>
        </div>

        <div class="privacy-panel">
            <h4>What the merchant server sees</h4>
            <p>The merchant server sees the amount and arrival time (block timestamp) of each payment. VeilGate's scanner reads compact blocks, which do not carry memos, so VeilGate neither reads nor stores memos. A holder of the viewing key could read memos by downloading full transactions. Fauzec's page states its payments carry a default receipt memo; VeilGate does not read it. The server holds an incoming viewing key: it can detect payments but cannot spend them. VeilGate stores no customer names, emails, IPs, or cookies.</p>
        </div>

        <div class="privacy-panel">
            <h4>What the lightwalletd operator sees</h4>
            <p>The lightwalletd operator sees the scanner server's IP address and which compact blocks it requests, but cannot tell which payments belong to the merchant, because trial decryption is performed locally by the scanner using the incoming viewing key.</p>
        </div>

        <div class="privacy-panel">
            <h4>What a visitor to the checkout page exposes</h4>
            <p>A visitor opening the checkout page connects to the merchant's server. The public invoice ID in the URL acts as a secret bearer token. If network-level surveillance exists (such as an ISP), the IP connecting to the checkout URL is visible unless Tor or a VPN is used. VeilGate makes 0 third-party requests: no CDNs, no web fonts, no external scripts, and no trackers.</p>
        </div>

        <div class="privacy-panel">
            <h4>Pools and receivers</h4>
            <p>Each invoice address has an Orchard receiver, and on the current network payments to it are recorded in the Ironwood pool.</p>
        </div>

        <div class="privacy-panel">
            <h4>Known limitations</h4>
            <ul>
                <li><strong>Testnet only:</strong> VeilGate operates strictly on Zcash testnet.</li>
                <li><strong>Reorganizations:</strong> Chain reorganizations are handled up to approximately 20 blocks.</li>
                <li><strong>No mempool detection:</strong> Payments are detected once mined into a block.</li>
                <li><strong>Single merchant:</strong> Designed for single-merchant operation.</li>
                <li><strong>Wallet compatibility:</strong> Customers require an up-to-date wallet aware of NU6.3 and Ironwood.</li>
            </ul>
        </div>
    </div>
</div>"#
    );

    layout("Privacy Model", &content, true, repo_url, None, None, has_session)
}

/// Renders the Demo Page (`GET /demo`).
pub fn render_demo_page(
    csrf_token: &str,
    error_msg: Option<&str>,
    repo_url: Option<&str>,
    has_session: bool,
    showcase_invoice: Option<&Invoice>,
) -> String {
    let error_html = if let Some(err) = error_msg {
        format!(r#"<div class="form-error" role="alert">{}</div>"#, esc(err))
    } else {
        String::new()
    };
    let csrf_token_esc = esc(csrf_token);

    let showcase_html = if let Some(showcase) = showcase_invoice {
        let label_text = showcase.label.as_deref().unwrap_or("Real faucet payment demonstration");
        format!(
            r#"<div class="checkout-card mb-4" id="showcase-card">
        <span class="eyebrow">SHOWCASE EXAMPLE</span>
        <h2>See a real completed payment</h2>
        <p class="hero-subtext">{}</p>
        <p class="form-help">This invoice was paid on the Zcash testnet with a faucet payment; this server detected it with its watch-only key.</p>
        <a href="/pay/{}" class="btn-primary" id="showcase-pay-link">See a real completed payment</a>
    </div>"#,
            esc(label_text),
            esc(&showcase.public_id),
        )
    } else {
        String::new()
    };

    let content = format!(
        r#"<div class="container">
    {showcase_html}
    <div class="checkout-card">
        <span class="eyebrow">TESTNET DEMO</span>
        <h1>Create a Testnet Invoice</h1>
        <p class="hero-subtext">Test VeilGate checkout in real-time. Enter an amount between 0.001 and 10 ZEC to derive a fresh shielded testnet address.</p>
        <p class="form-help demo-notice">This demo instance may reset. Invoices are not guaranteed to persist.</p>
        {error_html}
        <form method="POST" action="/demo" id="demo-form">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <div class="form-group">
                <label class="form-label" for="demo-amount">Amount (ZEC)</label>
                <input class="form-input" type="text" id="demo-amount" name="amount" value="0.01" placeholder="0.01" required>
                <div class="form-help">Allowed range: 0.001 to 10 ZEC (testnet)</div>
            </div>
            <div class="form-group">
                <label class="form-label" for="demo-validity">Validity (minutes)</label>
                <input class="form-input" type="number" id="demo-validity" name="validity_minutes" value="60" min="1" max="60" required>
                <div class="form-help">Maximum validity: 60 minutes</div>
            </div>
            <button type="submit" class="btn-primary" id="demo-submit-btn">Create Testnet Invoice</button>
        </form>
        <p class="form-help">Testnet faucets pay between 0.1 and 1 test coin; a 0.01 invoice is covered by any of them.</p>

        <details class="faucet-help" id="how-to-pay-section">
            <summary>How to pay on testnet</summary>
            <div class="faucet-help-content">
                <p>To test payment on the Zcash testnet:</p>
                <ol>
                    <li><strong>Zcash testnet wallet:</strong> Use a wallet that supports the Zcash testnet and scan the QR code or click &ldquo;Open in wallet&rdquo;.</li>
                    <li><strong>No testnet wallet:</strong> Paste the invoice address into a public testnet faucet, for example <a href="https://faucet.testnet.valargroup.dev" target="_blank" rel="noopener noreferrer">faucet.testnet.valargroup.dev</a> or <a href="https://fauzec.com" target="_blank" rel="noopener noreferrer">fauzec.com</a>, which will pay the address directly (typical drips are 0.1 to 1 TAZ, so use small demo invoices).</li>
                </ol>
                <p class="form-help">These are third-party sites we do not control and that may be paused or rate limited.</p>
            </div>
        </details>
    </div>
</div>"#,
        showcase_html = showcase_html,
        error_html = error_html,
        csrf_token = csrf_token_esc,
    );

    layout("Testnet Demo", &content, true, repo_url, Some(csrf_token), None, has_session)
}

/// Renders Merchant Login Page (`GET /merchant/login`).
pub fn render_login_page(csrf_token: &str, error_msg: Option<&str>, repo_url: Option<&str>) -> String {
    let error_html = if let Some(err) = error_msg {
        format!(r#"<div class="form-error" role="alert">{}</div>"#, esc(err))
    } else {
        String::new()
    };
    let csrf_token_esc = esc(csrf_token);

    let content = format!(
        r#"<div class="container">
    <div class="checkout-card">
        <span class="eyebrow">MERCHANT ACCESS</span>
        <h1>Merchant Login</h1>
        <p class="form-help">Authenticate to access the VeilGate merchant dashboard.</p>
        {error_html}
        <form method="POST" action="/merchant/login" id="login-form">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <div class="form-group">
                <label class="form-label" for="merchant-password">Password</label>
                <input class="form-input" type="password" id="merchant-password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn-primary" id="login-submit-btn">Sign in</button>
        </form>
    </div>
</div>"#,
        error_html = error_html,
        csrf_token = csrf_token_esc,
    );

    layout("Merchant Login", &content, true, repo_url, Some(csrf_token), None, false)
}

/// Renders Merchant Dashboard (`GET /merchant`).
pub fn render_merchant_dashboard(
    invoices: &[DashboardInvoiceItem],
    csrf_token: &str,
    error_msg: Option<&str>,
    repo_url: Option<&str>,
    filter: Option<&str>,
    scanner_health: Option<&ScannerHealth>,
) -> String {
    let error_html = if let Some(err) = error_msg {
        format!(r#"<div class="form-error" role="alert">{}</div>"#, esc(err))
    } else {
        String::new()
    };

    let (last_scanned_str, tip_str, behind_str, last_success_str, last_err_str) =
        if let Some(h) = scanner_health {
            let ls = h
                .last_scanned_block
                .map(|b| esc(&b.to_string()))
                .unwrap_or_else(|| "None".to_string());
            let tip = h
                .chain_tip
                .map(|t| esc(&t.to_string()))
                .unwrap_or_else(|| "None".to_string());
            let behind = esc(&h.blocks_behind.to_string());
            let ls_time = h
                .last_success_unix_time
                .map(|t| esc(&format_utc_timestamp(t)))
                .unwrap_or_else(|| "Never".to_string());
            let err = h
                .last_error_category
                .as_deref()
                .map(esc)
                .unwrap_or_else(|| "None".to_string());
            (ls, tip, behind, ls_time, err)
        } else {
            (
                "None".to_string(),
                "None".to_string(),
                "0".to_string(),
                "Never".to_string(),
                "None".to_string(),
            )
        };

    let scanner_panel_html = format!(
        r#"<div class="checkout-card mb-4" id="scanner-health-panel">
        <h3>Scanner</h3>
        <div class="scanner-grid">
            <div class="scanner-stat">
                <div class="scanner-stat-label">Last Scanned Block</div>
                <div class="scanner-stat-value" id="scanner-last-scanned">{last_scanned_str}</div>
            </div>
            <div class="scanner-stat">
                <div class="scanner-stat-label">Chain Tip</div>
                <div class="scanner-stat-value" id="scanner-chain-tip">{tip_str}</div>
            </div>
            <div class="scanner-stat">
                <div class="scanner-stat-label">Blocks Behind</div>
                <div class="scanner-stat-value" id="scanner-blocks-behind">{behind_str}</div>
            </div>
            <div class="scanner-stat">
                <div class="scanner-stat-label">Last Successful Scan</div>
                <div class="scanner-stat-value" id="scanner-last-success">{last_success_str}</div>
            </div>
            <div class="scanner-stat">
                <div class="scanner-stat-label">Last Error Category</div>
                <div class="scanner-stat-value" id="scanner-last-error">{last_err_str}</div>
            </div>
        </div>
    </div>"#
    );

    let csrf_token_esc = esc(csrf_token);
    let total_invoices = invoices.len();
    let total_volume_zatoshi: u64 = invoices.iter().map(|i| i.invoice.amount_zatoshi).sum();
    let total_paid_count = invoices
        .iter()
        .filter(|i| i.invoice.status == InvoiceStatus::Paid)
        .count();
    let total_paid_zatoshi: u64 = invoices
        .iter()
        .filter(|i| i.invoice.status == InvoiceStatus::Paid)
        .map(|i| i.received_zatoshi)
        .sum();

    let total_volume = esc(&format_zec_display(total_volume_zatoshi));
    let total_paid_volume = esc(&format_zec_display(total_paid_zatoshi));

    let current_filter = filter.unwrap_or("merchant");
    let filter_all_cls = if current_filter == "all" { "btn-secondary active-filter" } else { "btn-secondary" };
    let filter_merchant_cls = if current_filter == "merchant" { "btn-secondary active-filter" } else { "btn-secondary" };
    let filter_demo_cls = if current_filter == "demo" { "btn-secondary active-filter" } else { "btn-secondary" };

    let mut table_rows = String::new();
    for item in invoices {
        let inv = &item.invoice;
        let state_name = &item.payment_state;
        let state_class = match state_name.as_str() {
            "Paid" | "Paid late" => "status-paid",
            "Detected" => "status-detected",
            "Underpaid" => "status-underpaid",
            "Expired" => "status-expired",
            _ => "status-awaiting",
        };
        let status_badge = format!(
            r#"<span class="status-pill {}">{}</span>"#,
            state_class,
            esc(state_name)
        );

        let type_badge = if inv.is_showcase {
            r#"<span class="status-pill status-showcase">Showcase</span>"#
        } else if inv.is_demo {
            r#"<span class="status-pill status-demo">Demo</span>"#
        } else {
            r#"<span class="status-pill status-merchant">Merchant</span>"#
        };

        let public_id_esc = esc(&inv.public_id);
        let short_len = std::cmp::min(8, inv.public_id.len());
        let public_id_short_esc = esc(&inv.public_id[..short_len]);
        let amount_esc = esc(&format_zec_display(inv.amount_zatoshi));
        let received_esc = esc(&format_zec_display(item.received_zatoshi));
        let excess_esc = esc(&format_zec_display(item.excess_zatoshi));
        let created_utc = esc(&format_utc_timestamp(inv.created_at));

        table_rows.push_str(&format!(
            r#"<tr>
                <td><a href="/pay/{public_id}"><code>{public_id_short}</code></a></td>
                <td>{type_badge}</td>
                <td>{amount}</td>
                <td>{received}</td>
                <td>{excess}</td>
                <td>{status}</td>
                <td>{created_at}</td>
                <td><a href="/pay/{public_id}" class="btn-secondary">View pay page</a></td>
            </tr>"#,
            public_id = public_id_esc,
            public_id_short = public_id_short_esc,
            type_badge = type_badge,
            amount = amount_esc,
            received = received_esc,
            excess = excess_esc,
            status = status_badge,
            created_at = created_utc,
        ));
    }

    if table_rows.is_empty() {
        table_rows = r#"<tr><td colspan="8" class="form-help">No invoices found for this view.</td></tr>"#.to_string();
    }

    let content = format!(
        r#"<div class="container">
    <div class="dashboard-header">
        <div>
            <span class="eyebrow">MERCHANT DASHBOARD</span>
            <h1>Invoices</h1>
        </div>
        <form method="POST" action="/merchant/logout" id="logout-form">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <button type="submit" class="btn-secondary" id="logout-btn">Log out</button>
        </form>
    </div>

    {error_html}

    {scanner_panel_html}

    <div class="totals-grid">
        <div class="total-card">
            <div class="total-label">Total Invoices</div>
            <div class="total-value">{total_invoices}</div>
        </div>
        <div class="total-card">
            <div class="total-label">Total invoiced</div>
            <div class="total-value">{total_volume}</div>
        </div>
        <div class="total-card">
            <div class="total-label">Paid Invoices</div>
            <div class="total-value">{total_paid_count}</div>
        </div>
        <div class="total-card">
            <div class="total-label">Total Paid Volume</div>
            <div class="total-value">{total_paid_volume}</div>
        </div>
    </div>

    <div class="checkout-card mb-4">
        <h3>Create New Invoice</h3>
        <form method="POST" action="/merchant/invoices" id="create-invoice-form">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <div class="form-group">
                <label class="form-label" for="merchant-amount">Amount (ZEC)</label>
                <input class="form-input" type="text" id="merchant-amount" name="amount" placeholder="0.5" required>
            </div>
            <div class="form-group">
                <label class="form-label" for="merchant-validity">Validity (minutes)</label>
                <input class="form-input" type="number" id="merchant-validity" name="validity_minutes" value="30" min="1" max="1440" required>
            </div>
            <button type="submit" class="btn-primary" id="merchant-create-btn">Generate Invoice</button>
        </form>
    </div>

    <div class="filter-bar">
        <span class="form-help">Filter:</span>
        <a href="/merchant?filter=merchant" class="{filter_merchant_cls}" id="filter-merchant-btn">Merchant</a>
        <a href="/merchant?filter=all" class="{filter_all_cls}" id="filter-all-btn">All (Show demo)</a>
        <a href="/merchant?filter=demo" class="{filter_demo_cls}" id="filter-demo-btn">Demo</a>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Invoice ID</th>
                    <th>Type</th>
                    <th>Amount</th>
                    <th>Received</th>
                    <th>Excess</th>
                    <th>State</th>
                    <th>Created</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>
</div>"#,
        csrf_token = csrf_token_esc,
        total_volume = total_volume,
        total_paid_volume = total_paid_volume,
        scanner_panel_html = scanner_panel_html,
    );

    layout("Merchant Dashboard", &content, true, repo_url, Some(csrf_token), None, true)
}
