//! Server-rendered HTML templates for VeilGate.
//!
//! Hard constraints:
//! - No inline styles (`style="..."` forbidden by CSP)
//! - No inline scripts (`<script>...</script>` without src forbidden by CSP)
//! - No third-party assets, fonts, or scripts
//! - No emojis anywhere in the markup
//! - Mobile-first responsive structure

use std::borrow::Cow;
use crate::web::amount::format_zec_display;
use crate::web::icons;
use crate::invoices::Invoice;

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

/// Base HTML layout wrapper.
pub fn layout(
    title: &str,
    content: &str,
    show_testnet_banner: bool,
    repo_url: Option<&str>,
    csrf_token: Option<&str>,
    meta_refresh_seconds: Option<u32>,
    has_session: bool,
) -> String {
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
    <link rel="stylesheet" href="/static/style.css">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <script src="/static/app.js" defer></script>
</head>
<body>
    {testnet_bar}
    <header class="site-header">
        <div class="header-inner">
            <a href="/" class="logo-container" aria-label="VeilGate Home">
                <img src="/static/logo-light.png" class="logo-light" alt="VeilGate" width="130" height="38">
                <img src="/static/logo-dark.png" class="logo-dark" alt="VeilGate" width="130" height="38">
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
    <footer class="site-footer">
        <div class="footer-inner">
            <div class="footer-brand">
                <a href="/" class="logo-container" aria-label="VeilGate Home">
                    <img src="/static/logo-light.png" class="logo-light" alt="VeilGate" width="110" height="32">
                    <img src="/static/logo-dark.png" class="logo-dark" alt="VeilGate" width="110" height="32">
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
    let content = format!(
        r#"<section class="hero-section">
    <div class="hero-grid">
        <div class="hero-content">
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
        <div class="hero-card-wrapper">
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
    <div class="features-grid">
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

<section class="band-section">
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
    <div class="section-header">
        <span class="eyebrow">HOW IT WORKS</span>
        <h2>Three steps to private checkout</h2>
    </div>
    <div class="steps-grid">
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
    <div class="cta-card">
        <div class="cta-text">
            <h2>Ready to see it work?</h2>
            <p>Create a testnet invoice and pay it with a Zcash testnet wallet.</p>
            <a href="/demo" class="btn-primary" id="cta-demo-btn">Try the demo</a>
        </div>
        <div class="cta-shield">
            <img src="/static/shield-mark.png" alt="VeilGate Shield Mark" width="120" height="120">
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

    layout("Privacy-First Zcash Merchant Checkout", &content, false, repo_url, None, None, has_session)
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
    let expiry_str = esc(&format!("Unix {}", invoice.expires_at));

    let content = format!(
        r#"<div class="container">
    <div class="checkout-card" id="pay-container" data-public-id="{public_id}">
        <div class="mockup-header">
            <span class="eyebrow">TESTNET INVOICE</span>
            <span class="status-pill {status_class}" id="pay-status-badge">{status_label}</span>
        </div>
        <h1 class="mockup-title">Complete your payment</h1>
        <p class="form-help" id="pay-status-desc">{status_desc}</p>

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
            <button type="button" class="btn-secondary" id="copy-address-btn" data-address="{address}" data-original-text="Copy address">
                {copy_icon} <span>Copy address</span>
            </button>
        </div>

        <div class="form-group">
            <label class="form-label" for="shielded-address-text">Shielded Orchard address</label>
            <div class="address-box" id="shielded-address-text">{address}</div>
        </div>

        <div class="check-row">
            <div class="check-item">{clock_icon} <span>Expires at: {expiry_str}</span></div>
            <div class="check-item">{shield_icon} <span>Orchard shielded pool</span></div>
        </div>

        <div class="privacy-panel">
            <h4>Privacy Model &mdash; This Checkout</h4>
            <ul>
                <li><strong>What this page does NOT do:</strong> 0 third-party trackers, 0 external web fonts, 0 remote scripts, 0 analytics. Does not record your IP or store customer identities.</li>
                <li><strong>What the merchant sees:</strong> That this invoice was visited, the payment amount and confirmation count once mined into a block, and any memo included by your wallet.</li>
                <li><strong>Network privacy:</strong> The merchant server sees HTTP connections to this invoice URL. Use Tor or a trusted VPN if you need network-level IP privacy against the host.</li>
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
        expiry_str = expiry_str,
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
            <p>The merchant server sees the amount and arrival time (block timestamp) of each payment, and any memo the customer's wallet includes (VeilGate does not request a memo). The server holds an incoming viewing key: it can detect payments but cannot spend them. VeilGate stores no customer names, emails, IPs, or cookies.</p>
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
pub fn render_demo_page(csrf_token: &str, error_msg: Option<&str>, repo_url: Option<&str>, has_session: bool) -> String {
    let error_html = if let Some(err) = error_msg {
        format!(r#"<div class="form-error" role="alert">{}</div>"#, esc(err))
    } else {
        String::new()
    };
    let csrf_token_esc = esc(csrf_token);

    let content = format!(
        r#"<div class="container">
    <div class="checkout-card">
        <span class="eyebrow">TESTNET DEMO</span>
        <h1>Create a Testnet Invoice</h1>
        <p class="hero-subtext">Test VeilGate checkout in real-time. Enter an amount between 0.001 and 10 ZEC to derive a fresh shielded Orchard testnet address.</p>
        {error_html}
        <form method="POST" action="/demo" id="demo-form">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <div class="form-group">
                <label class="form-label" for="demo-amount">Amount (ZEC)</label>
                <input class="form-input" type="text" id="demo-amount" name="amount" placeholder="1.5" required>
                <div class="form-help">Allowed range: 0.001 to 10 ZEC (testnet)</div>
            </div>
            <div class="form-group">
                <label class="form-label" for="demo-validity">Validity (minutes)</label>
                <input class="form-input" type="number" id="demo-validity" name="validity_minutes" value="15" min="1" max="60" required>
                <div class="form-help">Maximum validity: 60 minutes</div>
            </div>
            <button type="submit" class="btn-primary" id="demo-submit-btn">Create Testnet Invoice</button>
        </form>
    </div>
</div>"#,
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
    invoices: &[Invoice],
    csrf_token: &str,
    error_msg: Option<&str>,
    repo_url: Option<&str>,
    filter: Option<&str>,
) -> String {
    let error_html = if let Some(err) = error_msg {
        format!(r#"<div class="form-error" role="alert">{}</div>"#, esc(err))
    } else {
        String::new()
    };

    let csrf_token_esc = esc(csrf_token);
    let total_invoices = invoices.len();
    let total_volume_zatoshi: u64 = invoices.iter().map(|i| i.amount_zatoshi).sum();
    let total_paid_count = invoices.iter().filter(|i| i.status == crate::invoices::InvoiceStatus::Paid).count();
    let total_paid_zatoshi: u64 = invoices
        .iter()
        .filter(|i| i.status == crate::invoices::InvoiceStatus::Paid)
        .map(|i| i.amount_zatoshi)
        .sum();

    let total_volume = esc(&format_zec_display(total_volume_zatoshi));
    let total_paid_volume = esc(&format_zec_display(total_paid_zatoshi));

    let current_filter = filter.unwrap_or("merchant");
    let filter_all_cls = if current_filter == "all" { "btn-secondary active-filter" } else { "btn-secondary" };
    let filter_merchant_cls = if current_filter == "merchant" { "btn-secondary active-filter" } else { "btn-secondary" };
    let filter_demo_cls = if current_filter == "demo" { "btn-secondary active-filter" } else { "btn-secondary" };

    let mut table_rows = String::new();
    for inv in invoices {
        let status_badge = match inv.status {
            crate::invoices::InvoiceStatus::Paid => {
                if inv.is_late {
                    r#"<span class="status-pill status-paid">Paid (late)</span>"#
                } else {
                    r#"<span class="status-pill status-paid">Paid</span>"#
                }
            }
            crate::invoices::InvoiceStatus::Pending => {
                r#"<span class="status-pill status-awaiting">Pending</span>"#
            }
            crate::invoices::InvoiceStatus::Expired => {
                r#"<span class="status-pill status-expired">Expired</span>"#
            }
        };

        let type_badge = if inv.is_demo {
            r#"<span class="status-pill status-demo">Demo</span>"#
        } else {
            r#"<span class="status-pill status-merchant">Merchant</span>"#
        };

        let public_id_esc = esc(&inv.public_id);
        let short_len = std::cmp::min(8, inv.public_id.len());
        let public_id_short_esc = esc(&inv.public_id[..short_len]);
        let amount_esc = esc(&format_zec_display(inv.amount_zatoshi));

        table_rows.push_str(&format!(
            r#"<tr>
                <td><a href="/pay/{public_id}"><code>{public_id_short}</code></a></td>
                <td>{type_badge}</td>
                <td>{amount}</td>
                <td>{status}</td>
                <td>Unix {created_at}</td>
                <td><a href="/pay/{public_id}" class="btn-secondary">View pay page</a></td>
            </tr>"#,
            public_id = public_id_esc,
            public_id_short = public_id_short_esc,
            type_badge = type_badge,
            amount = amount_esc,
            status = status_badge,
            created_at = inv.created_at,
        ));
    }

    if table_rows.is_empty() {
        table_rows = r#"<tr><td colspan="6" class="form-help">No invoices found for this view.</td></tr>"#.to_string();
    }

    let content = format!(
        r#"<div class="container">
    <div class="mockup-header">
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
                    <th>Status</th>
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
    );

    layout("Merchant Dashboard", &content, true, repo_url, Some(csrf_token), None, true)
}
