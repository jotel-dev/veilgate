//! VeilGate Payment Server binary.
//!
//! Provides the web checkout, merchant dashboard, status API, and runs the in-process payment scanner.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::time::sleep;
use tonic::transport::{ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::scanning::Nullifiers;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::Network;

use veilgate_backend::addresses::resolve_viewing_key;
use veilgate_backend::invoices::open_store;
use veilgate_backend::scanner::{
    build_scanning_keys, retry_with_delays, run_bounded_scan_pass, run_scan_pass,
    DEFAULT_CONFIRMATIONS, SHOWCASE_RETRY_DELAYS,
};
use veilgate_backend::web::auth::SessionManager;
use veilgate_backend::web::rate_limit::RateLimiter;
use veilgate_backend::web::{build_app, hash_password, AppState};

#[derive(Parser, Debug)]
#[command(name = "server")]
#[command(about = "VeilGate Payment Server: shielded checkout, web dashboard, and in-process scanner")]
struct Cli {
    /// Socket address to listen on
    #[arg(long, env = "VEILGATE_LISTEN")]
    listen: Option<SocketAddr>,

    /// lightwalletd server gRPC endpoint URL over TLS
    #[arg(long, env = "VEILGATE_LIGHTWALLETD_URL")]
    lightwalletd_url: Option<String>,

    /// Legacy lightwalletd server gRPC endpoint URL over TLS
    #[arg(long, env = "VEILGATE_URL")]
    url: Option<String>,

    /// Minimum confirmations required to mark an invoice as Paid
    #[arg(long, env = "VEILGATE_CONFIRMATIONS", default_value_t = DEFAULT_CONFIRMATIONS)]
    confirmations: u32,

    /// Path to merchant viewing key file
    #[arg(long, env = "VEILGATE_KEY_PATH", default_value = ".veilgate/merchant-viewing-key.txt")]
    key_path: String,

    /// Path to VeilGate SQLite database
    #[arg(long, env = "VEILGATE_DB_PATH", default_value = ".veilgate/veilgate.db")]
    db_path: String,

    /// Optional repository URL to display GitHub icon link in footer
    #[arg(long, env = "VEILGATE_REPO_URL")]
    repo_url: Option<String>,

    /// Enable demo mode (/demo endpoint for testnet invoices)
    #[arg(long)]
    demo: bool,

    /// Header to trust for client IP when behind a reverse proxy (e.g. x-forwarded-for, fly-client-ip)
    #[arg(long, env = "VEILGATE_TRUSTED_PROXY_HEADER")]
    trusted_proxy_header: Option<String>,

    /// Prompts for a password, outputs the Argon2id hash, and exits
    #[arg(long)]
    hash_password: bool,

    /// Enable detailed error chains logging for local debugging (forbidden on hosted demo)
    #[arg(long, env = "VEILGATE_DEBUG_ERRORS", default_value_t = false)]
    debug_errors: bool,
}

fn resolve_file_path(relative: &str) -> PathBuf {
    let direct = Path::new(relative);
    if direct.is_absolute() || direct.exists() {
        return direct.to_path_buf();
    }
    let parent = Path::new("..").join(relative);
    if parent.exists() {
        return parent;
    }
    if Path::new("../.veilgate").exists() {
        parent
    } else {
        direct.to_path_buf()
    }
}

fn resolve_listen_address(cli_listen: Option<SocketAddr>) -> Result<SocketAddr> {
    let listen_passed_on_cli = std::env::args().any(|a| a == "--listen" || a.starts_with("--listen="));
    let port_env = std::env::var("PORT").ok();
    let listen_env = std::env::var("VEILGATE_LISTEN").ok();
    veilgate_backend::web::handlers::resolve_listen_address_from_config(
        cli_listen,
        port_env.as_deref(),
        listen_env.as_deref(),
        listen_passed_on_cli,
    )
}

fn load_server_viewing_key(
    key_path_arg: &str,
    network: &Network,
) -> Result<UnifiedIncomingViewingKey> {
    let env_key = std::env::var("VEILGATE_VIEWING_KEY").ok();
    let key_path = resolve_file_path(key_path_arg);
    resolve_viewing_key(env_key.as_deref(), &key_path, network)
}

const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const SCAN_INTERVAL: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    if args.debug_errors {
        eprintln!("WARNING: --debug-errors is enabled. Full error chains will be logged. Do NOT use this flag on the hosted demo or production environments.");
    }

    // Check if --hash-password mode was requested
    if args.hash_password {
        let password = match rpassword::prompt_password("Enter merchant password: ") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .context("Failed to read password from stdin")?;
                line.trim().to_string()
            }
        };
        if password.is_empty() {
            eprintln!("Password cannot be empty.");
            std::process::exit(1);
        }
        let hash = hash_password(&password)
            .context("Failed to hash password")?;
        println!("{}", hash);
        return Ok(());
    }

    let network = Network::TestNetwork;

    // Load merchant incoming viewing key (never log or leak the key)
    let uivk = load_server_viewing_key(&args.key_path, &network)?;

    // Open merchant invoice store
    let db_path = resolve_file_path(&args.db_path);
    let store = Arc::new(
        open_store(&db_path)
            .with_context(|| format!("Failed to open invoice database at {}", db_path.display()))?,
    );

    // Seed showcase invoice if configured and database is brand new and empty
    let showcase_cfg = if let Ok(showcase_raw) = std::env::var("VEILGATE_SHOWCASE") {
        veilgate_backend::invoices::parse_showcase_env(&showcase_raw)
    } else {
        None
    };

    let showcase_to_scan = if let Some(ref cfg) = showcase_cfg {
        match store.init_showcase_invoice(&uivk, &network, cfg) {
            Ok(true) => Some((cfg.scan_from_height, cfg.scan_to_height)),
            Ok(false) => None,
            Err(e) => {
                eprintln!("Notice: Failed to initialize showcase invoice: {e}");
                None
            }
        }
    } else {
        None
    };

    let password_hash = std::env::var("VEILGATE_PASSWORD_HASH").ok();
    if password_hash.is_none() {
        eprintln!("Notice: VEILGATE_PASSWORD_HASH not set. Merchant dashboard login will be disabled until set.");
    }

    let listen_addr = resolve_listen_address(args.listen)?;

    let demo_enabled = args.demo
        || std::env::var("VEILGATE_DEMO")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let scanner_url = args
        .lightwalletd_url
        .or(args.url)
        .unwrap_or_else(|| "https://testnet.zec.rocks:443".to_string());

    // Build application state
    let is_localhost = listen_addr.ip().is_loopback();
    let app_state = AppState {
        store: Arc::clone(&store),
        uivk: Arc::new(uivk.clone()),
        network,
        confirmations: args.confirmations,
        repo_url: args.repo_url.clone(),
        demo_enabled,
        password_hash,
        session_manager: Arc::new(SessionManager::new()),
        rate_limiter: Arc::new(RateLimiter::new()),
        is_localhost,
        trusted_proxy_header: args.trusted_proxy_header.clone(),
    };

    // Spawn background payment scanner task
    let scanner_store = Arc::clone(&store);
    let scanner_uivk = uivk.clone();
    let scanner_url_clone = scanner_url.clone();
    let scanner_confs = args.confirmations;

    // Spawn background task to delete unpaid demo invoices expired for more than 24 hours
    let demo_store = Arc::clone(&store);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let _ = demo_store.prune_expired_demo_invoices(86400);
        }
    });

    // If the showcase invoice was seeded on an empty database, run ONE bounded pass in its own
    // task so it never holds up the normal scanner loop below. Failed attempts are retried on
    // a fixed schedule; only a generic error category is logged.
    if let Some((from_h, to_h)) = showcase_to_scan {
        let sc_store = Arc::clone(&store);
        let sc_uivk = uivk.clone();
        let sc_url = scanner_url.clone();
        let sc_confs = args.confirmations;
        tokio::spawn(async move {
            let Ok(scanning_keys) = build_scanning_keys(&sc_uivk) else {
                eprintln!("showcase scan could not start");
                return;
            };
            let nullifiers = Nullifiers::empty();
            let tls = ClientTlsConfig::new().with_webpki_roots();
            let Some(endpoint) = Endpoint::from_shared(sc_url)
                .ok()
                .and_then(|ep| ep.tls_config(tls).ok())
            else {
                eprintln!("showcase scan could not start");
                return;
            };
            let result = retry_with_delays(
                &SHOWCASE_RETRY_DELAYS,
                || async {
                    let mut c = CompactTxStreamerClient::connect(endpoint.clone())
                        .await
                        .map_err(|_| "connect".to_string())?;
                    run_bounded_scan_pass(
                        &mut c,
                        &sc_store,
                        &network,
                        &scanning_keys,
                        &nullifiers,
                        &sc_uivk,
                        sc_confs,
                        from_h,
                        to_h,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| e.kind.category())
                },
                sleep,
                |attempt, cat: &String| {
                    eprintln!("showcase scan attempt {attempt} failed ({cat})");
                },
            )
            .await;
            if result.is_err() {
                eprintln!("showcase scan failed after all retry attempts; the normal scanner continues");
            }
        });
    }


    let debug_errors = args.debug_errors;
    tokio::spawn(async move {
        let scanning_keys = match build_scanning_keys(&scanner_uivk) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Scanner background task initialization error: {e}");
                return;
            }
        };
        let nullifiers = Nullifiers::empty();

        let tls = ClientTlsConfig::new().with_webpki_roots();
        let endpoint = match Endpoint::from_shared(scanner_url_clone) {
            Ok(ep) => match ep.tls_config(tls) {
                Ok(configured) => configured,
                Err(e) => {
                    eprintln!("Scanner background task TLS configuration error: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("Scanner background task endpoint error: {e}");
                return;
            }
        };

        // Give the web server a short moment to start listening first
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client: Option<CompactTxStreamerClient<tonic::transport::Channel>> = None;
        let mut backoff = INITIAL_BACKOFF;

        loop {
            if client.is_none() {
                match CompactTxStreamerClient::connect(endpoint.clone()).await {
                    Ok(c) => {
                        client = Some(c);
                    }
                    Err(e) => {
                        let cat = "connect";
                        let _ = scanner_store.set_last_error_category(cat);
                        if debug_errors {
                            eprintln!(
                                "scan pass failed ({cat}), retrying in {} seconds: {e:?}",
                                backoff.as_secs()
                            );
                        } else {
                            eprintln!(
                                "scan pass failed ({cat}), retrying in {} seconds",
                                backoff.as_secs()
                            );
                        }
                        sleep(backoff).await;
                        backoff = std::cmp::min(backoff.saturating_mul(2), MAX_BACKOFF);
                        continue;
                    }
                }
            }

            let cl = client.as_mut().expect("client verified Some above");
            let pass_res = run_scan_pass(
                cl,
                &scanner_store,
                &network,
                &scanning_keys,
                &nullifiers,
                &scanner_uivk,
                scanner_confs,
                None,
            )
            .await;

            match pass_res {
                Ok(_summary) => {
                    backoff = INITIAL_BACKOFF;
                    sleep(SCAN_INTERVAL).await;
                }
                Err(err) => {
                    client = None;
                    let cat = err.kind.category();
                    let _ = scanner_store.set_last_error_category(&cat);
                    if debug_errors {
                        if let Some(src) = &err.source {
                            eprintln!(
                                "scan pass failed ({cat}), retrying in {} seconds: {src:?}",
                                backoff.as_secs()
                            );
                        } else {
                            eprintln!(
                                "scan pass failed ({cat}), retrying in {} seconds",
                                backoff.as_secs()
                            );
                        }
                    } else {
                        eprintln!(
                            "scan pass failed ({cat}), retrying in {} seconds",
                            backoff.as_secs()
                        );
                    }
                    sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), MAX_BACKOFF);
                }
            }
        }
    });

    let router = build_app(app_state);
    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(orig_err) => {
            let socket = if listen_addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            let _ = socket.set_reuseaddr(true);
            match socket.bind(listen_addr) {
                Ok(_) => socket.listen(1024)?,
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to bind to {}: {} (socket error: {})",
                        listen_addr,
                        orig_err,
                        e
                    ));
                }
            }
        }
    };

    let bound_addr = listener.local_addr()?;
    println!("VeilGate listening on http://{}", bound_addr);

    let cursor_str = match store.get_last_scanned_height()? {
        Some(h) => h.to_string(),
        None => "none".to_string(),
    };
    let behind = match (store.get_last_scanned_height()?, store.get_chain_tip()?) {
        (Some(c), Some(t)) => t.saturating_sub(c),
        _ => 0,
    };
    println!("Scan cursor: {}, tip behind: {}", cursor_str, behind);

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
