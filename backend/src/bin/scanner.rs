use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::time::sleep;
use tonic::transport::{ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::scanning::Nullifiers;
use zcash_protocol::consensus::Network;

use veilgate_backend::addresses::load_viewing_key;
use veilgate_backend::invoices::open_store;
use veilgate_backend::scanner::{
    build_scanning_keys, run_scan_pass, DEFAULT_CONFIRMATIONS,
};

#[derive(Parser, Debug)]
#[command(name = "scanner")]
#[command(about = "VeilGate Payment Scanner: monitors shielded testnet compact blocks for merchant payments")]
struct Cli {
    /// lightwalletd server gRPC endpoint URL over TLS
    #[arg(long, default_value = "https://testnet.zec.rocks:443")]
    url: String,

    /// Run a single scan pass and exit
    #[arg(long)]
    once: bool,

    /// Interval in seconds between background scan passes
    #[arg(long, default_value_t = 30)]
    interval_seconds: u64,

    /// Minimum confirmations required to mark an invoice as Paid
    #[arg(long, default_value_t = DEFAULT_CONFIRMATIONS)]
    confirmations: u32,

    /// Starting block height for initial scan (defaults to tip - 100)
    #[arg(long)]
    from_height: Option<u64>,

    /// Path to merchant viewing key file
    #[arg(long, default_value = ".veilgate/merchant-viewing-key.txt")]
    key_path: String,

    /// Path to VeilGate SQLite database
    #[arg(long, default_value = ".veilgate/veilgate.db")]
    db_path: String,

    /// Enable detailed error chains logging for local debugging (forbidden on hosted demo)
    #[arg(long, default_value_t = false)]
    debug_errors: bool,
}

fn resolve_file_path(relative: &str) -> PathBuf {
    let direct = Path::new(relative);
    if direct.exists() {
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

const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    if args.debug_errors {
        eprintln!("WARNING: --debug-errors is enabled. Full error chains will be logged. Do NOT use this flag on the hosted demo or production environments.");
    }

    let network = Network::TestNetwork;

    // Load merchant incoming viewing key from disk (never log or leak the key)
    let key_path = resolve_file_path(&args.key_path);
    if !key_path.exists() {
        return Err(anyhow!(
            "Merchant viewing key file not found at: {}. Please ensure the viewing key file exists.",
            key_path.display()
        ));
    }
    let uivk = load_viewing_key(&key_path, &network)
        .with_context(|| format!("Failed to load viewing key from {}", key_path.display()))?;

    // Build dual-pool scanning keys (Orchard + Ironwood)
    let scanning_keys = build_scanning_keys(&uivk)?;
    let nullifiers = Nullifiers::empty();

    // Open merchant invoice store
    let db_path = resolve_file_path(&args.db_path);
    let store = open_store(&db_path)
        .with_context(|| format!("Failed to open invoice database at {}", db_path.display()))?;

    // Configure lightwalletd server endpoint over TLS
    let tls = ClientTlsConfig::new().with_webpki_roots();
    let endpoint = Endpoint::from_shared(args.url.clone())
        .with_context(|| format!("Invalid lightwalletd URL: {}", args.url))?
        .tls_config(tls)
        .with_context(|| "Failed to configure TLS for endpoint")?;

    let mut client: Option<CompactTxStreamerClient<tonic::transport::Channel>> = None;
    let mut backoff = INITIAL_BACKOFF;

    println!(
        "Starting VeilGate payment scanner (testnet, confirmations: {})...",
        args.confirmations
    );

    loop {
        // Ensure gRPC client is connected; reconnect if needed
        if client.is_none() {
            match CompactTxStreamerClient::connect(endpoint.clone()).await {
                Ok(c) => {
                    client = Some(c);
                }
                Err(e) => {
                    let cat = "connect";
                    let _ = store.set_last_error_category(cat);
                    if args.debug_errors {
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
                    if args.once {
                        if args.debug_errors {
                            return Err(e).context("Failed to connect to lightwalletd server");
                        } else {
                            eprintln!("scan pass failed ({cat})");
                            std::process::exit(1);
                        }
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
            &store,
            &network,
            &scanning_keys,
            &nullifiers,
            &uivk,
            args.confirmations,
            args.from_height,
        )
        .await;

        match pass_res {
            Ok(summary) => {
                backoff = INITIAL_BACKOFF;
                println!(
                    "Scanned {} blocks ({}..={}), {} payments detected, {} invoices paid.",
                    summary.blocks_scanned,
                    summary.start_height,
                    summary.end_height,
                    summary.payments_detected,
                    summary.invoices_paid
                );
                if args.once {
                    break;
                }
                sleep(Duration::from_secs(args.interval_seconds)).await;
            }
            Err(err) => {
                client = None;
                let cat = err.kind.category();
                let _ = store.set_last_error_category(&cat);
                if args.debug_errors {
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
                if args.once {
                    if args.debug_errors {
                        if let Some(src) = err.source {
                            return Err(src).context(format!("scan pass failed ({cat})"));
                        } else {
                            return Err(anyhow!("scan pass failed ({cat})"));
                        }
                    } else {
                        eprintln!("scan pass failed ({cat})");
                        std::process::exit(1);
                    }
                }
                sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), MAX_BACKOFF);
            }
        }
    }

    Ok(())
}
