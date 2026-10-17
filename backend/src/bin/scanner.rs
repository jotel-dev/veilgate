use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::time::sleep;
use tonic::transport::{ClientTlsConfig, Endpoint};
use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, Empty};
use zcash_client_backend::scanning::Nullifiers;
use zcash_protocol::consensus::Network;

use veilgate_backend::addresses::load_viewing_key;
use veilgate_backend::invoices::open_store;
use veilgate_backend::scanner::{
    apply_detected, build_scanning_keys, check_and_rollback_reorg, scan_compact_block,
    DEFAULT_CONFIRMATIONS, DEFAULT_LOOKBACK_BLOCKS, DEFAULT_REORG_DEPTH,
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

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

const PASS_TIMEOUT: Duration = Duration::from_secs(60);
const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);

async fn run_scan_pass(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    store: &veilgate_backend::invoices::Store,
    network: &Network,
    scanning_keys: &zcash_client_backend::scanning::ScanningKeys<u32, u32>,
    nullifiers: &Nullifiers<u32>,
    uivk: &zcash_keys::keys::UnifiedIncomingViewingKey,
    confirmations: u32,
    from_height: Option<u64>,
) -> Result<()> {
    // Query server chain tip and verify network
    let info = client
        .get_lightd_info(tonic::Request::new(Empty {}))
        .await
        .with_context(|| "Failed to query get_lightd_info from server")?
        .into_inner();

    if info.chain_name != "test" {
        return Err(anyhow!(
            "Connected server chain is '{}', but TESTNET ('test') is strictly required",
            info.chain_name
        ));
    }

    let tip = info.block_height;
    let last_scanned = store.get_last_scanned_height()?;

    let start_height = match last_scanned {
        Some(last) => {
            if let Some(explicit) = from_height {
                if last < explicit {
                    explicit
                } else {
                    last.saturating_sub(DEFAULT_REORG_DEPTH)
                }
            } else {
                last.saturating_sub(DEFAULT_REORG_DEPTH)
            }
        }
        None => from_height.unwrap_or_else(|| tip.saturating_sub(DEFAULT_LOOKBACK_BLOCKS)),
    };

    let end_height = tip;

    if start_height > end_height {
        // Nothing new to scan; apply empty batch to update confirmation thresholds if tip advanced
        let _ = apply_detected(store, &[], tip, confirmations)?;
    } else {
        let range = BlockRange {
            start: Some(BlockId {
                height: start_height,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end_height,
                hash: vec![],
            }),
            pool_types: vec![],
        };

        let mut stream = client
            .get_block_range(tonic::Request::new(range))
            .await
            .with_context(|| {
                format!(
                    "Failed to request block range [{}..={}] from lightwalletd",
                    start_height, end_height
                )
            })?
            .into_inner();

        let mut blocks_scanned: u64 = 0;
        let mut detected_notes = Vec::new();
        let mut prior_metadata: Option<BlockMetadata> = None;
        let mut current_block_hashes = Vec::new();

        while let Some(block) = stream
            .message()
            .await
            .with_context(|| "Error receiving compact block from stream")?
        {
            let height = block.height;
            let hash_hex = hex_encode(&block.hash);
            current_block_hashes.push((height, hash_hex));

            let (notes, metadata) = scan_compact_block(
                network,
                block,
                scanning_keys,
                nullifiers,
                prior_metadata.as_ref(),
                uivk,
            )?;

            detected_notes.extend(notes);
            prior_metadata = Some(metadata);
            blocks_scanned += 1;
        }

        // Check for reorganization and rollback if block hashes differ
        let _ = check_and_rollback_reorg(store, &current_block_hashes)?;

        // Apply detected notes to database
        let result = apply_detected(store, &detected_notes, tip, confirmations)?;

        // Update scan cursor in invoice_meta only after full pass success
        store.set_last_scanned_height(end_height)?;

        // Privacy rule: Never log addresses, txids, amounts, or keys. Print counts only.
        println!(
            "Scanned {} blocks ({}..={}), {} payments detected, {} invoices paid.",
            blocks_scanned, start_height, end_height, result.payments_detected, result.invoices_paid
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
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
                    if args.once {
                        return Err(e).context("Failed to connect to lightwalletd server");
                    }
                    eprintln!(
                        "scan pass failed, retrying in {} seconds",
                        backoff.as_secs()
                    );
                    sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), MAX_BACKOFF);
                    continue;
                }
            }
        }

        let cl = client.as_mut().expect("client verified Some above");

        let pass_res = tokio::time::timeout(
            PASS_TIMEOUT,
            run_scan_pass(
                cl,
                &store,
                &network,
                &scanning_keys,
                &nullifiers,
                &uivk,
                args.confirmations,
                args.from_height,
            ),
        )
        .await;

        match pass_res {
            Ok(Ok(())) => {
                backoff = INITIAL_BACKOFF;
                if args.once {
                    break;
                }
                sleep(Duration::from_secs(args.interval_seconds)).await;
            }
            Ok(Err(e)) => {
                if args.once {
                    return Err(e);
                }
                client = None;
                eprintln!(
                    "scan pass failed, retrying in {} seconds",
                    backoff.as_secs()
                );
                sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), MAX_BACKOFF);
            }
            Err(_elapsed) => {
                if args.once {
                    return Err(anyhow!(
                        "Scan pass timed out after {} seconds",
                        PASS_TIMEOUT.as_secs()
                    ));
                }
                client = None;
                eprintln!(
                    "scan pass failed, retrying in {} seconds",
                    backoff.as_secs()
                );
                sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), MAX_BACKOFF);
            }
        }
    }

    Ok(())
}
