use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tonic::transport::{ClientTlsConfig, Endpoint};
use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, Empty};
use zcash_client_backend::scanning::{scan_block, Nullifiers, ScanningKey, ScanningKeys};
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};

/// Number of blocks to scan per range.
const NUM_BLOCKS_TO_SCAN: u64 = 500;

#[derive(Parser, Debug)]
#[command(name = "scan_spike")]
#[command(about = "Feasibility experiment: scan Zcash testnet compact blocks with IVK only for Orchard and Ironwood pools")]
struct Cli {
    /// lightwalletd server gRPC endpoint URL over TLS
    #[arg(long, default_value = "https://testnet.zec.rocks:443")]
    url: String,
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

#[allow(dead_code)]
#[derive(Debug)]
struct ScanStats {
    range_label: String,
    start_height: u64,
    end_height: u64,
    blocks_scanned: u64,
    orchard_outputs_examined: u64,
    orchard_notes_found: u64,
    ironwood_outputs_examined: u64,
    ironwood_notes_found: u64,
    elapsed: std::time::Duration,
}

async fn scan_block_range(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    network: &Network,
    scanning_keys: &ScanningKeys<u32, u32>,
    nullifiers: &Nullifiers<u32>,
    range_label: &str,
    start_height: u64,
    end_height: u64,
) -> Result<ScanStats> {
    println!("\n==================================================");
    println!(
        "Scanning [{}]: range [{}..={}] ({} blocks)...",
        range_label,
        start_height,
        end_height,
        end_height - start_height + 1
    );
    println!("==================================================");

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

    let start_time = Instant::now();
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
    let mut orchard_outputs_examined: u64 = 0;
    let mut orchard_notes_found: u64 = 0;
    let mut ironwood_outputs_examined: u64 = 0;
    let mut ironwood_notes_found: u64 = 0;
    let mut prior_metadata: Option<BlockMetadata> = None;

    while let Some(block) = stream
        .message()
        .await
        .with_context(|| "Error receiving compact block from stream")?
    {
        let height = block.height;

        // Count Orchard and Ironwood outputs (actions) in all transactions of this block
        for tx in &block.vtx {
            orchard_outputs_examined += tx.actions.len() as u64;
            ironwood_outputs_examined += tx.ironwood_actions.len() as u64;
        }

        // Scan compact block using zcash_client_backend::scanning::scan_block
        let scanned = scan_block(
            network,
            block,
            scanning_keys,
            nullifiers,
            prior_metadata.as_ref(),
        )
        .map_err(|e| anyhow!("Scan error at block height {}: {:?}", height, e))?;

        // Examine decrypted notes across both pools
        for tx in scanned.transactions() {
            for output in tx.orchard_outputs() {
                orchard_notes_found += 1;
                let (note, pool) = output.note();
                let val_zat = note.value().inner();
                let recip = note.recipient();
                let ua = UnifiedAddress::from_receivers(Some(recip), None, None)
                    .ok_or_else(|| anyhow!("Failed to construct UnifiedAddress from Orchard receiver"))?;
                let addr_str = ua.encode(network);
                println!(
                    "  [ORCHARD NOTE FOUND] Block {}: Value = {} zatoshis ({} ZEC), Pool = {:?}, Version = {:?}, Address = {}",
                    height,
                    val_zat,
                    val_zat as f64 / 100_000_000.0,
                    pool,
                    note.version(),
                    addr_str
                );
            }

            for output in tx.ironwood_outputs() {
                ironwood_notes_found += 1;
                let (note, pool) = output.note();
                let val_zat = note.value().inner();
                let recip = note.recipient();
                let ua = UnifiedAddress::from_receivers(Some(recip), None, None)
                    .ok_or_else(|| anyhow!("Failed to construct UnifiedAddress from Ironwood/Orchard receiver"))?;
                let addr_str = ua.encode(network);
                println!(
                    "  [IRONWOOD NOTE FOUND] Block {}: Value = {} zatoshis ({} ZEC), Pool = {:?}, Version = {:?}, Address = {}",
                    height,
                    val_zat,
                    val_zat as f64 / 100_000_000.0,
                    pool,
                    note.version(),
                    addr_str
                );
            }
        }

        prior_metadata = Some(scanned.to_block_metadata());
        blocks_scanned += 1;
    }

    let elapsed = start_time.elapsed();

    println!("\n--- Scan Results for [{}] ---", range_label);
    println!("Blocks scanned:              {}", blocks_scanned);
    println!("Orchard outputs examined:    {}", orchard_outputs_examined);
    println!("Orchard notes found:         {}", orchard_notes_found);
    println!("Ironwood outputs examined:   {}", ironwood_outputs_examined);
    println!("Ironwood notes found:        {}", ironwood_notes_found);
    println!("Elapsed time:                {:.2?}", elapsed);
    if blocks_scanned > 0 {
        let ms_per_block = elapsed.as_millis() as f64 / blocks_scanned as f64;
        println!("Average speed:               {:.2} ms/block", ms_per_block);
    }

    Ok(ScanStats {
        range_label: range_label.to_string(),
        start_height,
        end_height,
        blocks_scanned,
        orchard_outputs_examined,
        orchard_notes_found,
        ironwood_outputs_examined,
        ironwood_notes_found,
        elapsed,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let network = Network::TestNetwork;

    // Load merchant incoming viewing key from disk using addresses::load_viewing_key
    let key_path = resolve_file_path(".veilgate/merchant-viewing-key.txt");
    if !key_path.exists() {
        return Err(anyhow!(
            "Merchant viewing key file not found at: {}. Please ensure .veilgate/merchant-viewing-key.txt exists.",
            key_path.display()
        ));
    }

    let uivk = veilgate_backend::addresses::load_viewing_key(&key_path, &network)
        .with_context(|| format!("Failed to load viewing key from {}", key_path.display()))?;

    // Extract Orchard IVK alone (no full viewing key or spending key)
    let orchard_ivk = uivk
        .orchard()
        .as_ref()
        .ok_or_else(|| anyhow!("UnifiedIncomingViewingKey does not contain an Orchard IVK component"))?
        .clone();

    // Construct scanning keys from IVK alone for both Orchard and Ironwood pools.
    // Note: The nullifier key (nk) parameter is None since we only possess an incoming viewing key.
    // Ironwood outputs use the exact same Orchard incoming viewing key material under the Ironwood note-encryption domain.
    let orchard_scanning_key = ScanningKey::new(
        orchard_ivk.clone(),
        None, // None::<orchard::keys::FullViewingKey>: No full viewing key or spend key
        0u32, // AccountId
        None, // KeyScope
    );
    let ironwood_scanning_key = ScanningKey::new(
        orchard_ivk,
        None,
        0u32,
        None,
    );

    let mut orchard_keys = HashMap::new();
    orchard_keys.insert(0u32, Box::new(orchard_scanning_key) as _);

    let mut ironwood_keys = HashMap::new();
    ironwood_keys.insert(0u32, Box::new(ironwood_scanning_key) as _);

    let scanning_keys = ScanningKeys::new(HashMap::new(), orchard_keys, ironwood_keys);
    let nullifiers = Nullifiers::empty();

    // Connect to lightwalletd server over TLS with WebPKI root certificates
    println!("Connecting to lightwalletd server at {}...", args.url);
    let tls = ClientTlsConfig::new().with_webpki_roots();
    let endpoint = Endpoint::from_shared(args.url.clone())
        .with_context(|| format!("Invalid lightwalletd URL: {}", args.url))?
        .tls_config(tls)
        .with_context(|| "Failed to configure TLS for endpoint")?;

    let mut client = CompactTxStreamerClient::connect(endpoint)
        .await
        .with_context(|| format!("Failed to connect to lightwalletd server at {}", args.url))?;

    // Query lightwalletd info
    let info = client
        .get_lightd_info(tonic::Request::new(Empty {}))
        .await
        .with_context(|| "Failed to query get_lightd_info from server")?
        .into_inner();

    println!("Lightd Info:");
    println!("  Chain name:   {}", info.chain_name);
    println!("  Block height: {}", info.block_height);
    println!("  Vendor:       {}", info.vendor);
    println!("  Version:      {}", info.version);

    // Verify network: stop with clear message if the chain is not testnet
    if info.chain_name != "test" {
        eprintln!(
            "ERROR: Connected server chain is '{}', but TESTNET ('test') is strictly required.",
            info.chain_name
        );
        std::process::exit(1);
    }

    let tip = info.block_height;

    // Look up testnet NU6.3 activation height from zcash_protocol
    let nu6_3_activation = network.activation_height(NetworkUpgrade::Nu6_3);
    println!("\nNetwork Upgrade Info:");
    match nu6_3_activation {
        Some(act_height) => {
            let act_u32 = u32::from(act_height);
            let is_above = tip > act_u32 as u64;
            println!("  Testnet NU6.3 activation height: {}", act_u32);
            println!("  Current chain tip:               {}", tip);
            println!(
                "  Is chain tip above NU6.3?        {} (tip {} {} activation {})",
                if is_above { "YES" } else { "NO" },
                tip,
                if is_above { ">" } else { "<=" },
                act_u32
            );
        }
        None => {
            println!("  Testnet NU6.3 activation height: None (not defined)");
            println!("  Current chain tip:               {}", tip);
            println!("  Is chain tip above NU6.3?        NO (activation height not defined)");
        }
    }

    // 1. Scan the latest NUM_BLOCKS_TO_SCAN (500) blocks
    if tip < NUM_BLOCKS_TO_SCAN {
        return Err(anyhow!(
            "Chain height {} is less than required {} blocks",
            tip,
            NUM_BLOCKS_TO_SCAN
        ));
    }

    let latest_start = tip - (NUM_BLOCKS_TO_SCAN - 1);
    let latest_end = tip;
    let _latest_stats = scan_block_range(
        &mut client,
        &network,
        &scanning_keys,
        &nullifiers,
        "Latest 500 Blocks",
        latest_start,
        latest_end,
    )
    .await?;

    // 2. Scan a 500-block window starting at the NU6.3 activation height, if it exists on testnet
    if let Some(act_height) = nu6_3_activation {
        let act_start = u64::from(u32::from(act_height));
        if tip >= act_start {
            let act_end = std::cmp::min(act_start + NUM_BLOCKS_TO_SCAN - 1, tip);
            let _nu6_3_stats = scan_block_range(
                &mut client,
                &network,
                &scanning_keys,
                &nullifiers,
                "NU6.3 Activation Window",
                act_start,
                act_end,
            )
            .await?;
        } else {
            println!(
                "\nSkipping NU6.3 activation window scan: chain tip ({}) is below NU6.3 activation height ({}).",
                tip, act_start
            );
        }
    } else {
        println!("\nSkipping NU6.3 activation window scan: NU6.3 activation height is not defined for testnet.");
    }

    Ok(())
}
