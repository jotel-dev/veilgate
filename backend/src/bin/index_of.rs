use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::Parser;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::Network;

use veilgate_backend::addresses::{find_invoice_index, load_viewing_key};

#[derive(Parser, Debug)]
#[command(name = "index_of")]
#[command(about = "Recover invoice diversifier index from a unified address")]
struct Cli {
    /// Unified address to inspect
    #[arg(long)]
    address: String,

    /// Path to viewing key file
    #[arg(long, default_value = ".veilgate/demo-viewing-key.txt")]
    key_path: String,

    /// Consensus network (test or main)
    #[arg(long, default_value = "test")]
    network: String,
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

fn main() -> Result<()> {
    let args = Cli::parse();

    let network = match args.network.to_lowercase().as_str() {
        "main" | "mainnet" => Network::MainNetwork,
        _ => Network::TestNetwork,
    };

    let key_path = resolve_file_path(&args.key_path);
    if !key_path.exists() {
        return Err(anyhow!("Viewing key file not found at: {}", key_path.display()));
    }

    let uivk = load_viewing_key(&key_path, &network)?;

    let ua = match UnifiedAddress::decode(&network, &args.address) {
        Ok(addr) => addr,
        Err(_) => {
            println!("not ours");
            return Ok(());
        }
    };

    match find_invoice_index(&uivk, &ua) {
        Some(idx) => println!("{idx}"),
        None => println!("not ours"),
    }

    Ok(())
}
