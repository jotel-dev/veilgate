use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use qrcode::QrCode;
use zcash_protocol::consensus::Network;

use veilgate_backend::addresses::load_viewing_key;
use veilgate_backend::invoices::{create_invoice, open_store, payment_uri};

/// 1.5 ZEC in zatoshis (1 ZEC = 100,000,000 zatoshis).
const DEMO_AMOUNT_ZATOSHI: u64 = 150_000_000;

/// Invoice validity: 1 hour in seconds.
const DEMO_VALIDITY_SECONDS: u64 = 3600;

fn resolve_file_path(relative: &str) -> PathBuf {
    let direct = Path::new(relative);
    if direct.exists() {
        return direct.to_path_buf();
    }
    let parent = Path::new("..").join(relative);
    if parent.exists() {
        return parent;
    }
    // Fall back to checking where .veilgate directory exists
    if Path::new("../.veilgate").exists() {
        parent
    } else {
        direct.to_path_buf()
    }
}

fn main() -> Result<()> {
    let network = Network::TestNetwork;

    // Resolve merchant viewing key file
    let key_path = resolve_file_path(".veilgate/merchant-viewing-key.txt");
    if !key_path.exists() {
        return Err(anyhow!(
            "Merchant viewing key file not found at: {}. Please ensure the file exists.",
            key_path.display()
        ));
    }

    let uivk = load_viewing_key(&key_path, &network)?;

    // Resolve SQLite database file
    let db_path = resolve_file_path(".veilgate/veilgate.db");
    let store = open_store(&db_path)?;

    // Create 1.5 ZEC invoice valid for 1 hour
    let invoice = create_invoice(
        &store,
        &uivk,
        &network,
        DEMO_AMOUNT_ZATOSHI,
        DEMO_VALIDITY_SECONDS,
    )?;

    // Generate ZIP 321 payment URI
    let uri = payment_uri(&invoice, &network);

    // Render terminal QR code
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {e}"))?;
    let qr_terminal = code.render::<qrcode::render::unicode::Dense1x2>().build();

    // Print demo output: public ID, payment URI, and terminal QR code
    println!("VeilGate Testnet Merchant Invoice");
    println!("----------------------------------");
    println!("Public ID:   {}", invoice.public_id);
    println!("Payment URI: {}", uri);
    println!("\nScan with a Zcash Testnet Shielded Wallet:\n");
    println!("{qr_terminal}");

    Ok(())
}
