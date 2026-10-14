use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{ChainSpec, Empty};

const LIGHTWALLETD_URL: &str = "https://zec.rocks:443";

#[tokio::main]
async fn main() {
    println!("Connecting to lightwalletd server at {LIGHTWALLETD_URL}...");

    let mut client = match CompactTxStreamerClient::connect(LIGHTWALLETD_URL).await {
        Ok(client) => client,
        Err(err) => {
            eprintln!("Error: Failed to connect to lightwalletd at {LIGHTWALLETD_URL}: {err}");
            return;
        }
    };

    println!("Connected successfully.\n");

    println!("--- Server Info (get_lightd_info) ---");
    match client.get_lightd_info(Empty {}).await {
        Ok(response) => {
            let info = response.into_inner();
            println!("Chain Name:     {}", info.chain_name);
            println!("Server Version: {}", info.version);
            println!("Block Height:   {}", info.block_height);
        }
        Err(err) => {
            eprintln!("Error: Failed to call get_lightd_info: {err}");
            return;
        }
    }

    println!("\n--- Latest Block (get_latest_block) ---");
    match client.get_latest_block(ChainSpec {}).await {
        Ok(response) => {
            let block = response.into_inner();
            // In Zcash and Bitcoin RPCs, block hashes are presented in reverse (big-endian) byte order
            let block_hash_hex: String = block
                .hash
                .iter()
                .rev()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!("Block Height: {}", block.height);
            println!("Block Hash:   {}", block_hash_hex);
        }
        Err(err) => {
            eprintln!("Error: Failed to call get_latest_block: {err}");
            return;
        }
    }
}





