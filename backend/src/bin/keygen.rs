use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use bip0039::{Count, English, Mnemonic};
use clap::{Parser, ValueEnum};
use zeroize::{Zeroize, Zeroizing};

use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedIncomingViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{Network, Parameters};
use zip32::{AccountId, DiversifierIndex};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkChoice {
    Test,
    Main,
}

impl NetworkChoice {
    pub fn to_network(self) -> Network {
        match self {
            NetworkChoice::Test => Network::TestNetwork,
            NetworkChoice::Main => Network::MainNetwork,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "keygen",
    about = "VeilGate merchant wallet key generator. Generates a merchant wallet and exports only a watch-only viewing key."
)]
struct Cli {
    /// Network to derive keys for (test or main)
    #[arg(long, value_enum, default_value_t = NetworkChoice::Test)]
    network: NetworkChoice,

    /// Import an existing 24-word phrase using hidden terminal input
    #[arg(long)]
    from_mnemonic: bool,

    /// Output path for the encoded watch-only viewing key
    #[arg(long, default_value = ".veilgate/merchant-viewing-key.txt")]
    output: PathBuf,
}

/// Derives the Unified Incoming Viewing Key and sanity check addresses (indices 0 and 1)
/// from a BIP-39 binary seed.
///
/// Derivation method:
/// - BIP-39 64-byte seed derivation via PBKDF2 HMAC-SHA512 with empty passphrase `""`.
/// - ZIP-32 hierarchical deterministic wallet derivation for account index 0 (`m/32'/coin_type'/0'`).
/// - Key derivation is strictly network-dependent: coin_type is 1 on testnet and 133 on mainnet.
pub fn derive_merchant_keys<P: Parameters>(
    seed: &[u8],
    params: &P,
) -> Result<(UnifiedIncomingViewingKey, UnifiedAddress, UnifiedAddress)> {
    if seed.len() < 32 {
        return Err(anyhow!("ZIP 32 seeds must be at least 32 bytes"));
    }

    let account = AccountId::try_from(0u32).map_err(|e| anyhow!("Invalid account ID: {e}"))?;

    // Derive UnifiedSpendingKey for account 0
    let usk = UnifiedSpendingKey::from_seed(params, seed, account)
        .map_err(|e| anyhow!("Failed to derive UnifiedSpendingKey: {e:?}"))?;

    // Derive the Unified Full Viewing Key, then the incoming-only Unified Incoming Viewing Key
    let ufvk = usk.to_unified_full_viewing_key();
    let uivk = ufvk.to_unified_incoming_viewing_key();

    // Derive sanity-check addresses at indices 0 and 1 (Shielded only, NO transparent receiver)
    let addr0 = uivk
        .address(DiversifierIndex::from(0u32), UnifiedAddressRequest::SHIELDED)
        .map_err(|e| anyhow!("Failed to derive address at diversifier index 0: {e:?}"))?;

    let addr1 = uivk
        .address(DiversifierIndex::from(1u32), UnifiedAddressRequest::SHIELDED)
        .map_err(|e| anyhow!("Failed to derive address at diversifier index 1: {e:?}"))?;

    // Double-check our security rule: no transparent receiver
    if addr0.transparent().is_some() || addr1.transparent().is_some() {
        return Err(anyhow!(
            "Security invariant violated: generated address contains transparent receiver"
        ));
    }

    Ok((uivk, addr0, addr1))
}

/// Inspects which receivers are contained in a Unified Address.
pub fn receiver_names(ua: &UnifiedAddress) -> Vec<&'static str> {
    let mut names = Vec::new();
    if ua.orchard().is_some() {
        names.push("Orchard");
    }
    if ua.sapling().is_some() {
        names.push("Sapling");
    }
    if ua.transparent().is_some() {
        names.push("Transparent");
    }
    names
}

fn save_viewing_key(path: &Path, encoded_key: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }
    }

    fs::write(path, format!("{encoded_key}\n"))
        .with_context(|| format!("Failed to write viewing key to {}", path.display()))?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let network = cli.network.to_network();

    let mut mnemonic = if cli.from_mnemonic {
        let mut input = rpassword::prompt_password("Enter existing 24-word mnemonic phrase: ")
            .context("Failed to read mnemonic from terminal")?;
        let words_count = input.trim().split_whitespace().count();
        if words_count != 24 {
            input.zeroize();
            return Err(anyhow!(
                "Mnemonic phrase must have exactly 24 words, but got {words_count}"
            ));
        }

        let parsed = Mnemonic::<English>::from_phrase(input.trim()).map_err(|e| {
            input.zeroize();
            anyhow!("Failed to parse 24-word mnemonic phrase: {e}")
        })?;

        input.zeroize();
        parsed
    } else {
        let mut generated_mnemonic = Mnemonic::<English>::generate(Count::Words24);
        let mut phrase = generated_mnemonic.phrase().to_string();

        println!("================================================================================");
        println!("  WARNING: VEILGATE MERCHANT WALLET RECOVERY PHRASE");
        println!("  - Write these 24 words down on physical paper in a secure, private location.");
        println!("  - Never share them with anyone; they grant FULL spending authority.");
        println!("  - This tool will NEVER display them again and will NOT save them to disk.");
        println!("================================================================================");
        println!();
        println!("  {phrase}");
        println!();
        println!("================================================================================");
        print!("Type the word 'written' and press Enter to continue: ");
        io::stdout().flush().context("Failed to flush stdout")?;

        let mut confirmation = String::new();
        io::stdin()
            .read_line(&mut confirmation)
            .context("Failed to read confirmation")?;

        let is_confirmed = confirmation.trim() == "written";
        phrase.zeroize();
        confirmation.zeroize();

        if !is_confirmed {
            generated_mnemonic.zeroize();
            eprintln!("Error: Confirmation word was not 'written'. Aborting without saving keys.");
            std::process::exit(1);
        }

        generated_mnemonic
    };

    // Standard BIP-39 derivation with empty passphrase
    let seed_array = mnemonic.to_seed("");
    mnemonic.zeroize();
    let seed = Zeroizing::new(seed_array);

    println!();
    println!("Deriving merchant wallet keys...");
    println!("- Network: {:?}", network);
    println!("- Derivation method: BIP-39 PBKDF2 (empty passphrase) -> ZIP-32 Account 0");
    println!("- Viewing key type: UnifiedIncomingViewingKey (incoming-only, watch-only)");

    let (uivk, addr0, addr1) =
        derive_merchant_keys(&seed[..], &network).context("Key derivation failed")?;

    // Encode the viewing key for the target network
    let encoded_uivk = uivk.encode(&network);

    // Save ONLY the encoded viewing key
    save_viewing_key(&cli.output, &encoded_uivk)?;
    println!("- Watch-only viewing key saved to: {}", cli.output.display());

    // Print sanity check addresses at index 0 and 1
    println!();
    println!("Sanity Check Shielded Addresses:");
    let addr0_encoded = addr0.encode(&network);
    let addr0_receivers = receiver_names(&addr0);
    println!("  Index 0: {addr0_encoded}");
    println!("    Receivers: {}", addr0_receivers.join(", "));

    let addr1_encoded = addr1.encode(&network);
    let addr1_receivers = receiver_names(&addr1);
    println!("  Index 1: {addr1_encoded}");
    println!("    Receivers: {}", addr1_receivers.join(", "));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed throwaway test mnemonic that appears ONLY inside test code
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_seed() -> Zeroizing<[u8; 64]> {
        let mnemonic =
            Mnemonic::<English>::from_phrase(TEST_MNEMONIC).expect("Valid 24-word test mnemonic");
        Zeroizing::new(mnemonic.to_seed(""))
    }

    #[test]
    fn test_same_mnemonic_and_network_deterministic_viewing_key() {
        let seed1 = test_seed();
        let (uivk1, _, _) = derive_merchant_keys(&seed1[..], &Network::TestNetwork)
            .expect("Derivation should succeed");
        let encoded1 = uivk1.encode(&Network::TestNetwork);

        let seed2 = test_seed();
        let (uivk2, _, _) = derive_merchant_keys(&seed2[..], &Network::TestNetwork)
            .expect("Derivation should succeed");
        let encoded2 = uivk2.encode(&Network::TestNetwork);

        assert_eq!(
            uivk1, uivk2,
            "Same mnemonic and network must produce identical viewing key structures"
        );
        assert_eq!(
            encoded1, encoded2,
            "Same mnemonic and network must produce identical encoded viewing keys"
        );

        // Also test mainnet determinism
        let (uivk_main1, _, _) = derive_merchant_keys(&seed1[..], &Network::MainNetwork)
            .expect("Derivation should succeed");
        let (uivk_main2, _, _) = derive_merchant_keys(&seed2[..], &Network::MainNetwork)
            .expect("Derivation should succeed");
        assert_eq!(uivk_main1, uivk_main2);
    }

    #[test]
    fn test_testnet_and_mainnet_produce_different_viewing_keys() {
        let seed = test_seed();
        let (uivk_test, _, _) = derive_merchant_keys(&seed[..], &Network::TestNetwork)
            .expect("Derivation should succeed");
        let (uivk_main, _, _) = derive_merchant_keys(&seed[..], &Network::MainNetwork)
            .expect("Derivation should succeed");

        let encoded_test = uivk_test.encode(&Network::TestNetwork);
        let encoded_main = uivk_main.encode(&Network::MainNetwork);

        assert_ne!(
            uivk_test, uivk_main,
            "Testnet and Mainnet must produce different viewing keys due to distinct ZIP-32 coin_type"
        );
        assert_ne!(
            encoded_test, encoded_main,
            "Encoded viewing keys must differ between testnet and mainnet"
        );
        assert!(
            encoded_test.starts_with("uivktest"),
            "Testnet UIVK must have testnet HRP prefix 'uivktest', got: {encoded_test}"
        );
        assert!(
            encoded_main.starts_with("uivk"),
            "Mainnet UIVK must have mainnet HRP prefix 'uivk', got: {encoded_main}"
        );
    }

    #[test]
    fn test_addresses_differ_and_same_index_is_deterministic() {
        let seed = test_seed();
        let (uivk, addr0, addr1) = derive_merchant_keys(&seed[..], &Network::TestNetwork)
            .expect("Derivation should succeed");

        let addr0_encoded = addr0.encode(&Network::TestNetwork);
        let addr1_encoded = addr1.encode(&Network::TestNetwork);

        // Addresses at index 0 and 1 must differ
        assert_ne!(addr0, addr1, "Addresses at index 0 and index 1 must differ");
        assert_ne!(
            addr0_encoded, addr1_encoded,
            "Encoded addresses at index 0 and index 1 must differ"
        );

        // The same index must give the same address every time
        let addr0_again = uivk
            .address(
                DiversifierIndex::from(0u32),
                UnifiedAddressRequest::SHIELDED,
            )
            .expect("Address derivation should succeed");
        let addr1_again = uivk
            .address(
                DiversifierIndex::from(1u32),
                UnifiedAddressRequest::SHIELDED,
            )
            .expect("Address derivation should succeed");

        assert_eq!(
            addr0, addr0_again,
            "Same index 0 must produce identical address every time"
        );
        assert_eq!(
            addr1, addr1_again,
            "Same index 1 must produce identical address every time"
        );
    }

    #[test]
    fn test_generated_addresses_contain_no_transparent_receiver() {
        let seed = test_seed();
        let (_uivk, addr0, addr1) = derive_merchant_keys(&seed[..], &Network::TestNetwork)
            .expect("Derivation should succeed");

        // Verify transparent receiver is None
        assert!(
            addr0.transparent().is_none(),
            "Address at index 0 must NOT contain a transparent receiver"
        );
        assert!(
            addr1.transparent().is_none(),
            "Address at index 1 must NOT contain a transparent receiver"
        );

        // Verify receiver names don't include Transparent
        let r0 = receiver_names(&addr0);
        let r1 = receiver_names(&addr1);

        assert!(
            !r0.contains(&"Transparent"),
            "Receivers for index 0 must not include Transparent"
        );
        assert!(
            !r1.contains(&"Transparent"),
            "Receivers for index 1 must not include Transparent"
        );

        // Verify shielded receiver is present (privacy requirement)
        assert!(
            r0.contains(&"Orchard"),
            "Address 0 must contain at least Orchard shielded receiver"
        );
        assert!(
            r1.contains(&"Orchard"),
            "Address 1 must contain at least Orchard shielded receiver"
        );
    }
}
