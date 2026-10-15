use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedIncomingViewingKey};
use zcash_protocol::consensus::Network;
use zip32::DiversifierIndex;

/// The first diversifier index available for merchant invoices.
/// Indices 0 and 1 are reserved for keygen's sanity-check addresses.
pub const FIRST_INVOICE_INDEX: u32 = 2;

/// Reads an encoded viewing key from disk, decodes it for the specified network,
/// and returns the `UnifiedIncomingViewingKey`.
///
/// Returns an error if:
/// - The file is missing or cannot be read.
/// - The file is empty.
/// - The viewing key is corrupted or belongs to a different network.
pub fn load_viewing_key(
    path: impl AsRef<Path>,
    network: &Network,
) -> Result<UnifiedIncomingViewingKey> {
    let p = path.as_ref();
    if !p.exists() {
        return Err(anyhow!("Viewing key file not found at: {}", p.display()));
    }

    let raw = fs::read_to_string(p)
        .with_context(|| format!("Failed to read viewing key file from: {}", p.display()))?;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Viewing key file is empty: {}", p.display()));
    }

    let uivk = UnifiedIncomingViewingKey::decode(network, trimmed)
        .map_err(|e| anyhow!("Viewing key decoding failed for network {network:?}: {e}"))?;

    Ok(uivk)
}

/// Derives a single shielded invoice address at the specified diversifier index.
///
/// Uses `UnifiedAddressRequest::ORCHARD` so that the generated address contains
/// ONLY an Orchard shielded receiver (no Sapling, no transparent).
///
/// Returns an error if:
/// - `index < FIRST_INVOICE_INDEX` (indices 0 and 1 are reserved).
/// - The resulting address contains any non-Orchard receiver.
/// - Address derivation fails.
pub fn invoice_address(
    uivk: &UnifiedIncomingViewingKey,
    _network: &Network,
    index: u32,
) -> Result<UnifiedAddress> {
    if index < FIRST_INVOICE_INDEX {
        return Err(anyhow!(
            "Invalid invoice index {index}: must be >= {FIRST_INVOICE_INDEX} (indices 0 and 1 are reserved for sanity checks)"
        ));
    }

    let di = DiversifierIndex::from(index);
    let ua = uivk
        .address(di, UnifiedAddressRequest::ORCHARD)
        .map_err(|e| anyhow!("Failed to derive address at index {index}: {e:?}"))?;

    // Security check: Must contain an Orchard receiver
    if ua.orchard().is_none() {
        return Err(anyhow!(
            "Address generation error: address is missing an Orchard receiver"
        ));
    }

    // Security check: Must NOT contain Sapling or Transparent receivers
    if ua.sapling().is_some() || ua.transparent().is_some() {
        return Err(anyhow!(
            "Security violation: derived invoice address contains non-Orchard receiver"
        ));
    }

    Ok(ua)
}

/// Encodes a `UnifiedAddress` into its string representation for the given network.
pub fn encode_address(address: &UnifiedAddress, network: &Network) -> String {
    address.encode(network)
}

/// Recovers the diversifier index from a UnifiedAddress using the merchant's UnifiedIncomingViewingKey.
///
/// Because Orchard diversifiers are encrypted with the diversifier key (dk) contained within the IVK,
/// the viewing key holder can decrypt the diversifier and recover the index `j` without a database lookup.
///
/// Returns `Some(u32)` if the address belongs to this viewing key and fits in a `u32`.
/// Returns `None` if the address was derived from a different key or has no matching Orchard receiver.
pub fn find_invoice_index(
    uivk: &UnifiedIncomingViewingKey,
    address: &UnifiedAddress,
) -> Option<u32> {
    address
        .orchard()
        .zip(uivk.orchard().as_ref())
        .and_then(|(receiver, ivk)| ivk.diversifier_index(receiver))
        .and_then(|di| u32::try_from(di).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip0039::{English, Mnemonic};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    // Fixed throwaway test mnemonic used ONLY inside test code
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_uivk(network: &Network) -> UnifiedIncomingViewingKey {
        let mnemonic = Mnemonic::<English>::from_phrase(TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let usk = UnifiedSpendingKey::from_seed(network, &seed, AccountId::try_from(0).unwrap()).unwrap();
        usk.to_unified_full_viewing_key().to_unified_incoming_viewing_key()
    }

    #[test]
    fn test_same_index_gives_same_address() {
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let addr_a = invoice_address(&uivk, &net, FIRST_INVOICE_INDEX).unwrap();
        let addr_b = invoice_address(&uivk, &net, FIRST_INVOICE_INDEX).unwrap();

        assert_eq!(addr_a, addr_b);
        assert_eq!(encode_address(&addr_a, &net), encode_address(&addr_b, &net));
    }

    #[test]
    fn test_different_indices_give_different_addresses() {
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let addr_2 = invoice_address(&uivk, &net, 2).unwrap();
        let addr_3 = invoice_address(&uivk, &net, 3).unwrap();

        assert_ne!(addr_2, addr_3);
        assert_ne!(encode_address(&addr_2, &net), encode_address(&addr_3, &net));
    }

    #[test]
    fn test_addresses_are_orchard_only() {
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let addr = invoice_address(&uivk, &net, 2).unwrap();

        // Must have Orchard receiver
        assert!(addr.orchard().is_some());
        // Must NOT have Sapling receiver
        assert!(addr.sapling().is_none());
        // Must NOT have transparent receiver
        assert!(addr.transparent().is_none());
    }

    #[test]
    fn test_indices_below_two_are_rejected() {
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let err_0 = invoice_address(&uivk, &net, 0);
        assert!(err_0.is_err(), "Index 0 must be rejected");

        let err_1 = invoice_address(&uivk, &net, 1);
        assert!(err_1.is_err(), "Index 1 must be rejected");

        let ok_2 = invoice_address(&uivk, &net, 2);
        assert!(ok_2.is_ok(), "Index 2 must be accepted");
    }

    #[test]
    fn test_viewing_key_for_wrong_network_is_rejected() {
        // Generate mainnet viewing key
        let main_uivk = test_uivk(&Network::MainNetwork);
        let encoded_main = main_uivk.encode(&Network::MainNetwork);

        // Save to temporary file in target directory
        let temp_dir = std::env::temp_dir();
        let wrong_net_file = temp_dir.join("test_wrong_net_viewing_key.txt");
        fs::write(&wrong_net_file, encoded_main).unwrap();

        // Loading for TestNetwork should fail
        let result = load_viewing_key(&wrong_net_file, &Network::TestNetwork);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("network") || err_msg.contains("expected"),
            "Error message should mention network mismatch, got: {err_msg}"
        );

        let _ = fs::remove_file(wrong_net_file);

        // Also test non-existent file
        let missing_file = temp_dir.join("non_existent_key_123456789.txt");
        let result_missing = load_viewing_key(&missing_file, &Network::TestNetwork);
        assert!(result_missing.is_err());
        let missing_err = result_missing.unwrap_err().to_string();
        assert!(missing_err.contains("not found"));
    }

    #[test]
    fn test_find_invoice_index_recovery() {
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let addr_2 = invoice_address(&uivk, &net, 2).unwrap();
        let addr_42 = invoice_address(&uivk, &net, 42).unwrap();
        let addr_1000 = invoice_address(&uivk, &net, 1000).unwrap();

        assert_eq!(find_invoice_index(&uivk, &addr_2), Some(2));
        assert_eq!(find_invoice_index(&uivk, &addr_42), Some(42));
        assert_eq!(find_invoice_index(&uivk, &addr_1000), Some(1000));

        // Address from a different key
        const ANOTHER_MNEMONIC: &str =
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        let other_mnemonic = Mnemonic::<English>::from_phrase(ANOTHER_MNEMONIC).unwrap();
        let other_seed = other_mnemonic.to_seed("");
        let other_usk = UnifiedSpendingKey::from_seed(&net, &other_seed, AccountId::try_from(0).unwrap()).unwrap();
        let other_uivk = other_usk.to_unified_full_viewing_key().to_unified_incoming_viewing_key();
        let foreign_addr = invoice_address(&other_uivk, &net, 2).unwrap();

        assert_eq!(find_invoice_index(&uivk, &foreign_addr), None);
    }
}
