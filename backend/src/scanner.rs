use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use rusqlite::params;
use rusqlite::OptionalExtension;
use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::scanning::{scan_block, Nullifiers, ScanningKey, ScanningKeys};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::Parameters;

use crate::addresses::FIRST_INVOICE_INDEX;
use crate::invoices::Store;

/// Default confirmation count required to mark an invoice as Paid.
pub const DEFAULT_CONFIRMATIONS: u32 = 3;

/// Default number of blocks to look back for reorganization detection on each pass.
pub const DEFAULT_REORG_DEPTH: u64 = 20;

/// Default lookback block count for a fresh database without a recorded cursor.
pub const DEFAULT_LOOKBACK_BLOCKS: u64 = 100;

/// Represents a decrypted note output matching one of our merchant invoice addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedNote {
    pub txid: String,
    pub output_index: u32,
    pub pool: String,
    pub value_zatoshi: u64,
    pub address_index: u32,
    pub block_height: u64,
    pub block_hash: String,
}

/// Statistics returned by `apply_detected`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyResult {
    pub payments_detected: usize,
    pub invoices_paid: usize,
}

/// Constructs Orchard and Ironwood scanning keys from a merchant UnifiedIncomingViewingKey.
///
/// Under Zcash NU6.3, payments sent to an Orchard shielded receiver land in the Ironwood pool.
/// Ironwood trial-decryption uses the exact same Orchard IVK key material under the Ironwood domain.
pub fn build_scanning_keys(
    uivk: &UnifiedIncomingViewingKey,
) -> Result<ScanningKeys<u32, u32>> {
    let orchard_ivk = uivk
        .orchard()
        .as_ref()
        .ok_or_else(|| anyhow!("UnifiedIncomingViewingKey does not contain an Orchard IVK component"))?
        .clone();

    let orchard_scanning_key = ScanningKey::new(
        orchard_ivk.clone(),
        None,
        0u32,
        None,
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

    Ok(ScanningKeys::new(HashMap::new(), orchard_keys, ironwood_keys))
}

/// Scans a compact block and extracts decrypted notes matching our viewing key.
pub fn scan_compact_block<P: Parameters + Send + 'static>(
    params: &P,
    block: CompactBlock,
    scanning_keys: &ScanningKeys<u32, u32>,
    nullifiers: &Nullifiers<u32>,
    prior_block_metadata: Option<&BlockMetadata>,
    uivk: &UnifiedIncomingViewingKey,
) -> Result<(Vec<DetectedNote>, BlockMetadata)> {
    let height = block.height;
    let block_hash = hex_encode(&block.hash);

    let scanned = scan_block(
        params,
        block,
        scanning_keys,
        nullifiers,
        prior_block_metadata,
    )
    .map_err(|e| anyhow!("Scan error at block height {}: {:?}", height, e))?;

    let mut detected = Vec::new();

    for tx in scanned.transactions() {
        let txid_hex = tx.txid().to_string();

        for output in tx.orchard_outputs() {
            let note = &output.note().0;
            let recip = note.recipient();
            if let Some(ua) = UnifiedAddress::from_receivers(Some(recip), None, None) {
                if let Some(address_index) = crate::addresses::find_invoice_index(uivk, &ua) {
                    if address_index >= FIRST_INVOICE_INDEX {
                        detected.push(DetectedNote {
                            txid: txid_hex.clone(),
                            output_index: output.index() as u32,
                            pool: "orchard".to_string(),
                            value_zatoshi: note.value().inner(),
                            address_index,
                            block_height: height,
                            block_hash: block_hash.clone(),
                        });
                    }
                }
            }
        }

        for output in tx.ironwood_outputs() {
            let note = &output.note().0;
            let recip = note.recipient();
            if let Some(ua) = UnifiedAddress::from_receivers(Some(recip), None, None) {
                if let Some(address_index) = crate::addresses::find_invoice_index(uivk, &ua) {
                    if address_index >= FIRST_INVOICE_INDEX {
                        detected.push(DetectedNote {
                            txid: txid_hex.clone(),
                            output_index: output.index() as u32,
                            pool: "ironwood".to_string(),
                            value_zatoshi: note.value().inner(),
                            address_index,
                            block_height: height,
                            block_hash: block_hash.clone(),
                        });
                    }
                }
            }
        }
    }

    Ok((detected, scanned.to_block_metadata()))
}

/// Applies newly detected notes to the database and evaluates invoice statuses.
///
/// Rules:
/// - Rejects any note with `address_index < FIRST_INVOICE_INDEX` or without an existing invoice.
/// - Stores notes in `payments` table with `UNIQUE(txid, output_index, pool)`.
/// - Marks an invoice as `Paid` only when sum of confirmed payments (`tip_height - block_height + 1 >= confirmations`) >= `amount_zatoshi`.
/// - Overpayments and partial payments are recorded.
/// - If marked Paid after `expires_at`, sets `is_late = true`.
pub fn apply_detected(
    store: &Store,
    notes: &[DetectedNote],
    tip_height: u64,
    confirmations: u32,
) -> Result<ApplyResult> {
    let mut conn = store
        .conn()
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;
    let tx = conn.transaction()?;

    let mut payments_detected = 0;
    let mut candidate_indices = HashSet::new();

    // 1. Record valid notes in payments table
    for note in notes {
        if note.address_index < FIRST_INVOICE_INDEX {
            continue;
        }

        let exists: Option<u32> = tx
            .query_row(
                "SELECT address_index FROM invoices WHERE address_index = ?1",
                [note.address_index],
                |row| row.get(0),
            )
            .optional()?;

        if exists.is_none() {
            continue;
        }

        let rows_affected = tx.execute(
            "INSERT INTO payments (
                address_index, txid, output_index, pool, value_zatoshi, block_height, block_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(txid, output_index, pool) DO NOTHING",
            params![
                note.address_index,
                note.txid,
                note.output_index,
                note.pool,
                note.value_zatoshi as i64,
                note.block_height as i64,
                note.block_hash,
            ],
        )?;

        if rows_affected > 0 {
            payments_detected += 1;
        }

        candidate_indices.insert(note.address_index);
    }

    // 2. Also check unpaid invoices that have recorded payments (confirmations may have increased)
    {
        let mut stmt = tx.prepare(
            "SELECT DISTINCT payments.address_index
             FROM payments
             JOIN invoices ON payments.address_index = invoices.address_index
             WHERE invoices.status != 'paid'",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        for idx in rows {
            candidate_indices.insert(idx?);
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut invoices_paid = 0;

    // 3. Evaluate invoices for payment completion
    for idx in candidate_indices {
        let (amount_i64, expires_i64, status): (i64, i64, String) = tx.query_row(
            "SELECT amount_zatoshi, expires_at, status FROM invoices WHERE address_index = ?1",
            [idx],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        if status == "paid" {
            continue;
        }

        let amount_zatoshi = amount_i64 as u64;
        let expires_at = expires_i64 as u64;

        let payment_rows = {
            let mut stmt = tx.prepare(
                "SELECT value_zatoshi, block_height FROM payments WHERE address_index = ?1",
            )?;
            let rows = stmt
                .query_map([idx], |row| {
                    Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };

        let mut confirmed_sum: u64 = 0;
        for (val, height) in payment_rows {
            let confs = if tip_height >= height {
                tip_height - height + 1
            } else {
                0
            };
            if confs >= confirmations as u64 {
                confirmed_sum = confirmed_sum.saturating_add(val);
            }
        }

        if confirmed_sum >= amount_zatoshi {
            let is_late = now >= expires_at;
            tx.execute(
                "UPDATE invoices SET status = 'paid', is_late = ?1 WHERE address_index = ?2",
                params![if is_late { 1i64 } else { 0i64 }, idx],
            )?;
            invoices_paid += 1;
        }
    }

    tx.commit()?;
    Ok(ApplyResult {
        payments_detected,
        invoices_paid,
    })
}

/// Compares stored block hashes against current blocks from the server.
/// If any mismatch is found, deletes payments at or above the reorganization height
/// and returns `Some(reorg_height)`. If no reorg is detected, returns `Ok(None)`.
pub fn check_and_rollback_reorg(
    store: &Store,
    current_blocks: &[(u64, String)],
) -> Result<Option<u64>> {
    let conn = store
        .conn()
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;

    let mut lowest_reorg_height: Option<u64> = None;

    for (height, current_hash) in current_blocks {
        let stored_hashes: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT block_hash FROM payments WHERE block_height = ?1",
            )?;
            let rows = stmt
                .query_map([*height as i64], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };

        for stored_hash in stored_hashes {
            if stored_hash != *current_hash {
                lowest_reorg_height = Some(match lowest_reorg_height {
                    Some(prev) => std::cmp::min(prev, *height),
                    None => *height,
                });
            }
        }
    }

    drop(conn);

    if let Some(reorg_height) = lowest_reorg_height {
        store.delete_payments_from_height(reorg_height)?;
        Ok(Some(reorg_height))
    } else {
        Ok(None)
    }
}

/// Rolls back payments at or above the given block height.
pub fn rollback_payments_from_height(store: &Store, height: u64) -> Result<usize> {
    store.delete_payments_from_height(height)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip0039::{English, Mnemonic};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;
    use crate::invoices::{create_invoice, open_store, InvoiceStatus};
    use zcash_protocol::consensus::Network;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_uivk(network: &Network) -> UnifiedIncomingViewingKey {
        let mnemonic = Mnemonic::<English>::from_phrase(TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        let usk = UnifiedSpendingKey::from_seed(network, &seed, AccountId::try_from(0).unwrap())
            .unwrap();
        usk.to_unified_full_viewing_key()
            .to_unified_incoming_viewing_key()
    }

    #[test]
    fn test_exact_payment_confirms_to_paid() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };

        // Tip 102 with 3 confirmations: 102 - 100 + 1 = 3 >= 3
        let res = apply_detected(&store, &[note], 102, 3).unwrap();
        assert_eq!(res.payments_detected, 1);
        assert_eq!(res.invoices_paid, 1);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Paid);
        assert!(!fetched.is_late);
    }

    #[test]
    fn test_underpayment_stays_pending() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 60_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };

        let res = apply_detected(&store, &[note], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 1);
        assert_eq!(res.invoices_paid, 0);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Pending);

        let summary = store.get_payment_summary(inv.address_index, 105, 3).unwrap().unwrap();
        assert_eq!(summary.total_confirmed_zatoshi, 60_000);
        assert!(!summary.is_paid);
    }

    #[test]
    fn test_two_partial_payments_sum_to_paid() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note1 = DetectedNote {
            txid: "tx1".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 60_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };
        let note2 = DetectedNote {
            txid: "tx2".to_string(),
            output_index: 0,
            pool: "ironwood".to_string(),
            value_zatoshi: 40_000,
            address_index: inv.address_index,
            block_height: 101,
            block_hash: "hash101".to_string(),
        };

        let res = apply_detected(&store, &[note1, note2], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 2);
        assert_eq!(res.invoices_paid, 1);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Paid);

        let summary = store.get_payment_summary(inv.address_index, 105, 3).unwrap().unwrap();
        assert_eq!(summary.total_confirmed_zatoshi, 100_000);
        assert_eq!(summary.excess_zatoshi, 0);
        assert!(summary.is_paid);
    }

    #[test]
    fn test_overpayment_recorded() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "tx_over".to_string(),
            output_index: 0,
            pool: "ironwood".to_string(),
            value_zatoshi: 150_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };

        let res = apply_detected(&store, &[note], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 1);
        assert_eq!(res.invoices_paid, 1);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Paid);

        let summary = store.get_payment_summary(inv.address_index, 105, 3).unwrap().unwrap();
        assert_eq!(summary.total_confirmed_zatoshi, 150_000);
        assert_eq!(summary.excess_zatoshi, 50_000);
        assert!(summary.is_paid);
    }

    #[test]
    fn test_unconfirmed_payment_does_not_mark_paid() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "tx_unconf".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };

        // Tip 101 with confirmations 3: 101 - 100 + 1 = 2 < 3
        let res1 = apply_detected(&store, &[note], 101, 3).unwrap();
        assert_eq!(res1.payments_detected, 1);
        assert_eq!(res1.invoices_paid, 0);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Pending);

        // Tip advances to 102: 102 - 100 + 1 = 3 >= 3
        let res2 = apply_detected(&store, &[], 102, 3).unwrap();
        assert_eq!(res2.payments_detected, 0);
        assert_eq!(res2.invoices_paid, 1);

        let fetched_paid = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched_paid.status, InvoiceStatus::Paid);
    }

    #[test]
    fn test_duplicate_processing_is_idempotent() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "tx_dup".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };

        let res1 = apply_detected(&store, &[note.clone()], 105, 3).unwrap();
        assert_eq!(res1.payments_detected, 1);
        assert_eq!(res1.invoices_paid, 1);

        let res2 = apply_detected(&store, &[note], 105, 3).unwrap();
        assert_eq!(res2.payments_detected, 0);
        assert_eq!(res2.invoices_paid, 0);

        let payments = store.get_payments_for_invoice(inv.address_index).unwrap();
        assert_eq!(payments.len(), 1);
    }

    #[test]
    fn test_notes_for_unknown_or_reserved_indices_are_ignored() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let _inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note_res0 = DetectedNote {
            txid: "tx_res0".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 50_000,
            address_index: 0,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };
        let note_res1 = DetectedNote {
            txid: "tx_res1".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 50_000,
            address_index: 1,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };
        let note_unknown = DetectedNote {
            txid: "tx_unk".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 50_000,
            address_index: 9999,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };

        let res = apply_detected(&store, &[note_res0, note_res1, note_unknown], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 0);
        assert_eq!(res.invoices_paid, 0);

        let payments0 = store.get_payments_for_invoice(0).unwrap();
        assert_eq!(payments0.len(), 0);
        let payments1 = store.get_payments_for_invoice(1).unwrap();
        assert_eq!(payments1.len(), 0);
        let payments9999 = store.get_payments_for_invoice(9999).unwrap();
        assert_eq!(payments9999.len(), 0);
    }

    #[test]
    fn test_late_payment_sets_paid_with_late_flag() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        // Expired immediately
        let inv = create_invoice(&store, &uivk, &net, 100_000, 0).unwrap();
        assert_eq!(inv.status, InvoiceStatus::Expired);

        let note = DetectedNote {
            txid: "tx_late".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };

        let res = apply_detected(&store, &[note], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 1);
        assert_eq!(res.invoices_paid, 1);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Paid);
        assert!(fetched.is_late);
    }

    #[test]
    fn test_reorg_rollback_removes_affected_payments() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note1 = DetectedNote {
            txid: "tx_kept".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 50_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
        };
        let note2 = DetectedNote {
            txid: "tx_reorged".to_string(),
            output_index: 0,
            pool: "ironwood".to_string(),
            value_zatoshi: 50_000,
            address_index: inv.address_index,
            block_height: 101,
            block_hash: "hash101".to_string(),
        };

        apply_detected(&store, &[note1, note2], 105, 3).unwrap();
        let fetched_before = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched_before.status, InvoiceStatus::Paid);

        // Reorg occurs at height 101
        let deleted = rollback_payments_from_height(&store, 101).unwrap();
        assert_eq!(deleted, 1);

        let payments = store.get_payments_for_invoice(inv.address_index).unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].txid, "tx_kept");

        // Invoice status must revert to Pending since remaining confirmed payment (50_000) < 100_000
        let fetched_after = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched_after.status, InvoiceStatus::Pending);
    }
}
