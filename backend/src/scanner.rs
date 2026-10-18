use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use rusqlite::params;
use rusqlite::OptionalExtension;
use tonic::transport::Channel;
use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, Empty};
use zcash_client_backend::scanning::{scan_block, Nullifiers, ScanningKey, ScanningKeys};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::{Network, Parameters};

use crate::addresses::FIRST_INVOICE_INDEX;
use crate::invoices::Store;

/// Default confirmation count required to mark an invoice as Paid.
pub const DEFAULT_CONFIRMATIONS: u32 = 3;

/// Default number of blocks to look back for reorganization detection on each pass.
pub const DEFAULT_REORG_DEPTH: u64 = 20;

/// Default lookback block count for a fresh database without a recorded cursor.
pub const DEFAULT_LOOKBACK_BLOCKS: u64 = 100;

/// Number of blocks to process per chunk during scan catch-up.
pub const CHUNK_BLOCKS: u64 = 500;

/// Maximum duration allowed for scanning a single chunk before timing out.
pub const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);

/// Pure function dividing a block height range into sequential chunks of at most `size` blocks.
///
/// Returns an empty vector if `start > end` or `size == 0`.
pub fn plan_chunks(start: u64, end: u64, size: u64) -> Vec<(u64, u64)> {
    if start > end || size == 0 {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut current_start = start;
    while current_start <= end {
        let chunk_end = std::cmp::min(current_start.saturating_add(size.saturating_sub(1)), end);
        chunks.push((current_start, chunk_end));
        if chunk_end == end {
            break;
        }
        current_start = chunk_end + 1;
    }
    chunks
}

/// Categorization of scanner failures to prevent leakage of sensitive data in logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanErrorKind {
    Connect,
    Timeout,
    Stream,
    ScanBlock { height: u64 },
    Database,
    Other,
}

impl ScanErrorKind {
    pub fn category(&self) -> String {
        match self {
            Self::Connect => "connect".to_string(),
            Self::Timeout => "timeout".to_string(),
            Self::Stream => "stream".to_string(),
            Self::ScanBlock { height } => format!("scan_block at height {height}"),
            Self::Database => "database".to_string(),
            Self::Other => "other".to_string(),
        }
    }
}

/// Structured error for payment scanning operations.
#[derive(Debug)]
pub struct ScanError {
    pub kind: ScanErrorKind,
    pub source: Option<anyhow::Error>,
}

impl ScanError {
    pub fn connect(e: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: ScanErrorKind::Connect,
            source: Some(e.into()),
        }
    }
    pub fn timeout() -> Self {
        Self {
            kind: ScanErrorKind::Timeout,
            source: None,
        }
    }
    pub fn stream(e: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: ScanErrorKind::Stream,
            source: Some(e.into()),
        }
    }
    pub fn scan_block(height: u64, e: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: ScanErrorKind::ScanBlock { height },
            source: Some(e.into()),
        }
    }
    pub fn database(e: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: ScanErrorKind::Database,
            source: Some(e.into()),
        }
    }
    pub fn other(e: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: ScanErrorKind::Other,
            source: Some(e.into()),
        }
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind.category())
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

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
    pub block_time: u32,
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
    let block_time = block.time;

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
                            block_time,
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
                            block_time,
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
/// - An invoice is marked late if the payment that brings confirmed sum to >= amount was mined after `expires_at`.
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
                address_index, txid, output_index, pool, value_zatoshi, block_height, block_hash, block_time
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(txid, output_index, pool) DO NOTHING",
            params![
                note.address_index,
                note.txid,
                note.output_index,
                note.pool,
                note.value_zatoshi as i64,
                note.block_height as i64,
                note.block_hash,
                note.block_time as i64,
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
                "SELECT value_zatoshi, block_height, block_time
                 FROM payments WHERE address_index = ?1
                 ORDER BY block_height ASC, output_index ASC",
            )?;
            let rows = stmt
                .query_map([idx], |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u32,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };

        let mut confirmed_sum: u64 = 0;
        let mut threshold_payment_time: Option<u32> = None;

        for (val, height, btime) in payment_rows {
            let confs = if tip_height >= height {
                tip_height - height + 1
            } else {
                0
            };
            if confs >= confirmations as u64 {
                let prev_sum = confirmed_sum;
                confirmed_sum = confirmed_sum.saturating_add(val);
                if prev_sum < amount_zatoshi && confirmed_sum >= amount_zatoshi {
                    threshold_payment_time = Some(btime);
                }
            }
        }

        if confirmed_sum >= amount_zatoshi {
            let is_late = match threshold_payment_time {
                Some(btime) => (btime as u64) > expires_at,
                None => false,
            };
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

/// Pure function comparing stored block hashes against current chain block hashes.
///
/// Returns `Some(lowest_mismatch_height)` if any block height present in both sets has differing hashes.
/// If all common block heights match, or if current heights have no stored hashes, returns `None`.
pub fn find_reorg_height<S1: AsRef<str>, S2: AsRef<str>>(
    stored_hashes: &[(u64, S1)],
    current_hashes: &[(u64, S2)],
) -> Option<u64> {
    let mut current_map = HashMap::new();
    for (height, hash) in current_hashes {
        current_map.insert(*height, hash.as_ref());
    }

    let mut lowest_mismatch: Option<u64> = None;
    for (height, stored_hash) in stored_hashes {
        if let Some(current_hash) = current_map.get(height) {
            if stored_hash.as_ref() != *current_hash {
                lowest_mismatch = Some(match lowest_mismatch {
                    Some(prev) => std::cmp::min(prev, *height),
                    None => *height,
                });
            }
        }
    }

    lowest_mismatch
}

/// Compares stored block hashes against current blocks from the server.
/// If any mismatch is found, deletes payments at or above the reorganization height
/// and returns `Some(reorg_height)`. If no reorg is detected, returns `Ok(None)`.
pub fn check_and_rollback_reorg(
    store: &Store,
    current_blocks: &[(u64, String)],
) -> Result<Option<u64>> {
    if current_blocks.is_empty() {
        return Ok(None);
    }

    let conn = store
        .conn()
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;

    let min_height = current_blocks.iter().map(|(h, _)| *h).min().unwrap_or(0);
    let max_height = current_blocks.iter().map(|(h, _)| *h).max().unwrap_or(0);

    let stored_hashes: Vec<(u64, String)> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT block_height, block_hash FROM payments
             WHERE block_height >= ?1 AND block_height <= ?2",
        )?;
        let rows = stmt.query_map(params![min_height as i64, max_height as i64], |row| {
            Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    drop(conn);

    if let Some(reorg_height) = find_reorg_height(&stored_hashes, current_blocks) {
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

/// Current payment state of an invoice for the merchant dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvoicePaymentState {
    /// No payments have been detected for this invoice.
    NoPayment,
    /// Sufficient funds detected to pay the invoice, but awaiting required confirmations.
    Detected {
        received: u64,
        confirmations_remaining: u32,
    },
    /// Partial payment detected, but total received is less than the invoice amount.
    Underpaid {
        received: u64,
        missing: u64,
    },
    /// Confirmed sum meets or exceeds invoice amount.
    Paid {
        received: u64,
        excess: u64,
        late: bool,
    },
}

/// Computes the detailed payment state for an invoice given current chain tip and required confirmations.
pub fn invoice_payment_state(
    store: &Store,
    address_index: u32,
    tip_height: u64,
    confirmations: u32,
) -> Result<InvoicePaymentState> {
    let inv = match store.get_by_address_index(address_index)? {
        Some(i) => i,
        None => return Err(anyhow!("Invoice with address_index {} not found", address_index)),
    };

    let payments = store.get_payments_for_invoice(address_index)?;
    if payments.is_empty() {
        return Ok(InvoicePaymentState::NoPayment);
    }

    let mut total_received: u64 = 0;
    let mut total_confirmed: u64 = 0;
    let mut threshold_payment_btime: Option<u32> = None;
    let mut detected_threshold_height: Option<u64> = None;

    for p in &payments {
        let prev_total = total_received;
        total_received = total_received.saturating_add(p.value_zatoshi);
        if prev_total < inv.amount_zatoshi && total_received >= inv.amount_zatoshi {
            detected_threshold_height = Some(p.block_height);
        }

        let confs = if tip_height >= p.block_height {
            tip_height - p.block_height + 1
        } else {
            0
        };

        if confs >= confirmations as u64 {
            let prev_confirmed = total_confirmed;
            total_confirmed = total_confirmed.saturating_add(p.value_zatoshi);
            if prev_confirmed < inv.amount_zatoshi && total_confirmed >= inv.amount_zatoshi {
                threshold_payment_btime = Some(p.block_time);
            }
        }
    }

    if total_received == 0 {
        return Ok(InvoicePaymentState::NoPayment);
    }

    if total_confirmed >= inv.amount_zatoshi {
        let late = if inv.status == crate::invoices::InvoiceStatus::Paid {
            inv.is_late
        } else if let Some(btime) = threshold_payment_btime {
            (btime as u64) > inv.expires_at
        } else {
            false
        };

        let excess = total_confirmed.saturating_sub(inv.amount_zatoshi);
        return Ok(InvoicePaymentState::Paid {
            received: total_confirmed,
            excess,
            late,
        });
    }

    if total_received < inv.amount_zatoshi {
        let missing = inv.amount_zatoshi.saturating_sub(total_received);
        return Ok(InvoicePaymentState::Underpaid {
            received: total_received,
            missing,
        });
    }

    // total_received >= inv.amount_zatoshi, but total_confirmed < inv.amount_zatoshi
    let confs = if let Some(h) = detected_threshold_height {
        if tip_height >= h {
            tip_height - h + 1
        } else {
            0
        }
    } else {
        0
    };

    let confirmations_remaining = (confirmations as u64).saturating_sub(confs) as u32;

    Ok(InvoicePaymentState::Detected {
        received: total_received,
        confirmations_remaining,
    })
}

/// Summary of a completed scan pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPassSummary {
    pub blocks_scanned: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub payments_detected: usize,
    pub invoices_paid: usize,
}

/// Scans a single bounded block range (chunk), checks for reorgs, applies detected notes,
/// and updates the scan cursor and success timestamp to `chunk_end`.
pub async fn scan_single_chunk(
    client: &mut CompactTxStreamerClient<Channel>,
    store: &Store,
    network: &Network,
    scanning_keys: &ScanningKeys<u32, u32>,
    nullifiers: &Nullifiers<u32>,
    uivk: &UnifiedIncomingViewingKey,
    confirmations: u32,
    chunk_start: u64,
    chunk_end: u64,
    tip: u64,
) -> Result<(u64, usize, usize), ScanError> {
    let range = BlockRange {
        start: Some(BlockId {
            height: chunk_start,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: chunk_end,
            hash: vec![],
        }),
        pool_types: vec![],
    };

    let mut stream = client
        .get_block_range(tonic::Request::new(range))
        .await
        .map_err(ScanError::stream)?
        .into_inner();

    let mut blocks_scanned: u64 = 0;
    let mut detected_notes = Vec::new();
    let mut prior_metadata: Option<BlockMetadata> = None;
    let mut current_block_hashes = Vec::new();

    loop {
        let block_opt = stream.message().await.map_err(ScanError::stream)?;
        let block = match block_opt {
            Some(b) => b,
            None => break,
        };

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
        )
        .map_err(|e| ScanError::scan_block(height, e))?;

        detected_notes.extend(notes);
        prior_metadata = Some(metadata);
        blocks_scanned += 1;
    }

    // Check for reorganization and rollback if block hashes differ
    check_and_rollback_reorg(store, &current_block_hashes)
        .map_err(ScanError::database)?;

    // Apply detected notes to database
    let result = apply_detected(store, &detected_notes, tip, confirmations)
        .map_err(ScanError::database)?;

    // Update scan cursor in invoice_meta to the end of THAT chunk
    store
        .set_last_scanned_height(chunk_end)
        .map_err(ScanError::database)?;

    // Record last successful scan time in invoice_meta
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    store
        .set_last_success_unix_time(now)
        .map_err(ScanError::database)?;

    Ok((blocks_scanned, result.payments_detected, result.invoices_paid))
}

/// Executes a scan pass across the lightwalletd compact block stream in chunks of 500 blocks.
///
/// Records the server chain tip in `invoice_meta` under key `'chain_tip'`.
/// Each chunk updates `last_scanned_height` in `invoice_meta` immediately upon completion,
/// ensuring forward progress is preserved across timeouts or network interruptions.
pub async fn run_scan_pass(
    client: &mut CompactTxStreamerClient<Channel>,
    store: &Store,
    network: &Network,
    scanning_keys: &ScanningKeys<u32, u32>,
    nullifiers: &Nullifiers<u32>,
    uivk: &UnifiedIncomingViewingKey,
    confirmations: u32,
    from_height: Option<u64>,
) -> Result<ScanPassSummary, ScanError> {
    let info = client
        .get_lightd_info(tonic::Request::new(Empty {}))
        .await
        .map_err(ScanError::connect)?
        .into_inner();

    if info.chain_name != "test" {
        let err = ScanError::other(anyhow!(
            "Connected server chain is '{}', but TESTNET ('test') is strictly required",
            info.chain_name
        ));
        let _ = store.set_last_error_category(&err.kind.category());
        return Err(err);
    }

    let mut current_tip = info.block_height;
    store.set_chain_tip(current_tip).map_err(ScanError::database)?;

    let last_scanned = store.get_last_scanned_height().map_err(ScanError::database)?;

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
        None => from_height.unwrap_or_else(|| current_tip.saturating_sub(DEFAULT_LOOKBACK_BLOCKS)),
    };

    if start_height > current_tip {
        let result = apply_detected(store, &[], current_tip, confirmations)
            .map_err(ScanError::database)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = store.set_last_success_unix_time(now);
        return Ok(ScanPassSummary {
            blocks_scanned: 0,
            start_height,
            end_height: current_tip,
            payments_detected: result.payments_detected,
            invoices_paid: result.invoices_paid,
        });
    }

    let mut chunks = plan_chunks(start_height, current_tip, CHUNK_BLOCKS);
    let mut total_blocks_scanned: u64 = 0;
    let mut total_payments_detected: usize = 0;
    let mut total_invoices_paid: usize = 0;
    let mut final_end = current_tip;
    let mut chunk_idx = 0;

    while chunk_idx < chunks.len() {
        let (chunk_start, chunk_end) = chunks[chunk_idx];
        final_end = chunk_end;

        // Each chunk has its own 60 second timeout
        let chunk_res = tokio::time::timeout(
            CHUNK_TIMEOUT,
            scan_single_chunk(
                client,
                store,
                network,
                scanning_keys,
                nullifiers,
                uivk,
                confirmations,
                chunk_start,
                chunk_end,
                current_tip,
            ),
        )
        .await;

        match chunk_res {
            Ok(Ok((scanned, payments, paid))) => {
                total_blocks_scanned += scanned;
                total_payments_detected += payments;
                total_invoices_paid += paid;
                chunk_idx += 1;

                // Re-read the tip between chunks
                if let Ok(tip_resp) = client.get_lightd_info(tonic::Request::new(Empty {})).await {
                    let new_tip = tip_resp.into_inner().block_height;
                    if new_tip > current_tip {
                        let old_tip = current_tip;
                        current_tip = new_tip;
                        let _ = store.set_chain_tip(current_tip);
                        let extra_chunks = plan_chunks(old_tip + 1, current_tip, CHUNK_BLOCKS);
                        chunks.extend(extra_chunks);
                    }
                }
            }
            Ok(Err(err)) => {
                let _ = store.set_last_error_category(&err.kind.category());
                return Err(err);
            }
            Err(_elapsed) => {
                let err = ScanError::timeout();
                let _ = store.set_last_error_category(&err.kind.category());
                return Err(err);
            }
        }
    }

    Ok(ScanPassSummary {
        blocks_scanned: total_blocks_scanned,
        start_height,
        end_height: final_end,
        payments_detected: total_payments_detected,
        invoices_paid: total_invoices_paid,
    })
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
            block_time: (inv.expires_at - 100) as u32,
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
            block_time: (inv.expires_at - 100) as u32,
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
            block_time: (inv.expires_at - 100) as u32,
        };
        let note2 = DetectedNote {
            txid: "tx2".to_string(),
            output_index: 0,
            pool: "ironwood".to_string(),
            value_zatoshi: 40_000,
            address_index: inv.address_index,
            block_height: 101,
            block_hash: "hash101".to_string(),
            block_time: (inv.expires_at - 50) as u32,
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
            block_time: (inv.expires_at - 100) as u32,
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
            block_time: (inv.expires_at - 100) as u32,
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
            block_time: (inv.expires_at - 100) as u32,
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
            block_time: 1000,
        };
        let note_res1 = DetectedNote {
            txid: "tx_res1".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 50_000,
            address_index: 1,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: 1000,
        };
        let note_unknown = DetectedNote {
            txid: "tx_unk".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 50_000,
            address_index: 9999,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: 1000,
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
        // Expired immediately (expires_at = created_at)
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
            block_time: (inv.expires_at + 10) as u32,
        };

        let res = apply_detected(&store, &[note], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 1);
        assert_eq!(res.invoices_paid, 1);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Paid);
        assert!(fetched.is_late);
    }

    #[test]
    fn test_mined_before_expiry_but_confirmed_after_expiry_is_not_late() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        // Mined before expiry
        let note = DetectedNote {
            txid: "tx_before_exp".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: (inv.expires_at - 60) as u32,
        };

        // Confirmed when tip is 105
        let res = apply_detected(&store, &[note], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 1);
        assert_eq!(res.invoices_paid, 1);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Paid);
        assert!(!fetched.is_late, "Payment mined before expiry must NOT be marked late");
    }

    #[test]
    fn test_mined_after_expiry_is_late() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        // Mined after expiry
        let note = DetectedNote {
            txid: "tx_after_exp".to_string(),
            output_index: 0,
            pool: "ironwood".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: (inv.expires_at + 60) as u32,
        };

        let res = apply_detected(&store, &[note], 105, 3).unwrap();
        assert_eq!(res.payments_detected, 1);
        assert_eq!(res.invoices_paid, 1);

        let fetched = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched.status, InvoiceStatus::Paid);
        assert!(fetched.is_late, "Payment mined after expiry MUST be marked late");
    }

    #[test]
    fn test_pure_reorg_no_mismatch() {
        let stored = vec![(100u64, "hashA"), (101u64, "hashB")];
        let current = vec![(100u64, "hashA"), (101u64, "hashB")];
        assert_eq!(find_reorg_height(&stored, &current), None);
    }

    #[test]
    fn test_pure_reorg_one_mismatch() {
        let stored = vec![(100u64, "hashA"), (101u64, "hashB_old")];
        let current = vec![(100u64, "hashA"), (101u64, "hashB_new")];
        assert_eq!(find_reorg_height(&stored, &current), Some(101));
    }

    #[test]
    fn test_pure_reorg_several_mismatches_returns_lowest_height() {
        let stored = vec![
            (100u64, "hashA_old"),
            (101u64, "hashB_old"),
            (102u64, "hashC_old"),
        ];
        let current = vec![
            (100u64, "hashA_new"),
            (101u64, "hashB_new"),
            (102u64, "hashC_new"),
        ];
        assert_eq!(find_reorg_height(&stored, &current), Some(100));
    }

    #[test]
    fn test_pure_reorg_heights_with_no_stored_payments() {
        let stored = vec![(100u64, "hashA"), (105u64, "hashE")];
        let current = vec![
            (99u64, "hash99"),
            (100u64, "hashA"),
            (101u64, "hash101"),
            (102u64, "hash102"),
            (105u64, "hashE"),
            (106u64, "hash106"),
        ];
        assert_eq!(find_reorg_height(&stored, &current), None);

        let current_mismatch = vec![
            (99u64, "hash99"),
            (100u64, "hashA"),
            (105u64, "hashE_fork"),
        ];
        assert_eq!(find_reorg_height(&stored, &current_mismatch), Some(105));
    }

    #[test]
    fn test_check_and_rollback_reorg_returns_invoice_to_pending_and_clears_is_late() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "tx_reorg_late".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100_original".to_string(),
            block_time: (inv.expires_at + 10) as u32,
        };

        apply_detected(&store, &[note], 105, 3).unwrap();
        let fetched_paid = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched_paid.status, InvoiceStatus::Paid);
        assert!(fetched_paid.is_late);

        // Reorg at block 100
        let current_blocks = vec![(100u64, "hash100_reorged".to_string())];
        let reorg_height = check_and_rollback_reorg(&store, &current_blocks).unwrap();
        assert_eq!(reorg_height, Some(100));

        // Invoice status must revert to Pending and is_late must be cleared
        let fetched_after = store.get_by_address_index(inv.address_index).unwrap().unwrap();
        assert_eq!(fetched_after.status, InvoiceStatus::Pending);
        assert!(!fetched_after.is_late, "is_late must be cleared after reorg rollback");
    }

    #[test]
    fn test_invoice_payment_state_no_payment() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let state = invoice_payment_state(&store, inv.address_index, 100, 3).unwrap();
        assert_eq!(state, InvoicePaymentState::NoPayment);
    }

    #[test]
    fn test_invoice_payment_state_detected() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "tx_det".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 100_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: (inv.expires_at - 100) as u32,
        };
        apply_detected(&store, &[note], 100, 3).unwrap();

        // Tip 100 with confirmations 3: 1 confirmation received, 2 remaining
        let state = invoice_payment_state(&store, inv.address_index, 100, 3).unwrap();
        assert_eq!(
            state,
            InvoicePaymentState::Detected {
                received: 100_000,
                confirmations_remaining: 2,
            }
        );
    }

    #[test]
    fn test_invoice_payment_state_underpaid() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "tx_under".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 40_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: (inv.expires_at - 100) as u32,
        };
        apply_detected(&store, &[note], 105, 3).unwrap();

        let state = invoice_payment_state(&store, inv.address_index, 105, 3).unwrap();
        assert_eq!(
            state,
            InvoicePaymentState::Underpaid {
                received: 40_000,
                missing: 60_000,
            }
        );
    }

    #[test]
    fn test_invoice_payment_state_paid() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);
        let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();

        let note = DetectedNote {
            txid: "tx_paid".to_string(),
            output_index: 0,
            pool: "orchard".to_string(),
            value_zatoshi: 120_000,
            address_index: inv.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: (inv.expires_at - 100) as u32,
        };
        apply_detected(&store, &[note], 105, 3).unwrap();

        let state = invoice_payment_state(&store, inv.address_index, 105, 3).unwrap();
        assert_eq!(
            state,
            InvoicePaymentState::Paid {
                received: 120_000,
                excess: 20_000,
                late: false,
            }
        );

        // Also test Paid late
        let inv_late = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();
        let note_late = DetectedNote {
            txid: "tx_paid_late".to_string(),
            output_index: 0,
            pool: "ironwood".to_string(),
            value_zatoshi: 100_000,
            address_index: inv_late.address_index,
            block_height: 100,
            block_hash: "hash100".to_string(),
            block_time: (inv_late.expires_at + 50) as u32,
        };
        apply_detected(&store, &[note_late], 105, 3).unwrap();

        let state_late = invoice_payment_state(&store, inv_late.address_index, 105, 3).unwrap();
        assert_eq!(
            state_late,
            InvoicePaymentState::Paid {
                received: 100_000,
                excess: 0,
                late: true,
            }
        );
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
            block_time: (inv.expires_at - 100) as u32,
        };
        let note2 = DetectedNote {
            txid: "tx_reorged".to_string(),
            output_index: 0,
            pool: "ironwood".to_string(),
            value_zatoshi: 50_000,
            address_index: inv.address_index,
            block_height: 101,
            block_hash: "hash101".to_string(),
            block_time: (inv.expires_at - 50) as u32,
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

    #[test]
    fn test_plan_chunks_start_greater_than_end() {
        let chunks = plan_chunks(100, 50, 500);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_plan_chunks_empty_range() {
        let chunks = plan_chunks(100, 100, 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_plan_chunks_exact_multiple() {
        let chunks = plan_chunks(1, 1000, 500);
        assert_eq!(chunks, vec![(1, 500), (501, 1000)]);

        let chunks2 = plan_chunks(100, 599, 500);
        assert_eq!(chunks2, vec![(100, 599)]);
    }

    #[test]
    fn test_plan_chunks_remainder() {
        let chunks = plan_chunks(1, 1200, 500);
        assert_eq!(chunks, vec![(1, 500), (501, 1000), (1001, 1200)]);

        let chunks2 = plan_chunks(10, 25, 10);
        assert_eq!(chunks2, vec![(10, 19), (20, 25)]);
    }

    #[test]
    fn test_plan_chunks_single_block() {
        let chunks = plan_chunks(500, 500, 500);
        assert_eq!(chunks, vec![(500, 500)]);
    }

    #[test]
    fn test_default_error_output_contains_no_sensitive_data() {
        let viewing_key_text = "uviewtest1z67w8y90abcdef1234567890abcdef1234567890abcdef";
        let address_text = "utest1z67w8y90testaddress1234567890testaddress1234567890";
        let txid_text = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let amount_text = "50000000";

        let sensitive_source_err = anyhow!(
            "internal failure scanning key {} address {} txid {} amount {}",
            viewing_key_text,
            address_text,
            txid_text,
            amount_text
        );

        let errs = vec![
            ScanError::connect(anyhow!("connect error with {}", viewing_key_text)),
            ScanError::timeout(),
            ScanError::stream(anyhow!("stream broke on txid {}", txid_text)),
            ScanError::scan_block(3120500, sensitive_source_err),
            ScanError::database(anyhow!("db error on address {}", address_text)),
            ScanError::other(anyhow!("other error with amount {}", amount_text)),
        ];

        for err in &errs {
            let cat = err.kind.category();
            let default_log = format!("scan pass failed ({cat}), retrying in 20 seconds");

            assert!(!default_log.contains(viewing_key_text));
            assert!(!default_log.contains(address_text));
            assert!(!default_log.contains(txid_text));
            assert!(!default_log.contains(amount_text));

            match &err.kind {
                ScanErrorKind::Connect => assert_eq!(cat, "connect"),
                ScanErrorKind::Timeout => assert_eq!(cat, "timeout"),
                ScanErrorKind::Stream => assert_eq!(cat, "stream"),
                ScanErrorKind::ScanBlock { height } => {
                    assert_eq!(*height, 3120500);
                    assert!(cat.contains("3120500"));
                    assert!(cat.starts_with("scan_block"));
                }
                ScanErrorKind::Database => assert_eq!(cat, "database"),
                ScanErrorKind::Other => assert_eq!(cat, "other"),
            }
        }
    }
}
