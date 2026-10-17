use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use zcash_address::ZcashAddress;
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::Network;
use zcash_protocol::value::Zatoshis;
use zip321::{Payment, TransactionRequest};

use crate::addresses::{encode_address, invoice_address, FIRST_INVOICE_INDEX};

/// Default relative path to the SQLite database.
pub const DEFAULT_DB_PATH: &str = ".veilgate/veilgate.db";

/// Maximum ZEC supply: 21,000,000 ZEC.
pub const MAX_ZEC_SUPPLY: u64 = 21_000_000;

/// Number of zatoshis in 1 ZEC.
pub const COIN: u64 = 100_000_000;

/// Maximum allowable zatoshis across all of Zcash (21,000,000 * 10^8).
pub const MAX_ZATOSHI: u64 = MAX_ZEC_SUPPLY * COIN;

/// Status of an invoice.
///
/// Expiry is evaluated from `expires_at` at read time.
/// `Paid` is set only when marked by the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceStatus {
    Pending,
    Paid,
    Expired,
}

impl std::fmt::Display for InvoiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Paid => write!(f, "Paid"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

/// A merchant invoice record.
///
/// Privacy notes:
/// - `address_index` is internal and must never be exposed publicly.
/// - `public_id` is a 128-bit random hex value used in public URLs.
/// - No customer data (names, emails, IPs) is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// Internal monotonic diversifier index (>= FIRST_INVOICE_INDEX).
    pub address_index: u32,
    /// Random 128-bit hex string for public references and URLs.
    pub public_id: String,
    /// Amount in zatoshis (1 ZEC = 100,000,000 zatoshis).
    pub amount_zatoshi: u64,
    /// Shielded Orchard-only payment address encoded for the network.
    pub address: String,
    /// Creation timestamp in Unix epoch seconds.
    pub created_at: u64,
    /// Expiration timestamp in Unix epoch seconds.
    pub expires_at: u64,
    /// Dynamic status evaluated at read time (Pending, Paid, or Expired).
    pub status: InvoiceStatus,
    /// Flag indicating whether the invoice was marked paid after its expiration.
    pub is_late: bool,
}

impl Invoice {
    /// Builds a ZIP 321 payment URI for this invoice.
    pub fn payment_uri(&self, network: &Network) -> String {
        payment_uri(self, network)
    }
}

/// SQLite invoice storage manager.
pub struct Store {
    conn: Mutex<Connection>,
}

/// Opens an existing SQLite invoice store or initializes a new one.
///
/// Supports filesystem paths or `":memory:"` for test instances.
/// Sets up table schemas and initializes monotonic index tracking at `FIRST_INVOICE_INDEX`.
pub fn open_store(path: impl AsRef<Path>) -> Result<Store> {
    let p = path.as_ref();
    if p != Path::new(":memory:") {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }
        }
    }

    let conn = Connection::open(p)
        .with_context(|| format!("Failed to open SQLite database at: {}", p.display()))?;

    // Optimize SQLite connection settings
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;

    // Enable WAL mode if not an in-memory database
    if p != Path::new(":memory:") {
        let _ = conn.query_row("PRAGMA journal_mode = WAL;", [], |_| Ok(()));
    }

    // Initialize database schema
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS invoice_meta (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS invoices (
            address_index INTEGER NOT NULL UNIQUE,
            public_id TEXT NOT NULL UNIQUE,
            amount_zatoshi INTEGER NOT NULL,
            address TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            status TEXT NOT NULL,
            is_late INTEGER NOT NULL DEFAULT 0
         );

         CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address_index INTEGER NOT NULL,
            txid TEXT NOT NULL,
            output_index INTEGER NOT NULL,
            pool TEXT NOT NULL,
            value_zatoshi INTEGER NOT NULL,
            block_height INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            UNIQUE(txid, output_index, pool),
            FOREIGN KEY(address_index) REFERENCES invoices(address_index)
         );

         CREATE INDEX IF NOT EXISTS idx_payments_address_index ON payments(address_index);
         CREATE INDEX IF NOT EXISTS idx_payments_block_height ON payments(block_height);",
    )?;

    // Ensure is_late column exists in existing databases
    let _ = conn.execute("ALTER TABLE invoices ADD COLUMN is_late INTEGER NOT NULL DEFAULT 0", []);

    // Monotonic index setup:
    // Determine the next index, ensuring it never goes below FIRST_INVOICE_INDEX (2)
    // and never reuses any existing index (even if deletions occurred).
    let max_existing: Option<u32> = conn
        .query_row("SELECT MAX(address_index) FROM invoices", [], |row| {
            row.get(0)
        })
        .optional()?
        .flatten();

    let initial_next = match max_existing {
        Some(max_idx) => std::cmp::max(FIRST_INVOICE_INDEX, max_idx.saturating_add(1)),
        None => FIRST_INVOICE_INDEX,
    };

    conn.execute(
        "INSERT INTO invoice_meta (key, value) VALUES ('next_address_index', ?1)
         ON CONFLICT(key) DO UPDATE SET value = MAX(value, excluded.value)",
        [initial_next],
    )?;

    Ok(Store {
        conn: Mutex::new(conn),
    })
}

/// Creates a new invoice in the store.
///
/// Derives an Orchard-only shielded address using the viewing key at the next
/// monotonically allocated address index, records the invoice in SQLite,
/// and returns the `Invoice` struct.
///
/// Rejects `amount_zatoshi == 0` and amounts exceeding `MAX_ZATOSHI` (21,000,000 ZEC).
pub fn create_invoice(
    store: &Store,
    uivk: &UnifiedIncomingViewingKey,
    network: &Network,
    amount_zatoshi: u64,
    valid_for_seconds: u64,
) -> Result<Invoice> {
    if amount_zatoshi == 0 {
        return Err(anyhow!("Invoice amount must be greater than 0 zatoshis"));
    }
    if amount_zatoshi > MAX_ZATOSHI {
        return Err(anyhow!(
            "Invoice amount exceeds maximum ZEC supply of 21,000,000 ZEC"
        ));
    }

    let mut conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;

    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    // Monotonically allocate the next address index
    let current_index: u32 = tx.query_row(
        "SELECT value FROM invoice_meta WHERE key = 'next_address_index'",
        [],
        |row| row.get(0),
    )?;

    let allocated_index = std::cmp::max(current_index, FIRST_INVOICE_INDEX);
    let next_index = allocated_index
        .checked_add(1)
        .ok_or_else(|| anyhow!("Address index counter overflowed"))?;

    tx.execute(
        "UPDATE invoice_meta SET value = ?1 WHERE key = 'next_address_index'",
        [next_index],
    )?;

    // Derive Orchard-only shielded address for this index
    let ua = invoice_address(uivk, network, allocated_index)?;
    let address_str = encode_address(&ua, network);

    // Generate random 128-bit public ID (hex encoded, 32 characters)
    let mut id_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id_bytes);
    let public_id = hex_encode_128(&id_bytes);

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("System clock error: {e}"))?
        .as_secs();

    let expires_at = created_at
        .checked_add(valid_for_seconds)
        .ok_or_else(|| anyhow!("Expiration timestamp calculation overflow"))?;

    let amount_i64 = i64::try_from(amount_zatoshi)
        .map_err(|e| anyhow!("Amount exceeds i64 range: {e}"))?;
    let created_i64 = i64::try_from(created_at)
        .map_err(|e| anyhow!("Created timestamp exceeds i64 range: {e}"))?;
    let expires_i64 = i64::try_from(expires_at)
        .map_err(|e| anyhow!("Expires timestamp exceeds i64 range: {e}"))?;

    tx.execute(
        "INSERT INTO invoices (
            address_index, public_id, amount_zatoshi, address, created_at, expires_at, status, is_late
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0)",
        params![
            allocated_index,
            public_id,
            amount_i64,
            address_str,
            created_i64,
            expires_i64,
        ],
    )?;

    tx.commit()?;

    let status = if valid_for_seconds == 0 {
        InvoiceStatus::Expired
    } else {
        InvoiceStatus::Pending
    };

    Ok(Invoice {
        address_index: allocated_index,
        public_id,
        amount_zatoshi,
        address: address_str,
        created_at,
        expires_at,
        status,
        is_late: false,
    })
}

/// Retrieves an invoice by its 128-bit public ID.
///
/// Status is evaluated dynamically at read time based on `expires_at` and current Unix time.
pub fn get_by_public_id(store: &Store, id: &str) -> Result<Option<Invoice>> {
    let conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;

    let mut stmt = conn.prepare(
        "SELECT address_index, public_id, amount_zatoshi, address, created_at, expires_at, status, is_late
         FROM invoices WHERE public_id = ?1",
    )?;

    let mut rows = stmt.query([id])?;
    if let Some(row) = rows.next()? {
        let address_index: u32 = row.get(0)?;
        let public_id: String = row.get(1)?;
        let amount_i64: i64 = row.get(2)?;
        let address: String = row.get(3)?;
        let created_i64: i64 = row.get(4)?;
        let expires_i64: i64 = row.get(5)?;
        let db_status: String = row.get(6)?;
        let is_late_i64: i64 = row.get(7).unwrap_or(0);

        let amount_zatoshi = u64::try_from(amount_i64)
            .map_err(|e| anyhow!("Negative amount in database: {e}"))?;
        let created_at = u64::try_from(created_i64)
            .map_err(|e| anyhow!("Negative created_at in database: {e}"))?;
        let expires_at = u64::try_from(expires_i64)
            .map_err(|e| anyhow!("Negative expires_at in database: {e}"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let status = evaluate_status(&db_status, expires_at, now);

        Ok(Some(Invoice {
            address_index,
            public_id,
            amount_zatoshi,
            address,
            created_at,
            expires_at,
            status,
            is_late: is_late_i64 != 0,
        }))
    } else {
        Ok(None)
    }
}

/// Lists all invoices in ascending order of address index.
///
/// Status for each invoice is evaluated dynamically at read time.
pub fn list_invoices(store: &Store) -> Result<Vec<Invoice>> {
    let conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;

    let mut stmt = conn.prepare(
        "SELECT address_index, public_id, amount_zatoshi, address, created_at, expires_at, status, is_late
         FROM invoices ORDER BY address_index ASC",
    )?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let rows = stmt.query_map([], |row| {
        let address_index: u32 = row.get(0)?;
        let public_id: String = row.get(1)?;
        let amount_i64: i64 = row.get(2)?;
        let address: String = row.get(3)?;
        let created_i64: i64 = row.get(4)?;
        let expires_i64: i64 = row.get(5)?;
        let db_status: String = row.get(6)?;
        let is_late_i64: i64 = row.get(7).unwrap_or(0);

        let amount_zatoshi = u64::try_from(amount_i64)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Integer, Box::new(e)))?;
        let created_at = u64::try_from(created_i64)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Integer, Box::new(e)))?;
        let expires_at = u64::try_from(expires_i64)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Integer, Box::new(e)))?;

        let status = evaluate_status(&db_status, expires_at, now);

        Ok(Invoice {
            address_index,
            public_id,
            amount_zatoshi,
            address,
            created_at,
            expires_at,
            status,
            is_late: is_late_i64 != 0,
        })
    })?;

    let mut invoices = Vec::new();
    for inv in rows {
        invoices.push(inv?);
    }
    Ok(invoices)
}

/// Marks an invoice as paid.
///
/// Intended for use by the future payment scanner. Returns `true` if an invoice
/// with the given `public_id` was found and updated, `false` otherwise.
pub fn mark_paid(store: &Store, public_id: &str) -> Result<bool> {
    store.mark_paid(public_id)
}

/// A record of a detected shielded payment output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRecord {
    pub address_index: u32,
    pub txid: String,
    pub output_index: u32,
    pub pool: String,
    pub value_zatoshi: u64,
    pub block_height: u64,
    pub block_hash: String,
}

/// Summary of all payments and confirmation status for an invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentSummary {
    pub address_index: u32,
    pub amount_zatoshi: u64,
    pub total_detected_zatoshi: u64,
    pub total_confirmed_zatoshi: u64,
    pub excess_zatoshi: u64,
    pub is_paid: bool,
    pub is_late: bool,
    pub payments: Vec<PaymentRecord>,
}

/// Retrieves an invoice by its internal address index.
pub fn get_by_address_index(store: &Store, index: u32) -> Result<Option<Invoice>> {
    let conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;

    let mut stmt = conn.prepare(
        "SELECT address_index, public_id, amount_zatoshi, address, created_at, expires_at, status, is_late
         FROM invoices WHERE address_index = ?1",
    )?;

    let mut rows = stmt.query([index])?;
    if let Some(row) = rows.next()? {
        let address_index: u32 = row.get(0)?;
        let public_id: String = row.get(1)?;
        let amount_i64: i64 = row.get(2)?;
        let address: String = row.get(3)?;
        let created_i64: i64 = row.get(4)?;
        let expires_i64: i64 = row.get(5)?;
        let db_status: String = row.get(6)?;
        let is_late_i64: i64 = row.get(7).unwrap_or(0);

        let amount_zatoshi = u64::try_from(amount_i64)
            .map_err(|e| anyhow!("Negative amount in database: {e}"))?;
        let created_at = u64::try_from(created_i64)
            .map_err(|e| anyhow!("Negative created_at in database: {e}"))?;
        let expires_at = u64::try_from(expires_i64)
            .map_err(|e| anyhow!("Negative expires_at in database: {e}"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let status = evaluate_status(&db_status, expires_at, now);

        Ok(Some(Invoice {
            address_index,
            public_id,
            amount_zatoshi,
            address,
            created_at,
            expires_at,
            status,
            is_late: is_late_i64 != 0,
        }))
    } else {
        Ok(None)
    }
}

/// Marks an invoice as paid by address index, specifying whether the payment was confirmed late.
pub fn mark_paid_by_index(store: &Store, address_index: u32, is_late: bool) -> Result<bool> {
    let conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;
    let rows = conn.execute(
        "UPDATE invoices SET status = 'paid', is_late = ?1 WHERE address_index = ?2",
        params![if is_late { 1i64 } else { 0i64 }, address_index],
    )?;
    Ok(rows > 0)
}

/// Retrieves all payment records stored for a given invoice.
pub fn get_payments_for_invoice(store: &Store, address_index: u32) -> Result<Vec<PaymentRecord>> {
    let conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;

    let mut stmt = conn.prepare(
        "SELECT address_index, txid, output_index, pool, value_zatoshi, block_height, block_hash
         FROM payments WHERE address_index = ?1 ORDER BY block_height ASC, output_index ASC",
    )?;

    let rows = stmt.query_map([address_index], |row| {
        let address_index: u32 = row.get(0)?;
        let txid: String = row.get(1)?;
        let output_index: u32 = row.get(2)?;
        let pool: String = row.get(3)?;
        let val_i64: i64 = row.get(4)?;
        let height_i64: i64 = row.get(5)?;
        let block_hash: String = row.get(6)?;

        Ok(PaymentRecord {
            address_index,
            txid,
            output_index,
            pool,
            value_zatoshi: val_i64 as u64,
            block_height: height_i64 as u64,
            block_hash,
        })
    })?;

    let mut payments = Vec::new();
    for p in rows {
        payments.push(p?);
    }
    Ok(payments)
}

/// Computes a payment summary for an invoice given current chain tip and required confirmation count.
pub fn get_payment_summary(
    store: &Store,
    address_index: u32,
    tip_height: u64,
    confirmations: u32,
) -> Result<Option<PaymentSummary>> {
    let inv = match get_by_address_index(store, address_index)? {
        Some(i) => i,
        None => return Ok(None),
    };

    let payments = get_payments_for_invoice(store, address_index)?;

    let mut total_detected_zatoshi: u64 = 0;
    let mut total_confirmed_zatoshi: u64 = 0;

    for p in &payments {
        total_detected_zatoshi = total_detected_zatoshi.saturating_add(p.value_zatoshi);
        let confs = if tip_height >= p.block_height {
            tip_height - p.block_height + 1
        } else {
            0
        };
        if confs >= confirmations as u64 {
            total_confirmed_zatoshi = total_confirmed_zatoshi.saturating_add(p.value_zatoshi);
        }
    }

    let excess_zatoshi = total_confirmed_zatoshi.saturating_sub(inv.amount_zatoshi);
    let is_paid = inv.status == InvoiceStatus::Paid;

    Ok(Some(PaymentSummary {
        address_index,
        amount_zatoshi: inv.amount_zatoshi,
        total_detected_zatoshi,
        total_confirmed_zatoshi,
        excess_zatoshi,
        is_paid,
        is_late: inv.is_late,
        payments,
    }))
}

/// Retrieves the last scanned block height from invoice_meta.
pub fn get_last_scanned_height(store: &Store) -> Result<Option<u64>> {
    let conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;
    let val: Option<i64> = conn
        .query_row(
            "SELECT value FROM invoice_meta WHERE key = 'last_scanned_height'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(val.map(|v| v as u64))
}

/// Stores the last scanned block height in invoice_meta.
pub fn set_last_scanned_height(store: &Store, height: u64) -> Result<()> {
    let conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;
    conn.execute(
        "INSERT INTO invoice_meta (key, value) VALUES ('last_scanned_height', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [height as i64],
    )?;
    Ok(())
}

/// Deletes all payments at or above the given block height (used during chain reorganization).
/// Automatically reverts any invoices marked paid whose remaining confirmed payments fall below amount_zatoshi.
pub fn delete_payments_from_height(store: &Store, height: u64) -> Result<usize> {
    let mut conn = store
        .conn
        .lock()
        .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;
    let tx = conn.transaction()?;

    let affected_indices: Vec<u32> = {
        let mut stmt = tx.prepare(
            "SELECT DISTINCT address_index FROM payments WHERE block_height >= ?1",
        )?;
        let rows = stmt
            .query_map([height as i64], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };

    let deleted = tx.execute(
        "DELETE FROM payments WHERE block_height >= ?1",
        [height as i64],
    )?;

    // For any affected invoice, re-check whether remaining payments still suffice
    for idx in affected_indices {
        let (amount_i64, status): (i64, String) = tx.query_row(
            "SELECT amount_zatoshi, status FROM invoices WHERE address_index = ?1",
            [idx],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let amount_zatoshi = amount_i64 as u64;

        if status == "paid" {
            let remaining: i64 = tx.query_row(
                "SELECT COALESCE(SUM(value_zatoshi), 0) FROM payments WHERE address_index = ?1",
                [idx],
                |row| row.get(0),
            )?;
            if (remaining as u64) < amount_zatoshi {
                tx.execute(
                    "UPDATE invoices SET status = 'pending', is_late = 0 WHERE address_index = ?1",
                    [idx],
                )?;
            }
        }
    }

    tx.commit()?;
    Ok(deleted)
}

impl Store {
    /// Returns reference to internal mutex-guarded SQLite connection.
    pub fn conn(&self) -> &Mutex<Connection> {
        &self.conn
    }

    /// Marks an invoice as paid by its public ID.
    pub fn mark_paid(&self, public_id: &str) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {e}"))?;
        let rows = conn.execute(
            "UPDATE invoices SET status = 'paid' WHERE public_id = ?1",
            [public_id],
        )?;
        Ok(rows > 0)
    }

    /// Creates an invoice within this store.
    pub fn create_invoice(
        &self,
        uivk: &UnifiedIncomingViewingKey,
        network: &Network,
        amount_zatoshi: u64,
        valid_for_seconds: u64,
    ) -> Result<Invoice> {
        create_invoice(self, uivk, network, amount_zatoshi, valid_for_seconds)
    }

    /// Retrieves an invoice by public ID within this store.
    pub fn get_by_public_id(&self, id: &str) -> Result<Option<Invoice>> {
        get_by_public_id(self, id)
    }

    /// Retrieves an invoice by address index within this store.
    pub fn get_by_address_index(&self, index: u32) -> Result<Option<Invoice>> {
        get_by_address_index(self, index)
    }

    /// Marks an invoice as paid by address index.
    pub fn mark_paid_by_index(&self, address_index: u32, is_late: bool) -> Result<bool> {
        mark_paid_by_index(self, address_index, is_late)
    }

    /// Lists all invoices in this store.
    pub fn list_invoices(&self) -> Result<Vec<Invoice>> {
        list_invoices(self)
    }

    /// Retrieves all payments for an invoice.
    pub fn get_payments_for_invoice(&self, address_index: u32) -> Result<Vec<PaymentRecord>> {
        get_payments_for_invoice(self, address_index)
    }

    /// Gets payment summary for an invoice.
    pub fn get_payment_summary(
        &self,
        address_index: u32,
        tip_height: u64,
        confirmations: u32,
    ) -> Result<Option<PaymentSummary>> {
        get_payment_summary(self, address_index, tip_height, confirmations)
    }

    /// Gets last scanned block height.
    pub fn get_last_scanned_height(&self) -> Result<Option<u64>> {
        get_last_scanned_height(self)
    }

    /// Sets last scanned block height.
    pub fn set_last_scanned_height(&self, height: u64) -> Result<()> {
        set_last_scanned_height(self, height)
    }

    /// Rolls back payments from the given block height.
    pub fn delete_payments_from_height(&self, height: u64) -> Result<usize> {
        delete_payments_from_height(self, height)
    }
}

/// Constructs a ZIP 321 payment URI string for an invoice.
///
/// Features:
/// - Strictly NO memo.
/// - Generic message text: `"VeilGate invoice"`.
/// - Amount in ZEC computed using integer division and modulo (never floats).
/// - Testnet-compatible unified addresses.
pub fn payment_uri(invoice: &Invoice, _network: &Network) -> String {
    let zaddr = ZcashAddress::try_from_encoded(&invoice.address)
        .expect("Invoice must contain a valid encoded Zcash address");
    let zatoshis = Zatoshis::from_u64(invoice.amount_zatoshi)
        .expect("Invoice must contain a valid zatoshi amount (<= 21,000,000 ZEC)");

    let payment = Payment::new(
        zaddr,
        Some(zatoshis),
        None, // Strictly NO memo
        None, // No label
        Some("VeilGate invoice".to_string()),
        vec![],
    )
    .expect("ZIP 321 payment parameters must be valid");

    let req = TransactionRequest::new(vec![payment])
        .expect("ZIP 321 transaction request must be valid");

    req.to_uri()
}

/// Formats a zatoshi amount as a ZEC decimal string using strictly integer math.
///
/// Follows ZIP 321 decimal rules: up to 8 decimal places, trailing fractional zeros omitted.
/// Never uses floating point numbers.
pub fn format_zec_amount(amount_zatoshi: u64) -> Result<String> {
    if amount_zatoshi == 0 {
        return Err(anyhow!("Amount must be greater than 0"));
    }
    if amount_zatoshi > MAX_ZATOSHI {
        return Err(anyhow!(
            "Amount exceeds maximum ZEC supply of 21,000,000 ZEC"
        ));
    }

    let whole = amount_zatoshi / COIN;
    let frac = amount_zatoshi % COIN;

    if frac == 0 {
        Ok(format!("{whole}"))
    } else {
        let frac_str = format!("{:08}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        Ok(format!("{whole}.{trimmed}"))
    }
}

/// Evaluates invoice status based on stored database status, expiry, and current time.
fn evaluate_status(db_status: &str, expires_at: u64, now: u64) -> InvoiceStatus {
    if db_status == "paid" {
        InvoiceStatus::Paid
    } else if now >= expires_at {
        InvoiceStatus::Expired
    } else {
        InvoiceStatus::Pending
    }
}

/// Formats a 16-byte slice into a 32-character lowercase hex string.
fn hex_encode_128(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
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
    use zcash_keys::address::UnifiedAddress;
    use zcash_keys::encoding::AddressCodec;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

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
    fn test_monotonic_and_unique_indices() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let count = 30;
        let mut prev_index = FIRST_INVOICE_INDEX - 1;
        let mut seen_indices = std::collections::HashSet::new();

        for i in 0..count {
            let inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();
            assert_eq!(
                inv.address_index,
                prev_index + 1,
                "Index must increment monotonically by 1 at step {i}"
            );
            assert!(
                inv.address_index >= FIRST_INVOICE_INDEX,
                "Index must be >= FIRST_INVOICE_INDEX"
            );
            assert!(
                seen_indices.insert(inv.address_index),
                "Index {} must be unique",
                inv.address_index
            );
            prev_index = inv.address_index;
        }

        // Test deletion resilience: deleting an invoice must NOT cause its index to be reused
        {
            let conn = store.conn.lock().unwrap();
            conn.execute("DELETE FROM invoices WHERE address_index = 5", [])
                .unwrap();
        }

        let next_inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();
        assert_eq!(
            next_inv.address_index,
            prev_index + 1,
            "Next index must continue monotonically even after deletion"
        );
    }

    #[test]
    fn test_two_invoices_never_share_an_address() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let mut seen_addresses = std::collections::HashSet::new();
        for _ in 0..20 {
            let inv = create_invoice(&store, &uivk, &net, 500_000, 3600).unwrap();
            assert!(
                seen_addresses.insert(inv.address.clone()),
                "Every invoice must have a distinct shielded address"
            );
        }
    }

    #[test]
    fn test_public_ids_differ_and_are_32_hex_chars() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let mut seen_ids = std::collections::HashSet::new();
        for _ in 0..25 {
            let inv = create_invoice(&store, &uivk, &net, 10_000, 3600).unwrap();
            assert_eq!(
                inv.public_id.len(),
                32,
                "Public ID must be exactly 32 characters"
            );
            assert!(
                inv.public_id.chars().all(|c| c.is_ascii_hexdigit()),
                "Public ID must be valid hex characters"
            );
            assert!(
                seen_ids.insert(inv.public_id.clone()),
                "Public IDs must be unique"
            );
        }
    }

    #[test]
    fn test_amount_conversion_edge_cases() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        // 0 rejected
        let zero_res = create_invoice(&store, &uivk, &net, 0, 3600);
        assert!(zero_res.is_err(), "Amount 0 must be rejected");

        // Overflow rejected (> MAX_ZATOSHI)
        let overflow_res = create_invoice(&store, &uivk, &net, MAX_ZATOSHI + 1, 3600);
        assert!(
            overflow_res.is_err(),
            "Amounts above MAX_ZATOSHI must be rejected"
        );

        let max_u64_res = create_invoice(&store, &uivk, &net, u64::MAX, 3600);
        assert!(max_u64_res.is_err(), "u64::MAX amount must be rejected");

        // 1 zatoshi accepted
        let inv_1zat = create_invoice(&store, &uivk, &net, 1, 3600).unwrap();
        let uri_1zat = payment_uri(&inv_1zat, &net);
        assert!(uri_1zat.contains("amount=0.00000001"));
        assert_eq!(format_zec_amount(1).unwrap(), "0.00000001");

        // 1 ZEC (100,000,000 zatoshis) accepted
        let inv_1zec = create_invoice(&store, &uivk, &net, COIN, 3600).unwrap();
        let uri_1zec = payment_uri(&inv_1zec, &net);
        assert!(uri_1zec.contains("amount=1&") || uri_1zec.ends_with("amount=1"));
        assert_eq!(format_zec_amount(COIN).unwrap(), "1");

        // 1.5 ZEC (150,000,000 zatoshis) accepted
        let inv_1_5zec = create_invoice(&store, &uivk, &net, 150_000_000, 3600).unwrap();
        let uri_1_5zec = payment_uri(&inv_1_5zec, &net);
        assert!(uri_1_5zec.contains("amount=1.5"));
        assert_eq!(format_zec_amount(150_000_000).unwrap(), "1.5");

        // 21,000,000 ZEC accepted
        let inv_21m = create_invoice(&store, &uivk, &net, MAX_ZATOSHI, 3600).unwrap();
        let uri_21m = payment_uri(&inv_21m, &net);
        assert!(uri_21m.contains("amount=21000000"));
        assert_eq!(format_zec_amount(MAX_ZATOSHI).unwrap(), "21000000");
    }

    #[test]
    fn test_expiry_is_detected_at_read_time() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        // Invoice with 0 validity is expired immediately
        let expired_inv = create_invoice(&store, &uivk, &net, 100_000, 0).unwrap();
        assert_eq!(expired_inv.status, InvoiceStatus::Expired);

        // Fetching it back from the store also evaluates it as Expired
        let fetched = get_by_public_id(&store, &expired_inv.public_id)
            .unwrap()
            .expect("invoice should be found");
        assert_eq!(fetched.status, InvoiceStatus::Expired);

        // Active invoice with 1 hour validity is Pending
        let active_inv = create_invoice(&store, &uivk, &net, 100_000, 3600).unwrap();
        assert_eq!(active_inv.status, InvoiceStatus::Pending);

        let fetched_active = get_by_public_id(&store, &active_inv.public_id)
            .unwrap()
            .expect("invoice should be found");
        assert_eq!(fetched_active.status, InvoiceStatus::Pending);

        // Manually updating expires_at to the past triggers Expired status on next read
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE invoices SET expires_at = created_at - 100 WHERE public_id = ?1",
                [&active_inv.public_id],
            )
            .unwrap();
        }

        let fetched_now_expired = get_by_public_id(&store, &active_inv.public_id)
            .unwrap()
            .expect("invoice should be found");
        assert_eq!(fetched_now_expired.status, InvoiceStatus::Expired);

        // Marking an invoice as paid overrides expiry
        let marked = mark_paid(&store, &active_inv.public_id).unwrap();
        assert!(marked);

        let fetched_paid = get_by_public_id(&store, &active_inv.public_id)
            .unwrap()
            .expect("invoice should be found");
        assert_eq!(fetched_paid.status, InvoiceStatus::Paid);
    }

    #[test]
    fn test_uri_contains_no_memo_and_has_generic_message() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        let inv = create_invoice(&store, &uivk, &net, 150_000_000, 3600).unwrap();
        let uri = payment_uri(&inv, &net);

        // Must start with zcash:
        assert!(uri.starts_with("zcash:"));
        // Must NOT contain memo
        assert!(
            !uri.contains("memo="),
            "Payment URI must NOT contain a memo parameter"
        );
        // Must contain generic message
        assert!(
            uri.contains("message=VeilGate%20invoice") || uri.contains("message=VeilGate+invoice"),
            "Payment URI must contain generic 'VeilGate invoice' message"
        );
        // Must not contain any customer or merchant identifying info
        assert!(!uri.contains("email"));
        assert!(!uri.contains("customer"));
        assert!(!uri.contains("name"));
    }

    #[test]
    fn test_stored_address_roundtrips_through_find_invoice_index() {
        let store = open_store(":memory:").unwrap();
        let net = Network::TestNetwork;
        let uivk = test_uivk(&net);

        for _ in 0..5 {
            let inv = create_invoice(&store, &uivk, &net, 250_000, 3600).unwrap();

            // Decode stored address string back to UnifiedAddress
            let ua = UnifiedAddress::decode(&net, &inv.address)
                .expect("Stored address must be decodable as UnifiedAddress");

            // Recover diversifier index using viewing key
            let recovered = crate::addresses::find_invoice_index(&uivk, &ua);
            assert_eq!(
                recovered,
                Some(inv.address_index),
                "Address index recovered from Orchard diversifier must match stored address_index"
            );
        }
    }
}
