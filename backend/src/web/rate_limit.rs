//! In-memory rate limiting for sensitive endpoints (login, status, demo).
//!
//! Privacy & hygiene:
//! - Keys for client identities are salted SHA-256 hashes using a per-process random salt.
//! - Raw IP addresses are NEVER stored in keys or records.
//! - Expired keys are purged periodically and when map capacity is reached.
//! - Map capacity is capped at 10,000 keys, dropping oldest when full.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use sha2::{Digest, Sha256};

pub const DEFAULT_MAX_KEYS: usize = 10_000;
pub const PURGE_INTERVAL_CALLS: usize = 50;

#[derive(Debug)]
struct ClientRecord {
    timestamps: Vec<Instant>,
    window: Duration,
    last_updated: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    salt: [u8; 32],
    max_keys: usize,
    call_count: AtomicUsize,
    records: Mutex<HashMap<String, ClientRecord>>,
}

impl RateLimiter {
    /// Creates a new RateLimiter with default 10,000 key capacity and a random per-process salt.
    pub fn new() -> Self {
        Self::new_with_capacity(DEFAULT_MAX_KEYS)
    }

    /// Creates a new RateLimiter with specified key capacity and random per-process salt.
    pub fn new_with_capacity(max_keys: usize) -> Self {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            salt,
            max_keys,
            call_count: AtomicUsize::new(0),
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Derives a salted hash key for a given action and client identity.
    ///
    /// Never includes the raw IP or client identity in the key.
    pub fn client_key(&self, action: &str, client_identity: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(b":");
        hasher.update(action.as_bytes());
        hasher.update(b":");
        hasher.update(client_identity.as_bytes());
        let hash_hex = format!("{:x}", hasher.finalize());
        format!("{action}:{hash_hex}")
    }

    /// Checks if a request is allowed given a rate limit of `max_requests` per `window`.
    /// Returns `true` if allowed, `false` if rate limit is exceeded.
    pub fn check_and_record(&self, key: &str, max_requests: usize, window: Duration) -> bool {
        let now = Instant::now();
        let calls = self.call_count.fetch_add(1, Ordering::Relaxed);

        let mut map = match self.records.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Purge expired keys on every Nth call
        if calls % PURGE_INTERVAL_CALLS == 0 {
            Self::purge_expired_internal(&mut map, now);
        }

        // If map is full and key does not exist yet, purge expired keys
        if !map.contains_key(key) && map.len() >= self.max_keys {
            Self::purge_expired_internal(&mut map, now);
        }

        // If still full, drop the oldest record
        if !map.contains_key(key) && map.len() >= self.max_keys {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, r)| r.last_updated)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }

        let record = map.entry(key.to_string()).or_insert_with(|| ClientRecord {
            timestamps: Vec::new(),
            window,
            last_updated: now,
        });

        record.window = window;
        record.last_updated = now;
        record.timestamps.retain(|t| now.duration_since(*t) < window);

        if record.timestamps.len() >= max_requests {
            false
        } else {
            record.timestamps.push(now);
            true
        }
    }

    fn purge_expired_internal(map: &mut HashMap<String, ClientRecord>, now: Instant) {
        map.retain(|_k, rec| {
            rec.timestamps.retain(|t| now.duration_since(*t) < rec.window);
            !rec.timestamps.is_empty()
        });
    }

    /// Purges all expired keys across the entire rate limiter map.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        let mut map = match self.records.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        Self::purge_expired_internal(&mut map, now);
    }

    /// Returns the current number of keys in the rate limiter map.
    pub fn key_count(&self) -> usize {
        let map = match self.records.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        map.len()
    }

    /// Returns all current keys in the rate limiter map.
    pub fn all_keys(&self) -> Vec<String> {
        let map = match self.records.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        map.keys().cloned().collect()
    }

    /// Checks if any key contains the given needle substring (used to verify no raw IPs).
    pub fn contains_raw_string_in_any_key(&self, needle: &str) -> bool {
        let map = match self.records.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        map.keys().any(|k| k.contains(needle))
    }
}
