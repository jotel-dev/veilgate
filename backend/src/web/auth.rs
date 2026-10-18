//! Merchant authentication, Argon2 password hashing, session management, and CSRF protection.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;

use subtle::ConstantTimeEq;

pub const SESSION_COOKIE_NAME: &str = "veilgate_session";
pub const CSRF_COOKIE_NAME: &str = "veilgate_csrf";
pub const SESSION_DURATION: Duration = Duration::from_secs(4 * 3600); // 4 hours
pub const SESSION_MAX_AGE_SECS: u64 = 4 * 3600;
pub const MAX_LIVE_SESSIONS: usize = 20;

/// Constant-time string comparison using the subtle crate.
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    a_bytes.ct_eq(b_bytes).into()
}

/// Validates that a CSRF token matches exactly 64 lowercase hex characters.
pub fn is_valid_csrf_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub csrf_token: String,
    pub created_at: Instant,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Generates a cryptographic 256-bit random hex string.
    pub fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let mut s = String::with_capacity(64);
        for b in &bytes {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    /// Creates and stores a new authenticated session.
    pub fn create_session(&self) -> Session {
        let token = Self::generate_token();
        let csrf_token = Self::generate_token();
        let now = Instant::now();
        let session = Session {
            token: token.clone(),
            csrf_token,
            created_at: now,
            expires_at: now + SESSION_DURATION,
        };

        let mut lock = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Prune expired sessions
        lock.retain(|_, s| s.expires_at > now);

        // Cap live sessions at MAX_LIVE_SESSIONS (20): drop oldest if full
        while lock.len() >= MAX_LIVE_SESSIONS {
            if let Some(oldest_token) = lock
                .values()
                .min_by_key(|s| s.created_at)
                .map(|s| s.token.clone())
            {
                lock.remove(&oldest_token);
            } else {
                break;
            }
        }

        lock.insert(token, session.clone());
        session
    }

    /// Retrieves an active session by token using constant-time comparison.
    pub fn get_session(&self, token: &str) -> Option<Session> {
        let mut lock = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        let matched_token = lock
            .values()
            .find(|s| constant_time_compare(&s.token, token))
            .map(|s| s.token.clone());

        if let Some(t) = matched_token {
            if let Some(s) = lock.get(&t) {
                if s.expires_at > now {
                    return Some(s.clone());
                }
            }
            lock.remove(&t);
        }
        None
    }

    /// Removes a session upon logout using constant-time comparison.
    pub fn remove_session(&self, token: &str) {
        let mut lock = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let matched_token = lock
            .values()
            .find(|s| constant_time_compare(&s.token, token))
            .map(|s| s.token.clone());
        if let Some(t) = matched_token {
            lock.remove(&t);
        }
    }

    /// Returns the number of currently stored sessions (active and unpruned).
    pub fn session_count(&self) -> usize {
        let lock = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        lock.len()
    }
}

/// Hashes a plaintext password using Argon2id with random salt.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {}", e))?
        .to_string();
    Ok(hash)
}

/// Verifies a password against an Argon2 password hash.
pub fn verify_password(password: &str, hash_str: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash_str) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}
