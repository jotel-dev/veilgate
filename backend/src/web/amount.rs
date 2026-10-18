//! Integer-only ZEC and zatoshi parsing and formatting.
//!
//! No floating point arithmetic is used to prevent precision loss.

pub const COIN: u64 = 100_000_000; // 1 ZEC = 10^8 zatoshis
pub const MAX_ZEC_SUPPLY: u64 = 21_000_000;
pub const MAX_ZATOSHI: u64 = MAX_ZEC_SUPPLY * COIN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountParseError {
    Empty,
    InvalidCharacter(char),
    Negative,
    MultipleDecimals,
    TooManyDecimals,
    Overflow,
    ZeroAmount,
    ExceedsMaxSupply,
}

impl std::fmt::Display for AmountParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Amount string cannot be empty"),
            Self::InvalidCharacter(c) => write!(f, "Amount contains invalid character: '{c}'"),
            Self::Negative => write!(f, "Amount cannot be negative"),
            Self::MultipleDecimals => write!(f, "Multiple decimal points found"),
            Self::TooManyDecimals => write!(f, "Too many decimal places (maximum 8 decimal places for Zcash)"),
            Self::Overflow => write!(f, "Integer overflow in amount calculation"),
            Self::ZeroAmount => write!(f, "Amount must be greater than zero"),
            Self::ExceedsMaxSupply => write!(f, "Amount exceeds maximum Zcash supply of 21,000,000 ZEC"),
        }
    }
}

impl AmountParseError {
    /// Returns a fixed, generic error message suitable for user-facing pages,
    /// ensuring no user input is reflected back.
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::Empty => "Amount string cannot be empty.",
            Self::InvalidCharacter(_) => "Amount contains an invalid character. Please enter a valid number.",
            Self::Negative => "Amount cannot be negative.",
            Self::MultipleDecimals => "Multiple decimal points found.",
            Self::TooManyDecimals => "Too many decimal places (maximum 8 decimal places for Zcash).",
            Self::Overflow => "Amount is too large.",
            Self::ZeroAmount => "Amount must be greater than zero.",
            Self::ExceedsMaxSupply => "Amount exceeds maximum Zcash supply of 21,000,000 ZEC.",
        }
    }
}

impl std::error::Error for AmountParseError {}

/// Parses a decimal ZEC string (e.g. "1.5", "0.001", "12") into zatoshis using integer-only math.
pub fn parse_zec_amount(input: &str) -> Result<u64, AmountParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(AmountParseError::Empty);
    }

    if s.starts_with('-') {
        return Err(AmountParseError::Negative);
    }
    if s.starts_with('+') {
        return Err(AmountParseError::InvalidCharacter('+'));
    }

    let mut parts = s.split('.');
    let whole_str = parts.next().unwrap_or("");
    let frac_str_opt = parts.next();
    if parts.next().is_some() {
        return Err(AmountParseError::MultipleDecimals);
    }

    let whole: u64 = if whole_str.is_empty() {
        0
    } else {
        for c in whole_str.chars() {
            if !c.is_ascii_digit() {
                return Err(AmountParseError::InvalidCharacter(c));
            }
        }
        whole_str
            .parse::<u64>()
            .map_err(|_| AmountParseError::Overflow)?
    };

    let frac: u64 = if let Some(frac_str) = frac_str_opt {
        if frac_str.len() > 8 {
            return Err(AmountParseError::TooManyDecimals);
        }
        for c in frac_str.chars() {
            if !c.is_ascii_digit() {
                return Err(AmountParseError::InvalidCharacter(c));
            }
        }
        // Pad to 8 decimal places with zeros (e.g. "5" -> "50000000")
        let mut padded = String::from(frac_str);
        while padded.len() < 8 {
            padded.push('0');
        }
        if padded.is_empty() {
            0
        } else {
            padded
                .parse::<u64>()
                .map_err(|_| AmountParseError::Overflow)?
        }
    } else {
        0
    };

    let whole_zatoshis = whole
        .checked_mul(COIN)
        .ok_or(AmountParseError::Overflow)?;

    let total = whole_zatoshis
        .checked_add(frac)
        .ok_or(AmountParseError::Overflow)?;

    if total == 0 {
        return Err(AmountParseError::ZeroAmount);
    }
    if total > MAX_ZATOSHI {
        return Err(AmountParseError::ExceedsMaxSupply);
    }

    Ok(total)
}

/// Formats zatoshis into a clean decimal string without floating point operations.
/// Example: 150_000_000 -> "1.5", 100_000_000 -> "1.0", 100_000 -> "0.001"
pub fn format_zec_amount(zatoshis: u64) -> String {
    let whole = zatoshis / COIN;
    let frac = zatoshis % COIN;
    if frac == 0 {
        format!("{}.0", whole)
    } else {
        let s = format!("{:08}", frac);
        let trimmed = s.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    }
}

/// Formats zatoshis into a display string with ZEC unit.
pub fn format_zec_display(zatoshis: u64) -> String {
    format!("{} ZEC", format_zec_amount(zatoshis))
}
