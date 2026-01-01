//! Unified error types for the bitcoin library

use thiserror::Error;

/// Main error type for the bitcoin library
#[derive(Debug, Error)]
pub enum BitcoinError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<&str> for BitcoinError {
    fn from(s: &str) -> Self {
        BitcoinError::Parse(s.to_string())
    }
}

impl From<hex::FromHexError> for BitcoinError {
    fn from(e: hex::FromHexError) -> Self {
        BitcoinError::Parse(e.to_string())
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, BitcoinError>;
