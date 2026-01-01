//! Simple Bitcoin library - Rust implementation
//!
//! A educational Bitcoin library ported from Python for learning purposes.

pub mod bitcoin;
pub mod block;
pub mod curves;
pub mod ecdsa;
pub mod error;
pub mod keys;
pub mod network;
pub mod ripemd160;
pub mod script;
pub mod sha256;
pub mod transaction;

pub use error::{BitcoinError, Result};

pub use bitcoin::BITCOIN;
pub use block::Block;
pub use curves::{Curve, Generator, Point};
pub use ecdsa::{Signature, sign, verify};
pub use keys::{
    Network, PublicKey, address_to_pkb_hash, b58decode, b58encode, gen_key_pair, gen_secret_key,
};
pub use script::Script;
pub use transaction::{Tx, TxFetcher, TxIn, TxOut};
