//! Demonstrate Bitcoin hash functions
//!
//! Run with: cargo run --example hash_demo

use bitcoin::ripemd160::{hash160, ripemd160};
use bitcoin::sha256::{hash256, sha256};

fn main() {
    println!("=== Bitcoin Hash Functions ===\n");

    let data = b"Hello, Bitcoin!";
    println!("Input: {:?}\n", String::from_utf8_lossy(data));

    // SHA-256
    let sha = sha256(data);
    println!("SHA-256:");
    println!("  {}\n", hex::encode(sha));

    // Double SHA-256 (HASH256) - used for block hashes, tx IDs
    let hash256_result = hash256(data);
    println!("HASH256 (double SHA-256):");
    println!("  {}\n", hex::encode(hash256_result));

    // RIPEMD-160
    let ripemd = ripemd160(data);
    println!("RIPEMD-160:");
    println!("  {}\n", hex::encode(ripemd));

    // HASH160 - used for Bitcoin addresses
    let hash160_result = hash160(data);
    println!("HASH160 (RIPEMD160(SHA256(x))):");
    println!("  {}\n", hex::encode(hash160_result));

    // Show address generation flow
    println!("=== Address Generation Flow ===\n");

    let pubkey_hex = "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1";
    let pubkey = hex::decode(pubkey_hex).unwrap();

    println!("1. Compressed Public Key:");
    println!("   {}\n", pubkey_hex);

    let step1 = sha256(&pubkey);
    println!("2. SHA-256:");
    println!("   {}\n", hex::encode(step1));

    let step2 = ripemd160(&step1);
    println!("3. RIPEMD-160 (pubkey hash):");
    println!("   {}\n", hex::encode(step2));

    println!("4. Add version byte (0x00 for mainnet)");
    println!("5. Calculate checksum (first 4 bytes of HASH256)");
    println!("6. Base58Check encode -> Bitcoin address");
}
