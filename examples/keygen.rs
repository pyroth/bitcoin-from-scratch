//! Generate Bitcoin key pairs and addresses
//!
//! Run with: cargo run --example keygen

use bitcoin::{gen_key_pair, PublicKey};

fn main() {
    println!("=== Bitcoin Key Generation ===\n");

    // Generate a random key pair
    let (secret_key, public_key) = gen_key_pair();

    println!("Secret Key (hex):");
    println!("  {:064x}\n", secret_key);

    println!("Public Key (compressed):");
    println!("  {}\n", hex::encode(public_key.encode(true)));

    println!("Public Key (uncompressed):");
    println!("  {}\n", hex::encode(public_key.encode(false)));

    // Generate addresses
    println!("Bitcoin Addresses:");
    println!("  Mainnet: {}", public_key.address("main", true));
    println!("  Testnet: {}", public_key.address("test", true));

    // Derive from known secret key (Mastering Bitcoin example)
    println!("\n=== Known Key Derivation ===\n");
    let known_sk = "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6";
    let pk = PublicKey::from_sk_hex(known_sk);

    println!("Secret Key: {}", known_sk);
    println!("Address:    {}", pk.address("main", true));
    println!("Expected:   14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3");
}
