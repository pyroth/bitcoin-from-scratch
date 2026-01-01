//! Simple Bitcoin - Rust Implementation
//!
//! A educational Bitcoin library demonstrating core concepts.

use bitcoin::{gen_key_pair, keys::Network};

fn main() {
    println!("Simple Bitcoin - Rust Implementation");

    // Generate a new key pair
    let (sk, pk) = gen_key_pair();
    println!("\nGenerated new key pair:");
    println!("  Secret key: {sk:064x}");
    println!("  Public key: {}", hex::encode(pk.encode(true)));

    // Generate addresses for both networks
    let mainnet_addr = pk.address(Network::Main, true);
    let testnet_addr = pk.address(Network::Test, true);
    println!("\nBitcoin addresses:");
    println!("  Mainnet: {mainnet_addr}");
    println!("  Testnet: {testnet_addr}");
}
