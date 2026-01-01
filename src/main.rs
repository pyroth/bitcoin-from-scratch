//! Simple Bitcoin - Rust Implementation
//!
//! A educational Bitcoin library demonstrating core concepts.

use bitcoin::gen_key_pair;

fn main() {
    println!("Simple Bitcoin - Rust Implementation");

    // Generate a new key pair
    let (sk, pk) = gen_key_pair();
    println!("\nGenerated new key pair:");
    println!("  Secret key: {:064x}", sk);
    println!("  Public key: {}", hex::encode(pk.encode(true)));

    // Generate addresses for both networks
    let mainnet_addr = pk.address("main", true);
    let testnet_addr = pk.address("test", true);
    println!("\nBitcoin addresses:");
    println!("  Mainnet: {}", mainnet_addr);
    println!("  Testnet: {}", testnet_addr);
}
