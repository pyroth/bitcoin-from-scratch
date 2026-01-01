//! Parse and validate Bitcoin block headers
//!
//! Run with: cargo run --example parse_block

use bitcoin::block::{bits_to_target, Block, GENESIS_BLOCK};
use std::io::Cursor;

fn main() {
    println!("=== Bitcoin Genesis Block ===\n");

    let genesis_bytes = GENESIS_BLOCK.get("main").unwrap();
    let mut cursor = Cursor::new(genesis_bytes.as_slice());
    let genesis = Block::decode(&mut cursor).unwrap();

    println!("Block ID: {}", genesis.id());
    println!("Version: {}", genesis.version);
    println!("Timestamp: {} (2009-01-03 18:15:05 UTC)", genesis.timestamp);
    println!("Nonce: {}", u32::from_le_bytes(genesis.nonce));
    println!("Merkle Root: {}", hex::encode(genesis.merkle_root));
    println!("Target: {:064x}", genesis.target());
    println!("Difficulty: {:.2}", genesis.difficulty());
    println!("Valid PoW: {}", genesis.validate());

    // Parse a more recent block
    println!("\n=== Block #481824 (First SegWit Block) ===\n");

    let block_hex = "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d";
    let raw = hex::decode(block_hex).unwrap();
    let mut cursor = Cursor::new(raw.as_slice());
    let block = Block::decode(&mut cursor).unwrap();

    println!("Block ID: {}", block.id());
    println!("Version: 0x{:08x}", block.version);
    println!("Prev Block: {}", hex::encode(block.prev_block));
    println!("Timestamp: {}", block.timestamp);
    println!("Bits: {}", hex::encode(block.bits));
    println!("Target: {:064x}", block.target());
    println!("Difficulty: {:.2}", block.difficulty());
    println!("Valid PoW: {}", block.validate());

    // Show target calculation
    println!("\n=== Target Calculation ===\n");
    let bits = [0xe9, 0x3c, 0x01, 0x18];
    let target = bits_to_target(&bits);
    println!("Bits: {:02x}{:02x}{:02x}{:02x}", bits[3], bits[2], bits[1], bits[0]);
    println!("Target: {:064x}", target);
    println!("Block hash must be < target for valid PoW");
}
