//! Parse and inspect Bitcoin transactions
//!
//! Run with: cargo run --example parse_tx

use bitcoin::transaction::Tx;
use std::io::Cursor;

fn main() {
    println!("=== Parse Bitcoin Transaction ===\n");

    // Legacy transaction from Programming Bitcoin
    let legacy_hex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";

    let raw = hex::decode(legacy_hex).unwrap();
    let mut cursor = Cursor::new(raw.as_slice());
    let tx = Tx::decode(&mut cursor, "main").unwrap();

    println!("Transaction ID: {}", tx.id());
    println!("Version: {}", tx.version);
    println!("SegWit: {}", tx.segwit);
    println!("Locktime: {} (block {})", tx.locktime, tx.locktime);

    println!("\nInputs ({}):", tx.tx_ins.len());
    for (i, input) in tx.tx_ins.iter().enumerate() {
        println!("  [{}] prev_tx: {}:{}", i, hex::encode(input.prev_tx), input.prev_index);
        println!("      sequence: 0x{:08x}", input.sequence);
    }

    println!("\nOutputs ({}):", tx.tx_outs.len());
    for (i, output) in tx.tx_outs.iter().enumerate() {
        let btc = output.amount as f64 / 100_000_000.0;
        println!("  [{}] {} satoshis ({:.8} BTC)", i, output.amount, btc);
        println!("      script: {}", output.script_pubkey);
    }

    // Coinbase transaction
    println!("\n=== Coinbase Transaction ===\n");
    let coinbase_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000";

    let raw = hex::decode(coinbase_hex).unwrap();
    let mut cursor = Cursor::new(raw.as_slice());
    let coinbase = Tx::decode(&mut cursor, "main").unwrap();

    println!("Is Coinbase: {}", coinbase.is_coinbase());
    println!("Block Height: {:?}", coinbase.coinbase_height());

    let reward = coinbase.tx_outs[0].amount as f64 / 100_000_000.0;
    println!("Block Reward: {:.8} BTC", reward);
}
