//! ECDSA signature creation and verification
//!
//! Run with: cargo run --example sign_verify

use bitcoin::{gen_key_pair, sign, verify};

fn main() {
    println!("=== ECDSA Sign & Verify ===\n");

    // Create two parties: Alice and Bob
    let (alice_sk, alice_pk) = gen_key_pair();
    let (bob_sk, _bob_pk) = gen_key_pair();

    // Message to sign
    let message = b"Alice sends 1 BTC to Bob";
    println!("Message: {:?}\n", String::from_utf8_lossy(message));

    // Alice signs the message
    let signature = sign(&alice_sk, message);
    println!("Signature (DER):");
    println!("  {}\n", hex::encode(signature.encode()));

    // Verify with correct key
    let valid = verify(&alice_pk.point, message, &signature);
    println!("Verify with Alice's key: {}", if valid { "VALID" } else { "INVALID" });

    // Verify with wrong key
    let bob_sig = sign(&bob_sk, message);
    let invalid = verify(&alice_pk.point, message, &bob_sig);
    println!("Verify Bob's sig with Alice's key: {}", if invalid { "VALID" } else { "INVALID" });

    // Verify tampered message
    let tampered = b"Alice sends 100 BTC to Bob";
    let tampered_check = verify(&alice_pk.point, tampered, &signature);
    println!("Verify tampered message: {}", if tampered_check { "VALID" } else { "INVALID" });
}
