# Bitcoin from Scratch

A pure Rust implementation of Bitcoin's core cryptographic primitives and data structures for educational purposes.

## Overview

This library implements Bitcoin's fundamental building blocks from first principles, including:

- **Elliptic Curve Cryptography** — secp256k1 curve operations, point addition, scalar multiplication
- **ECDSA Signatures** — Digital signature creation and verification
- **Hash Functions** — SHA-256, RIPEMD-160, HASH160, HASH256
- **Key Management** — Key pair generation, public key encoding (SEC format), Base58Check addresses
- **Transactions** — Legacy and SegWit transaction parsing, encoding, and validation
- **Blocks** — Block header parsing, proof-of-work validation, difficulty calculation
- **Scripts** — Bitcoin Script parsing and P2PKH evaluation
- **Networking** — P2P protocol messages (version, verack, headers, ping/pong)

## Quick Start

```bash
# Run the demo
cargo run

# Run an example
cargo run --example keygen
```

## Examples

The `examples/` directory contains demonstration programs:

- `keygen.rs` — Generate Bitcoin key pairs and addresses
- `hash_demo.rs` — Demonstrate hash functions (SHA-256, RIPEMD-160, HASH160)
- `parse_tx.rs` — Parse and display a real Bitcoin transaction
- `parse_block.rs` — Parse and validate a Bitcoin block header
- `sign_verify.rs` — Sign messages and verify ECDSA signatures

## License

This project is licensed under either of the following licenses, at your option:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in `bitcoin-from-scratch` by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
