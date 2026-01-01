//! The Block object in Bitcoin
//! Reference: https://en.bitcoin.it/wiki/Block

use std::io::{Cursor, Read};
use std::sync::LazyLock;

use crate::error::Result;
use crate::script::{decode_int, encode_int};
use crate::sha256::sha256;

/// Genesis block headers (80 bytes)
pub static GENESIS_BLOCK: LazyLock<std::collections::HashMap<&'static str, Vec<u8>>> =
    LazyLock::new(|| {
        let mut m = std::collections::HashMap::new();
        m.insert("main", hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap());
        m.insert("test", hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18").unwrap());
        m
    });

/// Convert bits (compact target) to full target
#[must_use]
pub fn bits_to_target(bits: &[u8; 4]) -> num_bigint::BigInt {
    use num_bigint::BigInt;

    let exponent = bits[3] as u32;
    let coeff = u32::from_le_bytes([bits[0], bits[1], bits[2], 0]);

    if exponent <= 3 {
        BigInt::from(coeff >> (8 * (3 - exponent)))
    } else {
        BigInt::from(coeff) << (8 * (exponent - 3))
    }
}

/// Convert target to bits (compact format)
#[must_use]
pub fn target_to_bits(target: &num_bigint::BigInt) -> [u8; 4] {
    let (_, bytes) = target.to_bytes_be();

    // Skip leading zeros
    let mut bytes: Vec<u8> = bytes.into_iter().skip_while(|&b| b == 0).collect();
    if bytes.is_empty() {
        return [0, 0, 0, 0];
    }

    // Handle negative (high bit set)
    if bytes[0] >= 0x80 {
        bytes.insert(0, 0);
    }

    let exponent = bytes.len() as u8;
    let coeff = match bytes.len() {
        1 => [bytes[0], 0, 0],
        2 => [bytes[1], bytes[0], 0],
        _ => [bytes[2], bytes[1], bytes[0]],
    };

    [coeff[0], coeff[1], coeff[2], exponent]
}

/// Calculate new difficulty bits based on time delta
#[must_use]
pub fn calculate_new_bits(prev_bits: &[u8; 4], dt: i64) -> [u8; 4] {
    use num_bigint::BigInt;

    const TWO_WEEKS: i64 = 60 * 60 * 24 * 14;

    // Clamp time delta
    let dt = dt.clamp(TWO_WEEKS / 4, TWO_WEEKS * 4);

    let prev_target = bits_to_target(prev_bits);
    let new_target = &prev_target * dt / TWO_WEEKS;

    // Cap at maximum target
    let max_target = BigInt::from(0xffff_u32) << (8 * (0x1d - 3));
    let new_target = if new_target > max_target {
        max_target
    } else {
        new_target
    };

    target_to_bits(&new_target)
}

/// Bitcoin Block Header
#[derive(Debug, Clone)]
pub struct Block {
    pub version: u32,
    pub prev_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: [u8; 4],
    pub nonce: [u8; 4],
}

impl Block {
    /// Decode block header from bytes
    ///
    /// # Errors
    /// Returns `BitcoinError` if the block header data is malformed
    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let version = decode_int(cursor, 4)? as u32;

        let mut prev_block = [0u8; 32];
        cursor.read_exact(&mut prev_block)?;
        prev_block.reverse();

        let mut merkle_root = [0u8; 32];
        cursor.read_exact(&mut merkle_root)?;
        merkle_root.reverse();

        let timestamp = decode_int(cursor, 4)? as u32;

        let mut bits = [0u8; 4];
        cursor.read_exact(&mut bits)?;

        let mut nonce = [0u8; 4];
        cursor.read_exact(&mut nonce)?;

        Ok(Block {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    /// Encode block header to bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);

        out.extend(encode_int(self.version as u64, 4));

        let mut prev_block = self.prev_block;
        prev_block.reverse();
        out.extend_from_slice(&prev_block);

        let mut merkle_root = self.merkle_root;
        merkle_root.reverse();
        out.extend_from_slice(&merkle_root);

        out.extend(encode_int(self.timestamp as u64, 4));
        out.extend_from_slice(&self.bits);
        out.extend_from_slice(&self.nonce);

        out
    }

    /// Get block ID (double SHA-256, reversed)
    #[must_use]
    pub fn id(&self) -> String {
        let encoded = self.encode();
        let hash = sha256(&sha256(&encoded));
        let reversed: Vec<u8> = hash.iter().rev().copied().collect();
        hex::encode(reversed)
    }

    /// Get target from bits
    #[must_use]
    pub fn target(&self) -> num_bigint::BigInt {
        bits_to_target(&self.bits)
    }

    /// Calculate difficulty relative to genesis block
    #[must_use]
    pub fn difficulty(&self) -> f64 {
        use num_bigint::BigInt;
        use num_traits::ToPrimitive;

        let genesis_target: BigInt = BigInt::from(0xffff_u32) << (8 * (0x1d - 3));
        let target = self.target();

        // Convert to f64 for division
        let genesis_f = genesis_target.to_f64().unwrap_or(1.0);
        let target_f = target.to_f64().unwrap_or(1.0);

        genesis_f / target_f
    }

    /// Validate block (check proof of work)
    #[must_use]
    pub fn validate(&self) -> bool {
        use num_bigint::BigInt;

        let id = self.id();
        let id_int = BigInt::parse_bytes(id.as_bytes(), 16).unwrap_or_default();

        id_int < self.target()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    #[test]
    fn test_block_decode_encode() {
        // Example from Programming Bitcoin
        let raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let block = Block::decode(&mut cursor).unwrap();

        assert_eq!(block.version, 0x20000002);
        assert_eq!(
            hex::encode(block.prev_block),
            "000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e"
        );
        assert_eq!(
            hex::encode(block.merkle_root),
            "be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b"
        );
        assert_eq!(block.timestamp, 0x59a7771e);
        assert_eq!(block.bits, [0xe9, 0x3c, 0x01, 0x18]);
        assert_eq!(block.nonce, [0xa4, 0xff, 0xd7, 0x1d]);

        // Test roundtrip
        let raw2 = block.encode();
        assert_eq!(raw, raw2);

        // Test ID calculation
        assert_eq!(
            block.id(),
            "0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523"
        );

        // Test target
        let expected_target = BigInt::parse_bytes(
            b"0000000000000000013ce9000000000000000000000000000000000000000000",
            16,
        )
        .unwrap();
        assert_eq!(block.target(), expected_target);

        // Test difficulty
        assert_eq!(block.difficulty() as u64, 888171856257);
    }

    #[test]
    fn test_block_validate() {
        // Valid block
        let raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let block = Block::decode(&mut cursor).unwrap();
        assert!(block.validate());

        // Invalid block (last byte changed)
        let raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let block = Block::decode(&mut cursor).unwrap();
        assert!(!block.validate());
    }

    #[test]
    fn test_calculate_bits() {
        let dt = 302400i64;
        let prev_bits: [u8; 4] = [0x54, 0xd8, 0x01, 0x18];
        let next_bits = calculate_new_bits(&prev_bits, dt);
        assert_eq!(next_bits, [0x00, 0x15, 0x76, 0x17]);

        // Test bits <-> target roundtrip
        for bits in [prev_bits, next_bits] {
            let target = bits_to_target(&bits);
            let bits2 = target_to_bits(&target);
            assert_eq!(bits, bits2);
        }
    }

    #[test]
    fn test_genesis_block() {
        // Validate Bitcoin mainnet genesis block header
        let block_bytes = GENESIS_BLOCK.get("main").unwrap();
        assert_eq!(block_bytes.len(), 80);

        let mut cursor = Cursor::new(block_bytes.as_slice());
        let block = Block::decode(&mut cursor).unwrap();

        assert_eq!(block.version, 1);
        assert_eq!(block.prev_block, [0u8; 32]);
        assert_eq!(
            hex::encode(block.merkle_root),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(block.timestamp, 1231006505);

        // bits in little-endian reversed = 1d00ffff
        let mut bits_reversed = block.bits;
        bits_reversed.reverse();
        assert_eq!(hex::encode(bits_reversed), "1d00ffff");

        // nonce as little-endian u32
        let nonce = u32::from_le_bytes(block.nonce);
        assert_eq!(nonce, 2083236893);

        // Validate proof of work
        assert_eq!(
            block.id(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(
            format!("{:064x}", block.target()),
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
        assert!(block.validate());
    }
}
