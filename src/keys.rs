//! Utilities to generate secret/public key pairs and Bitcoin addresses

use crate::bitcoin::BITCOIN;
use crate::curves::Point;
use crate::error::{BitcoinError, Result};
use crate::ripemd160::hash160;
use crate::sha256::sha256;
use num_bigint::BigInt;
use num_traits::One;
use rand::RngCore;

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Main,
    Test,
}

impl Network {
    /// Get version byte for addresses
    #[inline]
    pub const fn version_byte(self) -> u8 {
        match self {
            Network::Main => 0x00,
            Network::Test => 0x6f,
        }
    }

    /// Get network name
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Network::Main => "main",
            Network::Test => "test",
        }
    }
}

impl TryFrom<&str> for Network {
    type Error = BitcoinError;

    fn try_from(s: &str) -> Result<Self> {
        match s {
            "main" | "mainnet" => Ok(Network::Main),
            "test" | "testnet" => Ok(Network::Test),
            _ => Err(BitcoinError::InvalidFormat(format!("Unknown network: {}", s))),
        }
    }
}

/// Generate a secret key with uniform random distribution in [1, n)
pub fn gen_secret_key(n: &BigInt) -> BigInt {
    let mut rng = rand::rng();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let key = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);
        if key >= BigInt::one() && key < *n {
            return key;
        }
    }
}

/// Public key - a Point on the secp256k1 curve with encoding/decoding functionality
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub point: Point,
}

impl PublicKey {
    /// Create from a Point
    pub fn from_point(pt: Point) -> Self {
        PublicKey { point: pt }
    }

    /// Derive public key from secret key
    pub fn from_sk(sk: &BigInt) -> Self {
        use crate::curves::scalar_mul;
        let pk = scalar_mul(sk, &BITCOIN.generator.g);
        PublicKey::from_point(pk)
    }

    /// Derive public key from hex string secret key
    pub fn from_sk_hex(sk_hex: &str) -> Self {
        let sk = BigInt::parse_bytes(sk_hex.as_bytes(), 16).expect("Invalid hex");
        Self::from_sk(&sk)
    }

    /// Decode from SEC binary format
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(BitcoinError::InvalidFormat("Empty public key".into()));
        }

        let curve = BITCOIN.generator.g.curve.as_ref().unwrap();

        match bytes[0] {
            // Uncompressed format
            4 => {
                if bytes.len() != 65 {
                    return Err(BitcoinError::InvalidFormat("Invalid uncompressed public key length".into()));
                }
                let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes[1..33]);
                let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes[33..65]);
                Ok(PublicKey {
                    point: Point::new(curve.clone(), x, y),
                })
            }
            // Compressed format
            2 | 3 => {
                if bytes.len() != 33 {
                    return Err(BitcoinError::InvalidFormat("Invalid compressed public key length".into()));
                }
                let is_even = bytes[0] == 2;
                let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes[1..33]);

                // Solve y^2 = x^3 + 7 (mod p)
                let p = &curve.p;
                let y2 = (x.modpow(&BigInt::from(3), p) + &curve.b) % p;

                // y = y2^((p+1)/4) mod p (works because p ≡ 3 mod 4 for secp256k1)
                let exp = (p + BigInt::one()) / BigInt::from(4);
                let mut y = y2.modpow(&exp, p);

                // Adjust y based on evenness
                let y_is_even = (&y % BigInt::from(2)) == BigInt::from(0);
                if is_even != y_is_even {
                    y = p - &y;
                }

                Ok(PublicKey {
                    point: Point::new(curve.clone(), x, y),
                })
            }
            _ => Err(BitcoinError::InvalidFormat("Invalid public key prefix".into())),
        }
    }

    /// Encode to SEC format
    pub fn encode(&self, compressed: bool) -> Vec<u8> {
        let x = self.point.x.as_ref().unwrap();
        let y = self.point.y.as_ref().unwrap();

        let x_bytes = bigint_to_32_bytes(x);

        if compressed {
            let prefix = if (y % BigInt::from(2)) == BigInt::from(0) {
                0x02
            } else {
                0x03
            };
            let mut result = vec![prefix];
            result.extend_from_slice(&x_bytes);
            result
        } else {
            let y_bytes = bigint_to_32_bytes(y);
            let mut result = vec![0x04];
            result.extend_from_slice(&x_bytes);
            result.extend_from_slice(&y_bytes);
            result
        }
    }

    /// Encode and hash with HASH160
    pub fn encode_hash160(&self, compressed: bool) -> [u8; 20] {
        hash160(&self.encode(compressed))
    }

    /// Get Bitcoin address for a specific network
    pub fn address(&self, net: Network, compressed: bool) -> String {
        let pkb_hash = self.encode_hash160(compressed);
        Self::pkb_hash_to_address(&pkb_hash, net)
    }

    /// Get Bitcoin address from string network name (for convenience)
    /// Panics on invalid network name - use `address` with `Network` enum for safe code
    pub fn address_str(&self, net: &str, compressed: bool) -> String {
        let network = Network::try_from(net).expect("Invalid network");
        self.address(network, compressed)
    }

    /// Convert public key hash to address
    fn pkb_hash_to_address(pkb_hash: &[u8; 20], net: Network) -> String {
        let mut ver_pkb_hash = vec![net.version_byte()];
        ver_pkb_hash.extend_from_slice(pkb_hash);

        // Calculate checksum
        let checksum = &sha256(&sha256(&ver_pkb_hash))[..4];
        ver_pkb_hash.extend_from_slice(checksum);

        b58encode(&ver_pkb_hash)
    }

    /// Get x coordinate
    pub fn x(&self) -> &BigInt {
        self.point.x.as_ref().unwrap()
    }

    /// Get y coordinate
    pub fn y(&self) -> &BigInt {
        self.point.y.as_ref().unwrap()
    }
}

/// Generate a (secret_key, public_key) pair
pub fn gen_key_pair() -> (BigInt, PublicKey) {
    let sk = gen_secret_key(&BITCOIN.generator.n);
    let pk = PublicKey::from_sk(&sk);
    (sk, pk)
}

/// Convert BigInt to 32-byte big-endian array
fn bigint_to_32_bytes(n: &BigInt) -> [u8; 32] {
    let (_, bytes) = n.to_bytes_be();
    let mut result = [0u8; 32];
    let start = 32 - bytes.len().min(32);
    result[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    result
}

// -----------------------------------------------------------------------------
// Base58 encoding/decoding

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn alphabet_inv(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&x| x == c).map(|i| i as u8)
}

/// Base58 encode bytes (expects 25 bytes for Bitcoin address)
pub fn b58encode(bytes: &[u8]) -> String {
    let mut n = BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes);
    let mut chars = Vec::new();
    let fifty_eight = BigInt::from(58);

    while n > BigInt::from(0) {
        let (quotient, remainder) = num_integer::Integer::div_rem(&n, &fifty_eight);
        let (_, rem_bytes) = remainder.to_bytes_be();
        let idx = if rem_bytes.is_empty() {
            0
        } else {
            rem_bytes[0] as usize
        };
        chars.push(ALPHABET[idx]);
        n = quotient;
    }

    // Handle leading zeros
    let num_leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    for _ in 0..num_leading_zeros {
        chars.push(ALPHABET[0]);
    }

    chars.reverse();
    String::from_utf8(chars).unwrap()
}

/// Base58 decode to bytes
pub fn b58decode(s: &str) -> Result<Vec<u8>> {
    let mut n = BigInt::from(0);
    let fifty_eight = BigInt::from(58);

    for c in s.bytes() {
        let val = alphabet_inv(c)
            .ok_or_else(|| BitcoinError::InvalidFormat("Invalid base58 character".into()))?;
        n = n * &fifty_eight + BigInt::from(val);
    }

    let (_, bytes) = n.to_bytes_be();

    // Handle leading '1's (zeros in base58)
    let num_leading_ones = s.bytes().take_while(|&c| c == b'1').count();

    // Pad to 25 bytes for Bitcoin addresses
    let mut result = vec![0u8; num_leading_ones];
    result.extend(bytes);

    // Ensure 25 bytes
    if result.len() < 25 {
        let mut padded = vec![0u8; 25 - result.len()];
        padded.extend(result);
        result = padded;
    }

    Ok(result)
}

/// Extract public key hash from Base58Check address
pub fn address_to_pkb_hash(b58check_address: &str) -> Result<[u8; 20]> {
    let bytes = b58decode(b58check_address)?;

    if bytes.len() != 25 {
        return Err(BitcoinError::InvalidFormat("Invalid address length".into()));
    }

    // Validate checksum
    let checksum = &sha256(&sha256(&bytes[..21]))[..4];
    if checksum != &bytes[21..25] {
        return Err(BitcoinError::Validation("Invalid checksum".into()));
    }

    // Extract public key hash (skip version byte, remove checksum)
    let mut pkb_hash = [0u8; 20];
    pkb_hash.copy_from_slice(&bytes[1..21]);
    Ok(pkb_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curves::scalar_mul;

    #[test]
    fn test_public_key_gen() {
        // Example from Mastering Bitcoin Chapter 4
        let pk = PublicKey::from_sk_hex(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
        );
        assert_eq!(
            format!("{:064x}", pk.x()).to_uppercase(),
            "F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A"
        );
        assert_eq!(
            format!("{:064x}", pk.y()).to_uppercase(),
            "07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB"
        );
    }

    #[test]
    fn test_btc_addresses() {
        // (net, compressed, secret_key_hex, expected_address)
        let tests = [
            // Mastering Bitcoin Chapter 4
            (
                "main",
                true,
                "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6",
                "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3",
            ),
            // Bitcoin wiki reference
            (
                "main",
                true,
                "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
                "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
            ),
        ];

        for (net, compressed, sk_hex, expected_addr) in tests {
            let pk = PublicKey::from_sk_hex(sk_hex);
            let addr = pk.address_str(net, compressed);
            assert_eq!(addr, expected_addr);
        }
    }

    #[test]
    fn test_pk_sec_encoding() {
        let g = &BITCOIN.generator.g;

        // Test vectors from Programming Bitcoin Chapter 4
        let tests: [(BigInt, bool, &str); 4] = [
            (
                BigInt::from(5000),
                false,
                "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10",
            ),
            (
                BigInt::from(5001),
                true,
                "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1",
            ),
            (
                BigInt::parse_bytes(b"deadbeef12345", 16).unwrap(),
                false,
                "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121",
            ),
            (
                BigInt::parse_bytes(b"deadbeef54321", 16).unwrap(),
                true,
                "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690",
            ),
        ];

        for (scalar, compressed, expected_sec) in tests {
            let point = scalar_mul(&scalar, g);
            let pk = PublicKey::from_point(point);
            let sec = pk.encode(compressed);
            assert_eq!(hex::encode(&sec), expected_sec);

            // Test decode roundtrip
            let pk2 = PublicKey::decode(&sec).unwrap();
            assert_eq!(pk.x(), pk2.x());
            assert_eq!(pk.y(), pk2.y());
        }
    }

    #[test]
    fn test_key_generation() {
        let (sk, pk) = gen_key_pair();
        assert!(sk >= BigInt::one());
        assert!(sk < BITCOIN.generator.n);
        assert!(!pk.point.is_infinity());
    }

    #[test]
    fn test_public_key_encoding() {
        let (_, pk) = gen_key_pair();

        // Test compressed encoding
        let compressed = pk.encode(true);
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);

        // Test uncompressed encoding
        let uncompressed = pk.encode(false);
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);
    }

    #[test]
    fn test_public_key_decode() {
        let (_, pk) = gen_key_pair();

        // Test compressed round-trip
        let compressed = pk.encode(true);
        let decoded = PublicKey::decode(&compressed).unwrap();
        assert_eq!(pk.point, decoded.point);

        // Test uncompressed round-trip
        let uncompressed = pk.encode(false);
        let decoded = PublicKey::decode(&uncompressed).unwrap();
        assert_eq!(pk.point, decoded.point);
    }

    #[test]
    fn test_b58_roundtrip() {
        // Test with a typical Bitcoin address pattern (version + hash + checksum)
        let mut original = vec![0x00]; // version byte
        original.extend([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ]); // 20-byte hash
        original.extend([0xaa, 0xbb, 0xcc, 0xdd]); // 4-byte checksum
        assert_eq!(original.len(), 25);

        let encoded = b58encode(&original);
        let decoded = b58decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_address_to_pkb_hash() {
        // Test address decoding
        let tests = [
            (
                "main",
                true,
                "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6",
                "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3",
            ),
            (
                "main",
                true,
                "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
                "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
            ),
        ];

        for (_net, compressed, sk_hex, address) in tests {
            let pk = PublicKey::from_sk_hex(sk_hex);
            let pkb_hash = pk.encode_hash160(compressed);
            let pkb_hash2 = address_to_pkb_hash(address).unwrap();
            assert_eq!(pkb_hash, pkb_hash2);
        }
    }
}
