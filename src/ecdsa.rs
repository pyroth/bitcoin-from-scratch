//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//! Functions that sign/verify digital signatures and related utilities

use crate::bitcoin::BITCOIN;
use crate::curves::{Point, mod_inv};
#[cfg(test)]
use crate::keys::PublicKey;
use crate::keys::gen_secret_key;
use crate::sha256::sha256;
use num_bigint::BigInt;
use num_traits::One;
use std::io::{Cursor, Read};

/// ECDSA Signature (r, s)
///
/// Represents a digital signature consisting of two big integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Signature {
    pub fn new(r: BigInt, s: BigInt) -> Self {
        Signature { r, s }
    }

    /// Decode from DER format
    /// Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
    pub fn decode(der: &[u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(der);
        let mut buf = [0u8; 1];

        // Read and validate marker
        cursor
            .read_exact(&mut buf)
            .map_err(|_| "Failed to read marker")?;
        if buf[0] != 0x30 {
            return Err("Invalid DER marker");
        }

        // Read total length
        cursor
            .read_exact(&mut buf)
            .map_err(|_| "Failed to read length")?;
        let total_len = buf[0] as usize;
        if total_len != der.len() - 2 {
            return Err("Invalid DER length");
        }

        // Read R marker
        cursor
            .read_exact(&mut buf)
            .map_err(|_| "Failed to read R marker")?;
        if buf[0] != 0x02 {
            return Err("Invalid R marker");
        }

        // Read R
        cursor
            .read_exact(&mut buf)
            .map_err(|_| "Failed to read R length")?;
        let r_len = buf[0] as usize;
        let mut r_bytes = vec![0u8; r_len];
        cursor
            .read_exact(&mut r_bytes)
            .map_err(|_| "Failed to read R")?;
        let r = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r_bytes);

        // Read S marker
        cursor
            .read_exact(&mut buf)
            .map_err(|_| "Failed to read S marker")?;
        if buf[0] != 0x02 {
            return Err("Invalid S marker");
        }

        // Read S
        cursor
            .read_exact(&mut buf)
            .map_err(|_| "Failed to read S length")?;
        let s_len = buf[0] as usize;
        let mut s_bytes = vec![0u8; s_len];
        cursor
            .read_exact(&mut s_bytes)
            .map_err(|_| "Failed to read S")?;
        let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &s_bytes);

        // Validate total length
        if der.len() != 6 + r_len + s_len {
            return Err("DER length mismatch");
        }

        Ok(Signature { r, s })
    }

    /// Encode to DER format
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let r_bytes = self.encode_int(&self.r);
        let s_bytes = self.encode_int(&self.s);

        let mut content = Vec::new();
        content.push(0x02);
        content.push(r_bytes.len() as u8);
        content.extend(&r_bytes);
        content.push(0x02);
        content.push(s_bytes.len() as u8);
        content.extend(&s_bytes);

        let mut result = Vec::new();
        result.push(0x30);
        result.push(content.len() as u8);
        result.extend(content);

        result
    }

    fn encode_int(&self, n: &BigInt) -> Vec<u8> {
        let (_, mut bytes) = n.to_bytes_be();

        // Ensure 32 bytes minimum, then strip leading zeros
        while bytes.len() < 32 {
            bytes.insert(0, 0);
        }
        while bytes.len() > 1 && bytes[0] == 0 && bytes[1] < 0x80 {
            bytes.remove(0);
        }

        // Prepend 0x00 if first byte >= 0x80 (to indicate positive number)
        if !bytes.is_empty() && bytes[0] >= 0x80 {
            bytes.insert(0, 0x00);
        }

        bytes
    }
}

/// Sign a message with a secret key
///
/// Uses double SHA-256 hashing and generates a random nonce.
/// Ensures low S value per BIP-62.
#[must_use]
pub fn sign(secret_key: &BigInt, message: &[u8]) -> Signature {
    use crate::curves::scalar_mul;
    let n = &BITCOIN.generator.n;

    // Hash the message (double SHA-256)
    let hash = sha256(&sha256(message));
    let z = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);

    // Generate random k
    let k = gen_secret_key(n);
    let p = scalar_mul(&k, &BITCOIN.generator.g);

    // Calculate signature
    let r = p.x.as_ref().unwrap().clone();
    let mut s = (mod_inv(&k, n) * (&z + secret_key * &r)) % n;

    // Ensure low S value (BIP-62)
    let half_n = n / BigInt::from(2);
    if s > half_n {
        s = n - &s;
    }

    Signature::new(r, s)
}

/// Verify a signature
///
/// Returns `true` if the signature is valid for the given public key and message.
#[must_use]
pub fn verify(public_key: &Point, message: &[u8], sig: &Signature) -> bool {
    use crate::curves::scalar_mul;
    let n = &BITCOIN.generator.n;
    let n_clone = n.clone();

    // Basic validation
    if sig.r < BigInt::one() || sig.r >= n_clone {
        return false;
    }
    if sig.s < BigInt::one() || sig.s >= n_clone {
        return false;
    }

    // Hash the message (double SHA-256)
    let hash = sha256(&sha256(message));
    let z = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);

    // Verify
    let w = mod_inv(&sig.s, n);
    let u1 = (&z * &w) % n;
    let u2 = (&sig.r * &w) % n;

    let p1 = scalar_mul(&u1, &BITCOIN.generator.g);
    let p2 = scalar_mul(&u2, public_key);
    let p = p1 + p2;

    if p.is_infinity() {
        return false;
    }

    p.x.as_ref().unwrap() == &sig.r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::gen_key_pair;

    #[test]
    fn test_ecdsa_sign_verify() {
        // Create two identities
        let (sk1, pk1) = gen_key_pair();
        let (sk2, _pk2) = gen_key_pair();

        let message = b"user pk1 would like to pay user pk2 1 BTC kkthx";

        // Random signature should fail
        let fake_r = gen_secret_key(&BITCOIN.generator.n);
        let fake_s = gen_secret_key(&BITCOIN.generator.n);
        let fake_sig = Signature::new(fake_r, fake_s);
        assert!(!verify(&pk1.point, message, &fake_sig));

        // Signature with wrong key should fail
        let sig2 = sign(&sk2, message);
        assert!(!verify(&pk1.point, message, &sig2));

        // Correct signature should pass
        let sig1 = sign(&sk1, message);
        assert!(verify(&pk1.point, message, &sig1));
    }

    #[test]
    fn test_sig_der_decode() {
        // From Programming Bitcoin Chapter 4
        let der = hex::decode("3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec").unwrap();
        let sig = Signature::decode(&der).unwrap();

        let expected_r = BigInt::parse_bytes(
            b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let expected_s = BigInt::parse_bytes(
            b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();

        assert_eq!(sig.r, expected_r);
        assert_eq!(sig.s, expected_s);

        // Test roundtrip encoding
        let der2 = sig.encode();
        assert_eq!(der, der2);
    }

    #[test]
    fn test_signature_der_roundtrip() {
        let sk = gen_secret_key(&BITCOIN.generator.n);
        let message = b"Test message";

        let sig = sign(&sk, message);
        let der = sig.encode();
        let decoded = Signature::decode(&der).unwrap();

        assert_eq!(sig.r, decoded.r);
        assert_eq!(sig.s, decoded.s);
    }

    #[test]
    fn test_invalid_signature() {
        let sk = gen_secret_key(&BITCOIN.generator.n);
        let pk = PublicKey::from_sk(&sk);
        let message = b"Hello, Bitcoin!";
        let wrong_message = b"Wrong message!";

        let sig = sign(&sk, message);
        assert!(!verify(&pk.point, wrong_message, &sig));
    }
}
