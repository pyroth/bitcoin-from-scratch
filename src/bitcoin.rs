//! Bitcoin-specific functions, classes, utilities and parameters

use crate::curves::{Curve, Generator, Point};
use num_bigint::BigInt;
use std::sync::LazyLock;

/// Coin wrapper containing a generator
#[derive(Debug, Clone)]
pub struct Coin {
    pub generator: Generator,
}

/// Create the Bitcoin generator (secp256k1)
fn bitcoin_gen() -> Generator {
    // Bitcoin uses secp256k1: http://www.oid-info.com/get/1.3.132.0.10
    let p = BigInt::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .unwrap();
    let a = BigInt::from(0);
    let b = BigInt::from(7);
    let gx = BigInt::parse_bytes(
        b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .unwrap();
    let gy = BigInt::parse_bytes(
        b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    .unwrap();
    let n = BigInt::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    let curve = Curve::new(p, a, b);
    let g = Point::new(curve, gx, gy);
    Generator::new(g, n)
}

/// Global Bitcoin configuration (secp256k1)
pub static BITCOIN: LazyLock<Coin> = LazyLock::new(|| Coin {
    generator: bitcoin_gen(),
});

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;

    #[test]
    fn test_bitcoin_curve() {
        let generator = &BITCOIN.generator;
        assert!(!generator.n.is_zero());
        assert!(!generator.g.is_infinity());
    }
}
