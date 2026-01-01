//! RIPEMD-160 hash function implementation
//! Used in Bitcoin for address generation (HASH160 = RIPEMD160(SHA256(x)))

const K: [u32; 5] = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
const KK: [u32; 5] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

const R: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const S: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const SS: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

#[inline]
fn rol(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

#[inline]
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        64..=79 => x ^ (y | !z),
        _ => unreachable!(),
    }
}

fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    let mut aa = state[0];
    let mut bb = state[1];
    let mut cc = state[2];
    let mut dd = state[3];
    let mut ee = state[4];

    for j in 0..80 {
        let round = j / 16;

        // Left rounds
        let t = a
            .wrapping_add(f(j, b, c, d))
            .wrapping_add(x[R[j]])
            .wrapping_add(K[round]);
        let t = rol(t, S[j]).wrapping_add(e);
        a = e;
        e = d;
        d = rol(c, 10);
        c = b;
        b = t;

        // Right rounds
        let tt = aa
            .wrapping_add(f(79 - j, bb, cc, dd))
            .wrapping_add(x[RR[j]])
            .wrapping_add(KK[round]);
        let tt = rol(tt, SS[j]).wrapping_add(ee);
        aa = ee;
        ee = dd;
        dd = rol(cc, 10);
        cc = bb;
        bb = tt;
    }

    let t = state[1].wrapping_add(c).wrapping_add(dd);
    state[1] = state[2].wrapping_add(d).wrapping_add(ee);
    state[2] = state[3].wrapping_add(e).wrapping_add(aa);
    state[3] = state[4].wrapping_add(a).wrapping_add(bb);
    state[4] = state[0].wrapping_add(b).wrapping_add(cc);
    state[0] = t;
}

/// Compute RIPEMD-160 hash
#[must_use]
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Pad message
    let mut padded = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    // Process blocks
    for chunk in padded.chunks(64) {
        compress(&mut state, chunk);
    }

    // Produce output
    let mut result = [0u8; 20];
    for (i, val) in state.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    result
}

/// HASH160 = RIPEMD160(SHA256(data))
#[must_use]
#[inline]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&crate::sha256::sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ripemd160_vectors() {
        // Test vectors from RIPEMD-160 docs
        // https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
        let test_pairs = [
            ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        ];

        for (input, expected) in test_pairs {
            let result = ripemd160(input.as_bytes());
            assert_eq!(hex::encode(result), expected);
        }
    }

    #[test]
    fn test_ripemd160_long() {
        // "1234567890" repeated 8 times
        let input = "1234567890".repeat(8);
        let result = ripemd160(input.as_bytes());
        assert_eq!(
            hex::encode(result),
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
        );
    }

    #[test]
    fn test_ripemd160_a_repeated() {
        // 'a' repeated 1000 times
        let input = "a".repeat(1000);
        let result = ripemd160(input.as_bytes());
        assert_eq!(
            hex::encode(result),
            "aa69deee9a8922e92f8105e007f76110f381e9cf"
        );
    }
}
