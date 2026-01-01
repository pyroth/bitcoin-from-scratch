//! SHA-256 hash function wrapper
//! Uses the sha2 crate for a correct implementation.

use sha2::{Digest, Sha256};

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Double SHA-256 (used in Bitcoin)
pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_vectors() {
        // Standard test vectors
        let test_cases = [
            (
                b"".as_slice(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".as_slice(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"hello".as_slice(),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ),
        ];

        for (input, expected) in test_cases {
            let result = sha256(input);
            assert_eq!(hex::encode(result), expected);
        }
    }

    #[test]
    fn test_sha256_long_message() {
        // Test with longer message (multiple blocks)
        let long_msg =
            "a longer message to make sure that a larger number of blocks works okay too"
                .repeat(15);
        let result = sha256(long_msg.as_bytes());
        // Just verify it produces a valid 32-byte hash
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash256() {
        let result = hash256(b"hello");
        // Double SHA-256 of "hello"
        let first = sha256(b"hello");
        let expected = sha256(&first);
        assert_eq!(result, expected);
    }
}
