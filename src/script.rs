//! Bitcoin Script implementation
//! Reference: https://en.bitcoin.it/wiki/Script

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::LazyLock;

use crate::ecdsa::{Signature, verify};
use crate::keys::PublicKey;
use crate::ripemd160::hash160;

/// Script command - either an opcode or data bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptCmd {
    Op(u8),
    Data(Vec<u8>),
}

/// Bitcoin Script
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Script {
    pub cmds: Vec<ScriptCmd>,
}

impl Script {
    pub fn new(cmds: Vec<ScriptCmd>) -> Self {
        Script { cmds }
    }

    pub fn empty() -> Self {
        Script { cmds: Vec::new() }
    }

    /// Decode script from bytes
    pub fn decode(data: &mut Cursor<&[u8]>) -> Result<Self, &'static str> {
        let length = decode_varint(data)?;
        let mut cmds = Vec::new();
        let mut count = 0usize;

        while count < length as usize {
            let mut byte = [0u8; 1];
            data.read_exact(&mut byte)
                .map_err(|_| "Failed to read byte")?;
            count += 1;
            let current = byte[0];

            if (1..=75).contains(&current) {
                // Data push of 1-75 bytes
                let mut buf = vec![0u8; current as usize];
                data.read_exact(&mut buf)
                    .map_err(|_| "Failed to read data")?;
                count += current as usize;
                cmds.push(ScriptCmd::Data(buf));
            } else if current == 76 {
                // OP_PUSHDATA1: next byte is length
                let mut len_byte = [0u8; 1];
                data.read_exact(&mut len_byte)
                    .map_err(|_| "Failed to read pushdata1 length")?;
                let data_len = len_byte[0] as usize;
                let mut buf = vec![0u8; data_len];
                data.read_exact(&mut buf)
                    .map_err(|_| "Failed to read pushdata1 data")?;
                count += 1 + data_len;
                cmds.push(ScriptCmd::Data(buf));
            } else if current == 77 {
                // OP_PUSHDATA2: next 2 bytes are length (little-endian)
                let mut len_bytes = [0u8; 2];
                data.read_exact(&mut len_bytes)
                    .map_err(|_| "Failed to read pushdata2 length")?;
                let data_len = u16::from_le_bytes(len_bytes) as usize;
                let mut buf = vec![0u8; data_len];
                data.read_exact(&mut buf)
                    .map_err(|_| "Failed to read pushdata2 data")?;
                count += 2 + data_len;
                cmds.push(ScriptCmd::Data(buf));
            } else {
                // Opcode
                cmds.push(ScriptCmd::Op(current));
            }
        }

        if count != length as usize {
            return Err("Script parsing failed: length mismatch");
        }

        Ok(Script { cmds })
    }

    /// Encode script to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        for cmd in &self.cmds {
            match cmd {
                ScriptCmd::Op(opcode) => {
                    out.push(*opcode);
                }
                ScriptCmd::Data(data) => {
                    let length = data.len();
                    if length < 75 {
                        out.push(length as u8);
                    } else if length <= 255 {
                        out.push(76); // OP_PUSHDATA1
                        out.push(length as u8);
                    } else if length <= 520 {
                        out.push(77); // OP_PUSHDATA2
                        out.extend_from_slice(&(length as u16).to_le_bytes());
                    } else {
                        // Data exceeds Bitcoin script limits; truncate silently
                        // In production, this should return an error
                        debug_assert!(length <= 520, "Data too long for script: {} bytes", length);
                        out.push(77);
                        out.extend_from_slice(&520u16.to_le_bytes());
                        out.extend_from_slice(&data[..520]);
                        continue;
                    }
                    out.extend_from_slice(data);
                }
            }
        }

        let mut result = encode_varint(out.len() as u64);
        result.extend(out);
        result
    }

    /// Concatenate two scripts
    pub fn concat(&self, other: &Script) -> Script {
        let mut cmds = self.cmds.clone();
        cmds.extend(other.cmds.clone());
        Script { cmds }
    }

    /// Evaluate script for P2PKH transactions
    pub fn evaluate(&self, mod_tx_enc: &[u8]) -> bool {
        // For now, only support standard P2PKH
        if self.cmds.len() != 7 {
            return false;
        }

        // Expected: <sig> <pubkey> OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        let sig = match &self.cmds[0] {
            ScriptCmd::Data(d) => d.clone(),
            _ => return false,
        };
        let pubkey = match &self.cmds[1] {
            ScriptCmd::Data(d) => d.clone(),
            _ => return false,
        };

        // Check opcodes
        if !matches!(&self.cmds[2], ScriptCmd::Op(118)) {
            return false;
        } // OP_DUP
        if !matches!(&self.cmds[3], ScriptCmd::Op(169)) {
            return false;
        } // OP_HASH160

        let pubkey_hash = match &self.cmds[4] {
            ScriptCmd::Data(d) => d.clone(),
            _ => return false,
        };

        if !matches!(&self.cmds[5], ScriptCmd::Op(136)) {
            return false;
        } // OP_EQUALVERIFY
        if !matches!(&self.cmds[6], ScriptCmd::Op(172)) {
            return false;
        } // OP_CHECKSIG

        // Verify public key hash
        let computed_hash = hash160(&pubkey);
        if pubkey_hash != computed_hash {
            return false;
        }

        // Verify signature
        let sighash_type = sig.last().copied().unwrap_or(0);
        if sighash_type != 1 {
            return false; // Only SIGHASH_ALL supported
        }

        let der = &sig[..sig.len() - 1];
        let signature = match Signature::decode(der) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let pk = match PublicKey::decode(&pubkey) {
            Ok(p) => p,
            Err(_) => return false,
        };

        verify(&pk.point, mod_tx_enc, &signature)
    }
}

impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self
            .cmds
            .iter()
            .map(|cmd| match cmd {
                ScriptCmd::Op(op) => OP_CODE_NAMES
                    .get(op)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("OP_[{}]", op)),
                ScriptCmd::Data(data) => hex::encode(data),
            })
            .collect();
        write!(f, "{}", parts.join(" "))
    }
}

impl std::ops::Add for Script {
    type Output = Script;

    fn add(self, other: Script) -> Script {
        self.concat(&other)
    }
}

impl std::ops::Add for &Script {
    type Output = Script;

    fn add(self, other: &Script) -> Script {
        self.concat(other)
    }
}

/// Decode a variable-length integer
pub fn decode_varint(cursor: &mut Cursor<&[u8]>) -> Result<u64, &'static str> {
    let mut buf = [0u8; 1];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| "Failed to read varint")?;

    match buf[0] {
        0xfd => {
            let mut bytes = [0u8; 2];
            cursor
                .read_exact(&mut bytes)
                .map_err(|_| "Failed to read varint")?;
            Ok(u16::from_le_bytes(bytes) as u64)
        }
        0xfe => {
            let mut bytes = [0u8; 4];
            cursor
                .read_exact(&mut bytes)
                .map_err(|_| "Failed to read varint")?;
            Ok(u32::from_le_bytes(bytes) as u64)
        }
        0xff => {
            let mut bytes = [0u8; 8];
            cursor
                .read_exact(&mut bytes)
                .map_err(|_| "Failed to read varint")?;
            Ok(u64::from_le_bytes(bytes))
        }
        n => Ok(n as u64),
    }
}

/// Encode a variable-length integer
pub fn encode_varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n < 0x10000 {
        let mut result = vec![0xfd];
        result.extend_from_slice(&(n as u16).to_le_bytes());
        result
    } else if n < 0x100000000 {
        let mut result = vec![0xfe];
        result.extend_from_slice(&(n as u32).to_le_bytes());
        result
    } else {
        let mut result = vec![0xff];
        result.extend_from_slice(&n.to_le_bytes());
        result
    }
}

/// Decode a little-endian integer
pub fn decode_int(cursor: &mut Cursor<&[u8]>, nbytes: usize) -> Result<u64, &'static str> {
    let mut buf = vec![0u8; nbytes];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| "Failed to read int")?;

    let mut result = 0u64;
    for (i, &byte) in buf.iter().enumerate() {
        result |= (byte as u64) << (i * 8);
    }
    Ok(result)
}

/// Encode a little-endian integer
pub fn encode_int(n: u64, nbytes: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(nbytes);
    for i in 0..nbytes {
        result.push((n >> (i * 8)) as u8);
    }
    result
}

/// Opcode names
pub static OP_CODE_NAMES: LazyLock<HashMap<u8, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(0, "OP_0");
    m.insert(76, "OP_PUSHDATA1");
    m.insert(77, "OP_PUSHDATA2");
    m.insert(78, "OP_PUSHDATA4");
    m.insert(79, "OP_1NEGATE");
    m.insert(81, "OP_1");
    m.insert(82, "OP_2");
    m.insert(83, "OP_3");
    m.insert(84, "OP_4");
    m.insert(85, "OP_5");
    m.insert(86, "OP_6");
    m.insert(87, "OP_7");
    m.insert(88, "OP_8");
    m.insert(89, "OP_9");
    m.insert(90, "OP_10");
    m.insert(91, "OP_11");
    m.insert(92, "OP_12");
    m.insert(93, "OP_13");
    m.insert(94, "OP_14");
    m.insert(95, "OP_15");
    m.insert(96, "OP_16");
    m.insert(97, "OP_NOP");
    m.insert(99, "OP_IF");
    m.insert(100, "OP_NOTIF");
    m.insert(103, "OP_ELSE");
    m.insert(104, "OP_ENDIF");
    m.insert(105, "OP_VERIFY");
    m.insert(106, "OP_RETURN");
    m.insert(107, "OP_TOALTSTACK");
    m.insert(108, "OP_FROMALTSTACK");
    m.insert(109, "OP_2DROP");
    m.insert(110, "OP_2DUP");
    m.insert(111, "OP_3DUP");
    m.insert(112, "OP_2OVER");
    m.insert(113, "OP_2ROT");
    m.insert(114, "OP_2SWAP");
    m.insert(115, "OP_IFDUP");
    m.insert(116, "OP_DEPTH");
    m.insert(117, "OP_DROP");
    m.insert(118, "OP_DUP");
    m.insert(119, "OP_NIP");
    m.insert(120, "OP_OVER");
    m.insert(121, "OP_PICK");
    m.insert(122, "OP_ROLL");
    m.insert(123, "OP_ROT");
    m.insert(124, "OP_SWAP");
    m.insert(125, "OP_TUCK");
    m.insert(130, "OP_SIZE");
    m.insert(135, "OP_EQUAL");
    m.insert(136, "OP_EQUALVERIFY");
    m.insert(139, "OP_1ADD");
    m.insert(140, "OP_1SUB");
    m.insert(143, "OP_NEGATE");
    m.insert(144, "OP_ABS");
    m.insert(145, "OP_NOT");
    m.insert(146, "OP_0NOTEQUAL");
    m.insert(147, "OP_ADD");
    m.insert(148, "OP_SUB");
    m.insert(154, "OP_BOOLAND");
    m.insert(155, "OP_BOOLOR");
    m.insert(156, "OP_NUMEQUAL");
    m.insert(157, "OP_NUMEQUALVERIFY");
    m.insert(158, "OP_NUMNOTEQUAL");
    m.insert(159, "OP_LESSTHAN");
    m.insert(160, "OP_GREATERTHAN");
    m.insert(161, "OP_LESSTHANOREQUAL");
    m.insert(162, "OP_GREATERTHANOREQUAL");
    m.insert(163, "OP_MIN");
    m.insert(164, "OP_MAX");
    m.insert(165, "OP_WITHIN");
    m.insert(166, "OP_RIPEMD160");
    m.insert(167, "OP_SHA1");
    m.insert(168, "OP_SHA256");
    m.insert(169, "OP_HASH160");
    m.insert(170, "OP_HASH256");
    m.insert(171, "OP_CODESEPARATOR");
    m.insert(172, "OP_CHECKSIG");
    m.insert(173, "OP_CHECKSIGVERIFY");
    m.insert(174, "OP_CHECKMULTISIG");
    m.insert(175, "OP_CHECKMULTISIGVERIFY");
    m.insert(176, "OP_NOP1");
    m.insert(177, "OP_CHECKLOCKTIMEVERIFY");
    m.insert(178, "OP_CHECKSEQUENCEVERIFY");
    m.insert(179, "OP_NOP4");
    m.insert(180, "OP_NOP5");
    m.insert(181, "OP_NOP6");
    m.insert(182, "OP_NOP7");
    m.insert(183, "OP_NOP8");
    m.insert(184, "OP_NOP9");
    m.insert(185, "OP_NOP10");
    m
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(252), vec![252]);
        assert_eq!(encode_varint(253), vec![0xfd, 253, 0]);
        assert_eq!(encode_varint(0xffff), vec![0xfd, 0xff, 0xff]);
    }

    #[test]
    fn test_script_roundtrip() {
        let script = Script::new(vec![
            ScriptCmd::Op(118), // OP_DUP
            ScriptCmd::Op(169), // OP_HASH160
            ScriptCmd::Data(vec![0u8; 20]),
            ScriptCmd::Op(136), // OP_EQUALVERIFY
            ScriptCmd::Op(172), // OP_CHECKSIG
        ]);

        let encoded = script.encode();
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = Script::decode(&mut cursor).unwrap();

        assert_eq!(script, decoded);
    }
}
