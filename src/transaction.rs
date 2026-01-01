//! The Transaction object in Bitcoin
//! Reference: https://en.bitcoin.it/wiki/Transaction

use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use crate::script::{Script, ScriptCmd, decode_int, decode_varint, encode_int, encode_varint};
use crate::sha256::sha256;

/// Transaction fetcher - lazily fetches transactions from API or cache
pub struct TxFetcher;

impl TxFetcher {
    /// Fetch a transaction by ID
    pub fn fetch(tx_id: &str, net: &str) -> Result<Tx, String> {
        // Validate tx_id
        if !tx_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid transaction ID".to_string());
        }
        let tx_id = tx_id.to_lowercase();

        let txdb_dir = "txdb";
        let cache_file = format!("{}/{}", txdb_dir, tx_id);

        let raw = if Path::new(&cache_file).exists() {
            // Read from cache
            fs::read(&cache_file).map_err(|e| e.to_string())?
        } else {
            // Fetch from API
            let url = match net {
                "main" => format!("https://blockstream.info/api/tx/{}/hex", tx_id),
                "test" => format!("https://blockstream.info/testnet/api/tx/{}/hex", tx_id),
                _ => return Err(format!("Invalid network: {}", net)),
            };

            let response = reqwest::blocking::get(&url).map_err(|e| e.to_string())?;

            if !response.status().is_success() {
                return Err(format!("Transaction {} not found", tx_id));
            }

            let hex_str = response.text().map_err(|e| e.to_string())?;
            let raw = hex::decode(hex_str.trim()).map_err(|e| e.to_string())?;

            // Cache to disk
            fs::create_dir_all(txdb_dir).ok();
            fs::write(&cache_file, &raw).ok();

            raw
        };

        let mut cursor = Cursor::new(raw.as_slice());
        let tx = Tx::decode(&mut cursor, net)?;

        // Verify ID matches
        if tx.id() != tx_id {
            return Err("Transaction ID mismatch".to_string());
        }

        Ok(tx)
    }
}

/// Bitcoin Transaction
#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,
    pub tx_ins: Vec<TxIn>,
    pub tx_outs: Vec<TxOut>,
    pub locktime: u32,
    pub segwit: bool,
    pub net: String,
}

impl Tx {
    /// Decode transaction from bytes
    pub fn decode(cursor: &mut Cursor<&[u8]>, net: &str) -> Result<Self, String> {
        let version = decode_int(cursor, 4).map_err(|e| e.to_string())? as u32;

        // Detect segwit
        let mut segwit = false;
        let mut num_inputs = decode_varint(cursor).map_err(|e| e.to_string())?;

        if num_inputs == 0 {
            // Segwit marker
            let mut flag = [0u8; 1];
            cursor
                .read_exact(&mut flag)
                .map_err(|_| "Failed to read segwit flag")?;
            if flag[0] != 1 {
                return Err("Invalid segwit flag".to_string());
            }
            segwit = true;
            num_inputs = decode_varint(cursor).map_err(|e| e.to_string())?;
        }

        // Decode inputs
        let mut tx_ins = Vec::new();
        for _ in 0..num_inputs {
            let mut tx_in = TxIn::decode(cursor)?;
            tx_in.net = net.to_string();
            tx_ins.push(tx_in);
        }

        // Decode outputs
        let num_outputs = decode_varint(cursor).map_err(|e| e.to_string())?;
        let mut tx_outs = Vec::new();
        for _ in 0..num_outputs {
            tx_outs.push(TxOut::decode(cursor)?);
        }

        // Decode witness data for segwit
        if segwit {
            for tx_in in &mut tx_ins {
                let num_items = decode_varint(cursor).map_err(|e| e.to_string())?;
                let mut items = Vec::new();
                for _ in 0..num_items {
                    let item_len = decode_varint(cursor).map_err(|e| e.to_string())?;
                    if item_len == 0 {
                        items.push(WitnessItem::Int(0));
                    } else {
                        let mut data = vec![0u8; item_len as usize];
                        cursor
                            .read_exact(&mut data)
                            .map_err(|_| "Failed to read witness")?;
                        items.push(WitnessItem::Data(data));
                    }
                }
                tx_in.witness = items;
            }
        }

        let locktime = decode_int(cursor, 4).map_err(|e| e.to_string())? as u32;

        Ok(Tx {
            version,
            tx_ins,
            tx_outs,
            locktime,
            segwit,
            net: net.to_string(),
        })
    }

    /// Encode transaction to bytes
    pub fn encode(&self, force_legacy: bool, sig_index: Option<usize>) -> Vec<u8> {
        let mut out = Vec::new();

        // Version
        out.extend(encode_int(self.version as u64, 4));

        // Segwit marker
        if self.segwit && !force_legacy {
            out.extend_from_slice(&[0x00, 0x01]);
        }

        // Inputs
        out.extend(encode_varint(self.tx_ins.len() as u64));
        for (i, tx_in) in self.tx_ins.iter().enumerate() {
            let script_override = sig_index.map(|idx| idx == i);
            out.extend(tx_in.encode(script_override));
        }

        // Outputs
        out.extend(encode_varint(self.tx_outs.len() as u64));
        for tx_out in &self.tx_outs {
            out.extend(tx_out.encode());
        }

        // Witness
        if self.segwit && !force_legacy {
            for tx_in in &self.tx_ins {
                out.extend(encode_varint(tx_in.witness.len() as u64));
                for item in &tx_in.witness {
                    match item {
                        WitnessItem::Int(n) => out.extend(encode_varint(*n as u64)),
                        WitnessItem::Data(data) => {
                            out.extend(encode_varint(data.len() as u64));
                            out.extend(data);
                        }
                    }
                }
            }
        }

        // Locktime
        out.extend(encode_int(self.locktime as u64, 4));

        // SIGHASH_ALL for signing
        if sig_index.is_some() {
            out.extend(encode_int(1, 4));
        }

        out
    }

    /// Get transaction ID (double SHA-256, reversed)
    pub fn id(&self) -> String {
        let encoded = self.encode(true, None);
        let hash = sha256(&sha256(&encoded));
        let reversed: Vec<u8> = hash.iter().rev().copied().collect();
        hex::encode(reversed)
    }

    /// Calculate transaction fee
    pub fn fee(&self) -> Result<i64, String> {
        let mut input_total = 0i64;
        for tx_in in &self.tx_ins {
            input_total += tx_in.value()? as i64;
        }
        let output_total: i64 = self.tx_outs.iter().map(|o| o.amount as i64).sum();
        Ok(input_total - output_total)
    }

    /// Validate transaction
    pub fn validate(&self) -> Result<bool, String> {
        if self.segwit {
            return Err("Segwit validation not implemented".to_string());
        }

        // Check fee is non-negative
        if self.fee()? < 0 {
            return Ok(false);
        }

        // Validate signatures
        for (i, tx_in) in self.tx_ins.iter().enumerate() {
            let mod_tx_enc = self.encode(false, Some(i));
            let script_pubkey = tx_in.script_pubkey()?;
            let combined = tx_in.script_sig.concat(&script_pubkey);
            if !combined.evaluate(&mod_tx_enc) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.tx_ins.len() == 1
            && self.tx_ins[0].prev_tx == [0u8; 32]
            && self.tx_ins[0].prev_index == 0xffffffff
    }

    /// Get coinbase height (BIP34)
    pub fn coinbase_height(&self) -> Option<u32> {
        if !self.is_coinbase() {
            return None;
        }
        if let Some(ScriptCmd::Data(data)) = self.tx_ins[0].script_sig.cmds.first() {
            let mut bytes = [0u8; 4];
            let len = data.len().min(4);
            bytes[..len].copy_from_slice(&data[..len]);
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

/// Witness item
#[derive(Debug, Clone)]
pub enum WitnessItem {
    Int(i32),
    Data(Vec<u8>),
}

/// Transaction Input
#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_tx: [u8; 32],
    pub prev_index: u32,
    pub script_sig: Script,
    pub sequence: u32,
    pub witness: Vec<WitnessItem>,
    pub net: String,
}

impl TxIn {
    /// Decode from bytes
    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, String> {
        let mut prev_tx = [0u8; 32];
        cursor
            .read_exact(&mut prev_tx)
            .map_err(|_| "Failed to read prev_tx")?;
        prev_tx.reverse(); // Little-endian

        let prev_index = decode_int(cursor, 4).map_err(|e| e.to_string())? as u32;
        let script_sig = Script::decode(cursor).map_err(|e| e.to_string())?;
        let sequence = decode_int(cursor, 4).map_err(|e| e.to_string())? as u32;

        Ok(TxIn {
            prev_tx,
            prev_index,
            script_sig,
            sequence,
            witness: Vec::new(),
            net: String::new(),
        })
    }

    /// Encode to bytes
    pub fn encode(&self, script_override: Option<bool>) -> Vec<u8> {
        let mut out = Vec::new();

        // Previous tx (reversed for little-endian)
        let mut prev_tx = self.prev_tx;
        prev_tx.reverse();
        out.extend_from_slice(&prev_tx);

        // Previous index
        out.extend(encode_int(self.prev_index as u64, 4));

        // Script
        match script_override {
            None => out.extend(self.script_sig.encode()),
            Some(true) => {
                // Use script_pubkey from previous output
                if let Ok(script) = self.script_pubkey() {
                    out.extend(script.encode());
                } else {
                    out.extend(Script::empty().encode());
                }
            }
            Some(false) => out.extend(Script::empty().encode()),
        }

        // Sequence
        out.extend(encode_int(self.sequence as u64, 4));

        out
    }

    /// Get value from previous output
    pub fn value(&self) -> Result<u64, String> {
        let tx = TxFetcher::fetch(&hex::encode(self.prev_tx), &self.net)?;
        Ok(tx.tx_outs[self.prev_index as usize].amount)
    }

    /// Get script_pubkey from previous output
    pub fn script_pubkey(&self) -> Result<Script, String> {
        let tx = TxFetcher::fetch(&hex::encode(self.prev_tx), &self.net)?;
        Ok(tx.tx_outs[self.prev_index as usize].script_pubkey.clone())
    }
}

/// Transaction Output
#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: u64,
    pub script_pubkey: Script,
}

impl TxOut {
    /// Decode from bytes
    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, String> {
        let amount = decode_int(cursor, 8).map_err(|e| e.to_string())?;
        let script_pubkey = Script::decode(cursor).map_err(|e| e.to_string())?;
        Ok(TxOut {
            amount,
            script_pubkey,
        })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(encode_int(self.amount, 8));
        out.extend(self.script_pubkey.encode());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_decode() {
        // Example from Programming Bitcoin Chapter 5
        let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let tx = Tx::decode(&mut cursor, "main").unwrap();

        // Metadata
        assert_eq!(tx.version, 1);
        assert!(!tx.segwit);

        // Input parsing
        assert_eq!(tx.tx_ins.len(), 1);
        assert_eq!(
            hex::encode(tx.tx_ins[0].prev_tx),
            "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        );
        assert_eq!(tx.tx_ins[0].prev_index, 0);
        assert_eq!(tx.tx_ins[0].sequence, 0xfffffffe);

        // Output parsing
        assert_eq!(tx.tx_outs.len(), 2);
        assert_eq!(tx.tx_outs[0].amount, 32454049);
        assert_eq!(tx.tx_outs[1].amount, 10011545);

        // Locktime
        assert_eq!(tx.locktime, 410393);

        // ID calculation
        assert_eq!(
            tx.id(),
            "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03"
        );

        // Roundtrip encoding
        let raw2 = tx.encode(false, None);
        assert_eq!(raw, raw2);
    }

    #[test]
    fn test_segwit_decode() {
        let raw = hex::decode("010000000001026c4224e4d6bab0cfdfd67870e084cda34e42d3544b3c77d310df40831fa4f5061700000023220020fb24ee0fec024ff3ff03c44d16ca523b78fd33ebaab99176e98b3f5e0e78da9dffffffffe8faf73aee5a09b1b678277fc63150dff639c97521e9088d6721a2b995f33664010000002322002083e1adc1eb82945fa99500bcd9df963b0e731524fd8eb25ef205e88d3bd7ab77ffffffff03a0370a00000000001976a914b00ff32bbc990acde3e5ac022e6d4120fb168f1e88ac7f791300000000001976a914128afed7e8d4e6f3a9d2d38ad560c307ebf392ba88ac54115c00000000001976a914c65d16caa1d8c1c46cc1bfac92eff06b02d8afcc88ac04004830450221009d93dc766b4a3417d7daccffe39719cd0344779c19d589d3a078625139a7dcd50220267c1b9b365d0eaa3b036771cbfc994c2b1c5b29e5107f023f036360cb60c8b50147304402206346b5c2bfa243c9cd0c5056abedfadc79e4a2b67b918315fc3faf79dfd12d7602203f729a665afd02ceb4b07898c06c81f0dfc378f66409ed828a4b5fe84f9287550169522102b951c91d97118489d1980ec472d89b5bc98fb98d0bafa17aca238d18a758b8642103d45b78e2a683330c62878e44610a5d1c8d40bd1f261b1110940b1b8a5aecd3e82103796ecd1667be6e20af571c46517e4ecf5e83052df864266658dd7f88e63efa6153ae0400483045022100e396deff2fe6dd6081e35f9dced6e09ea1b8b4830ae322b5d58986596996893d0220485420653c118c1a13b48941166b242077530d2b3cab908abe67af6b96ef2850014730440220171e11f4d6a106464a94e29f46750803a7deb214e6fbe2140ec5d80577dded0e02203483ab0c685f66e17b4afa86ba053732b43ff1ca7654796e72b69bd224bf26c4016952210375e42f77749f92a6b54c8e85fab2209e6807e15a3768c024a5cab01dc301c0282103fd4969521bd2d0f8e147c16655ae9c29dc48cb4f124b7a6398db78b1cbc878a221036bc18f387d1e4ba80492854cee639bd4ab6e3a310d9faa6f17350bbdc4c029d053ae25680a00").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let tx = Tx::decode(&mut cursor, "main").unwrap();

        // Metadata
        assert_eq!(tx.version, 1);
        assert!(tx.segwit);

        // Input parsing
        assert_eq!(tx.tx_ins.len(), 2);
        assert!(!tx.tx_ins[0].witness.is_empty());
        assert!(!tx.tx_ins[1].witness.is_empty());

        // Output parsing
        assert_eq!(tx.tx_outs.len(), 3);
        assert_eq!(tx.tx_outs[0].amount, 669600);
        assert_eq!(tx.tx_outs[1].amount, 1276287);
        assert_eq!(tx.tx_outs[2].amount, 6033748);

        // ID calculation
        assert_eq!(
            tx.id(),
            "3ecf9b3d965cfaa2c472f09b5f487fbd838e4e1f861e3542c541d39c5cb7bc25"
        );

        // Roundtrip encoding
        let raw2 = tx.encode(false, None);
        assert_eq!(raw, raw2);
    }

    #[test]
    fn test_is_coinbase() {
        // Not coinbase
        let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let tx = Tx::decode(&mut cursor, "main").unwrap();
        assert!(!tx.is_coinbase());

        // Is coinbase
        let raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let mut tx = Tx::decode(&mut cursor, "main").unwrap();
        assert!(tx.is_coinbase());

        // Make not coinbase by deleting inputs
        tx.tx_ins.clear();
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn test_coinbase_height() {
        // Not coinbase - should return None
        let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let tx = Tx::decode(&mut cursor, "main").unwrap();
        assert!(tx.coinbase_height().is_none());

        // Is coinbase - height should be 465879
        let raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000").unwrap();
        let mut cursor = Cursor::new(raw.as_slice());
        let tx = Tx::decode(&mut cursor, "main").unwrap();
        assert_eq!(tx.coinbase_height(), Some(465879));
    }

    #[test]
    fn test_tx_id() {
        // Simple test that encoding/id works
        let tx = Tx {
            version: 1,
            tx_ins: vec![],
            tx_outs: vec![],
            locktime: 0,
            segwit: false,
            net: "main".to_string(),
        };

        let id = tx.id();
        assert_eq!(id.len(), 64); // 32 bytes hex
    }
}
