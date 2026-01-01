//! Classes/utils for connecting to Bitcoin nodes
//! Protocol Documentation: https://en.bitcoin.it/wiki/Protocol_documentation

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::LazyLock;

use crate::block::Block;
use crate::script::{decode_varint, encode_varint};
use crate::sha256::sha256;

/// Network magic bytes
pub static MAGICS: LazyLock<HashMap<&'static str, [u8; 4]>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("main", [0xf9, 0xbe, 0xb4, 0xd9]);
    m.insert("test", [0x0b, 0x11, 0x09, 0x07]);
    m
});

/// Network envelope for Bitcoin P2P messages
#[derive(Debug, Clone)]
pub struct NetworkEnvelope {
    pub command: Vec<u8>,
    pub payload: Vec<u8>,
    pub net: String,
}

impl NetworkEnvelope {
    pub fn new(command: &[u8], payload: Vec<u8>, net: &str) -> Self {
        NetworkEnvelope {
            command: command.to_vec(),
            payload,
            net: net.to_string(),
        }
    }

    /// Decode from stream
    pub fn decode<R: Read>(stream: &mut R, net: &str) -> Result<Self, String> {
        // Read magic
        let mut magic = [0u8; 4];
        stream
            .read_exact(&mut magic)
            .map_err(|_| "No magic bytes; Connection was reset?")?;

        let expected_magic = MAGICS.get(net).ok_or("Unknown network")?;
        if magic != *expected_magic {
            return Err("Invalid magic bytes".to_string());
        }

        // Read command
        let mut command = [0u8; 12];
        stream
            .read_exact(&mut command)
            .map_err(|_| "Failed to read command")?;
        let command: Vec<u8> = command.iter().take_while(|&&b| b != 0).copied().collect();

        // Read payload length
        let mut payload_len_bytes = [0u8; 4];
        stream
            .read_exact(&mut payload_len_bytes)
            .map_err(|_| "Failed to read payload length")?;
        let payload_len = u32::from_le_bytes(payload_len_bytes) as usize;

        // Read checksum
        let mut checksum = [0u8; 4];
        stream
            .read_exact(&mut checksum)
            .map_err(|_| "Failed to read checksum")?;

        // Read payload
        let mut payload = vec![0u8; payload_len];
        stream
            .read_exact(&mut payload)
            .map_err(|_| "Failed to read payload")?;

        // Verify checksum
        let computed = sha256(&sha256(&payload));
        if checksum != computed[..4] {
            return Err("Invalid checksum".to_string());
        }

        Ok(NetworkEnvelope {
            command,
            payload,
            net: net.to_string(),
        })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Magic
        let magic = MAGICS.get(self.net.as_str()).unwrap();
        out.extend_from_slice(magic);

        // Command (padded to 12 bytes)
        let mut cmd = self.command.clone();
        cmd.resize(12, 0);
        out.extend_from_slice(&cmd);

        // Payload length
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());

        // Checksum
        let checksum = sha256(&sha256(&self.payload));
        out.extend_from_slice(&checksum[..4]);

        // Payload
        out.extend_from_slice(&self.payload);

        out
    }

    /// Get payload as cursor
    pub fn stream(&self) -> Cursor<&[u8]> {
        Cursor::new(self.payload.as_slice())
    }
}

impl std::fmt::Display for NetworkEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[NetworkEnvelope] Command: {}, Payload: {}",
            String::from_utf8_lossy(&self.command),
            hex::encode(&self.payload)
        )
    }
}

/// Network address structure
#[derive(Debug, Clone)]
pub struct NetAddrStruct {
    pub services: u64,
    pub ip: [u8; 4],
    pub port: u16,
}

impl Default for NetAddrStruct {
    fn default() -> Self {
        NetAddrStruct {
            services: 0,
            ip: [0; 4],
            port: 8333, // Default Bitcoin mainnet port
        }
    }
}

impl NetAddrStruct {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.services.to_le_bytes());
        out.extend_from_slice(&[0u8; 10]); // IPv6 padding
        out.extend_from_slice(&[0xff, 0xff]); // IPv4-mapped
        out.extend_from_slice(&self.ip);
        out.extend_from_slice(&self.port.to_be_bytes());
        out
    }
}

/// Version message
#[derive(Debug, Clone)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub receiver: NetAddrStruct,
    pub sender: NetAddrStruct,
    pub nonce: [u8; 8],
    pub user_agent: Vec<u8>,
    pub latest_block: u32,
    pub relay: bool,
}

impl Default for VersionMessage {
    fn default() -> Self {
        VersionMessage {
            version: 70015,
            services: 0,
            timestamp: 0,
            receiver: NetAddrStruct::default(),
            sender: NetAddrStruct::default(),
            nonce: [0; 8],
            user_agent: Vec::new(),
            latest_block: 0,
            relay: false,
        }
    }
}

impl VersionMessage {
    pub const COMMAND: &'static [u8] = b"version";

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.services.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend(self.receiver.encode());
        out.extend(self.sender.encode());
        out.extend_from_slice(&self.nonce);
        out.extend(encode_varint(self.user_agent.len() as u64));
        out.extend_from_slice(&self.user_agent);
        out.extend_from_slice(&self.latest_block.to_le_bytes());
        out.push(if self.relay { 1 } else { 0 });
        out
    }

    pub fn decode(_cursor: &mut Cursor<&[u8]>) -> Result<Self, String> {
        // Simplified: return default for now
        Ok(Self::default())
    }
}

/// Verack message
#[derive(Debug, Clone, Default)]
pub struct VerAckMessage;

impl VerAckMessage {
    pub const COMMAND: &'static [u8] = b"verack";

    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn decode(_cursor: &mut Cursor<&[u8]>) -> Result<Self, String> {
        Ok(Self)
    }
}

/// Ping message
#[derive(Debug, Clone)]
pub struct PingMessage {
    pub nonce: [u8; 8],
}

impl PingMessage {
    pub const COMMAND: &'static [u8] = b"ping";

    pub fn encode(&self) -> Vec<u8> {
        self.nonce.to_vec()
    }

    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, String> {
        let mut nonce = [0u8; 8];
        cursor
            .read_exact(&mut nonce)
            .map_err(|_| "Failed to read nonce")?;
        Ok(PingMessage { nonce })
    }
}

/// Pong message
#[derive(Debug, Clone)]
pub struct PongMessage {
    pub nonce: [u8; 8],
}

impl PongMessage {
    pub const COMMAND: &'static [u8] = b"pong";

    pub fn encode(&self) -> Vec<u8> {
        self.nonce.to_vec()
    }

    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, String> {
        let mut nonce = [0u8; 8];
        cursor
            .read_exact(&mut nonce)
            .map_err(|_| "Failed to read nonce")?;
        Ok(PongMessage { nonce })
    }
}

/// GetHeaders message
#[derive(Debug, Clone)]
pub struct GetHeadersMessage {
    pub version: u32,
    pub num_hashes: u64,
    pub start_block: [u8; 32],
    pub end_block: [u8; 32],
}

impl GetHeadersMessage {
    pub const COMMAND: &'static [u8] = b"getheaders";

    pub fn new(start_block: [u8; 32]) -> Self {
        GetHeadersMessage {
            version: 70015,
            num_hashes: 1,
            start_block,
            end_block: [0; 32],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend(encode_varint(self.num_hashes));

        let mut start = self.start_block;
        start.reverse();
        out.extend_from_slice(&start);

        let mut end = self.end_block;
        end.reverse();
        out.extend_from_slice(&end);

        out
    }
}

/// Headers message
#[derive(Debug, Clone)]
pub struct HeadersMessage {
    pub blocks: Vec<Block>,
}

impl HeadersMessage {
    pub const COMMAND: &'static [u8] = b"headers";

    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, String> {
        let count = decode_varint(cursor).map_err(|e| e.to_string())?;
        let mut blocks = Vec::new();

        for _ in 0..count {
            let block = Block::decode(cursor).map_err(|e| e.to_string())?;
            blocks.push(block);

            // Number of transactions (always 0 for headers)
            let num_tx = decode_varint(cursor).map_err(|e| e.to_string())?;
            if num_tx != 0 {
                return Err("Expected 0 transactions in headers".to_string());
            }
        }

        Ok(HeadersMessage { blocks })
    }
}

/// Simple Bitcoin node
pub struct SimpleNode {
    net: String,
    stream: TcpStream,
    verbose: bool,
}

impl SimpleNode {
    /// Connect to a Bitcoin node
    pub fn connect(host: &str, net: &str, verbose: bool) -> Result<Self, String> {
        let port = match net {
            "main" => 8333,
            "test" => 18333,
            _ => return Err("Unknown network".to_string()),
        };

        let stream = TcpStream::connect(format!("{}:{}", host, port)).map_err(|e| e.to_string())?;

        Ok(SimpleNode {
            net: net.to_string(),
            stream,
            verbose,
        })
    }

    /// Send a message
    pub fn send(&mut self, command: &[u8], payload: Vec<u8>) -> Result<(), String> {
        let env = NetworkEnvelope::new(command, payload, &self.net);
        if self.verbose {
            println!("sending: {}", env);
        }
        self.stream
            .write_all(&env.encode())
            .map_err(|e| e.to_string())
    }

    /// Read a message
    pub fn read(&mut self) -> Result<NetworkEnvelope, String> {
        let env = NetworkEnvelope::decode(&mut self.stream, &self.net)?;
        if self.verbose {
            println!("receiving: {}", env);
        }
        Ok(env)
    }

    /// Perform version handshake
    pub fn handshake(&mut self) -> Result<(), String> {
        let version = VersionMessage {
            timestamp: 0,
            nonce: [0; 8],
            user_agent: b"/simple-bitcoin-rust:0.1/".to_vec(),
            ..Default::default()
        };

        self.send(VersionMessage::COMMAND, version.encode())?;

        // Wait for version
        loop {
            let env = self.read()?;
            if env.command == VersionMessage::COMMAND {
                break;
            }
            self.handle_message(&env)?;
        }

        // Wait for verack
        loop {
            let env = self.read()?;
            if env.command == VerAckMessage::COMMAND {
                break;
            }
            self.handle_message(&env)?;
        }

        // Send verack
        self.send(VerAckMessage::COMMAND, Vec::new())?;

        Ok(())
    }

    /// Handle incoming messages (ping/pong, etc.)
    fn handle_message(&mut self, env: &NetworkEnvelope) -> Result<(), String> {
        if env.command == VersionMessage::COMMAND {
            self.send(VerAckMessage::COMMAND, Vec::new())?;
        } else if env.command == PingMessage::COMMAND {
            // Respond with pong
            self.send(PongMessage::COMMAND, env.payload.clone())?;
        }
        Ok(())
    }

    /// Close connection
    pub fn close(self) {
        drop(self.stream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_verack() {
        let msg = hex::decode("f9beb4d976657261636b000000000000000000005df6e0e2").unwrap();
        let mut cursor = Cursor::new(msg.as_slice());
        let envelope = NetworkEnvelope::decode(&mut cursor, "main").unwrap();

        assert_eq!(envelope.command, b"verack");
        assert_eq!(envelope.payload, b"");
        assert_eq!(envelope.encode(), msg);
    }

    #[test]
    fn test_encode_decode_version() {
        let msg = hex::decode("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001").unwrap();
        let mut cursor = Cursor::new(msg.as_slice());
        let envelope = NetworkEnvelope::decode(&mut cursor, "main").unwrap();

        assert_eq!(envelope.command, b"version");
        assert_eq!(envelope.payload, &msg[24..]);
        assert_eq!(envelope.encode(), msg);
    }

    #[test]
    fn test_encode_version_payload() {
        let m = VersionMessage {
            timestamp: 0,
            nonce: [0; 8],
            user_agent: b"/programmingbitcoin:0.1/".to_vec(),
            ..Default::default()
        };

        assert_eq!(
            hex::encode(m.encode()),
            "7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000"
        );
    }

    #[test]
    fn test_encode_getheaders_payload() {
        let block_hex = "0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3";
        let mut start_block = [0u8; 32];
        let bytes = hex::decode(block_hex).unwrap();
        start_block.copy_from_slice(&bytes);

        let m = GetHeadersMessage::new(start_block);
        assert_eq!(
            hex::encode(m.encode()),
            "7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_decode_headers_payload() {
        let hex_msg = "0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600";
        let bytes = hex::decode(hex_msg).unwrap();
        let mut cursor = Cursor::new(bytes.as_slice());
        let headers = HeadersMessage::decode(&mut cursor).unwrap();

        assert_eq!(headers.blocks.len(), 2);
    }

    #[test]
    fn test_network_envelope_roundtrip() {
        let env = NetworkEnvelope::new(b"test", vec![1, 2, 3], "main");
        let encoded = env.encode();

        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = NetworkEnvelope::decode(&mut cursor, "main").unwrap();

        assert_eq!(env.command, decoded.command);
        assert_eq!(env.payload, decoded.payload);
    }
}
