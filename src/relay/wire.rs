//! Fixed-size, allocation-bounded admission packets, separate from QUIC datagrams.
use crate::identity::{Identity, NodeId};
use crate::nat::punch::PunchToken;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// Relay endpoints disable fixed-bit greasing; zero cannot collide with their QUIC headers.
pub const MAGIC: &[u8] = b"\0P2PF-RELAY/1";
pub const VERSION: u32 = 1;
pub const MAX_CONTROL: usize = 512;
const BIND_DOMAIN: &[u8] = b"p2p_file/relay-bind/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub token: PunchToken,
    pub node: NodeId,
    pub peer: NodeId,
    pub public_key: [u8; 32],
    pub client_nonce: [u8; 32],
}
impl Hello {
    pub fn new(identity: &Identity, peer: NodeId, token: PunchToken) -> Self {
        Self {
            token,
            node: identity.node_id(),
            peer,
            public_key: identity.public_key_bytes(),
            client_nonce: rand::random(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Challenge {
    pub hello: Hello,
    pub nonce: [u8; 32],
    pub source: SocketAddr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Packet {
    Hello(Hello),
    Challenge {
        client_nonce: [u8; 32],
        nonce: [u8; 32],
        source: SocketAddr,
    },
    Register {
        challenge: Challenge,
        signature_a: [u8; 32],
        signature_b: [u8; 32],
    },
    Ready {
        token: PunchToken,
        node: NodeId,
        client_nonce: [u8; 32],
    },
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    packet: Packet,
}
pub fn encode(packet: Packet) -> Result<Vec<u8>> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(&Envelope {
        version: VERSION,
        packet,
    })?);
    if bytes.len() > MAX_CONTROL {
        return Err(Error::Protocol("relay control packet too large".into()));
    }
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<Packet> {
    if bytes.len() > MAX_CONTROL || !bytes.starts_with(MAGIC) {
        return Err(Error::Protocol("invalid relay control envelope".into()));
    }
    let (envelope, remaining): (Envelope, _) = postcard::take_from_bytes(&bytes[MAGIC.len()..])?;
    if envelope.version != VERSION || !remaining.is_empty() {
        return Err(Error::Protocol(
            "unsupported or trailing relay control data".into(),
        ));
    }
    Ok(envelope.packet)
}
pub fn bind_payload(challenge: &Challenge) -> Result<Vec<u8>> {
    let mut payload = BIND_DOMAIN.to_vec();
    payload.extend_from_slice(&VERSION.to_be_bytes());
    payload.extend(postcard::to_allocvec(challenge)?);
    Ok(payload)
}
pub fn register(identity: &Identity, challenge: Challenge) -> Result<Packet> {
    let signature = identity.sign(&bind_payload(&challenge)?).to_bytes();
    Ok(Packet::Register {
        challenge,
        signature_a: signature[..32].try_into().unwrap(),
        signature_b: signature[32..].try_into().unwrap(),
    })
}
