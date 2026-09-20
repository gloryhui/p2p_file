//! 控制消息与握手签名载荷。

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::identity::NodeId;
use crate::protocol::manifest::{ChunkHash, FileManifest};

/// 协议版本。不兼容改动时递增。
pub const PROTOCOL_VERSION: u32 = 1;

/// 握手签名的用途标签，避免签名被挪用到别处。
pub const HANDSHAKE_DOMAIN: &[u8] = b"p2p_file/handshake/v1";

/// 握手/传输通道上流动的消息。
///
/// 注意：`Chunk` 直接携带整片数据，只适合初稿。真正跑大文件时数据应当走
/// 独立的单向流，避免控制消息和大块数据在同一个流里互相阻塞（TODO）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// 发起方打招呼，带上自己的公钥和随机数。
    Hello {
        protocol_version: u32,
        node_id: NodeId,
        public_key: [u8; 32],
        nonce: [u8; 32],
    },
    /// 接收方回应，并对双方公钥 + 双方随机数签名。
    HelloAck {
        protocol_version: u32,
        node_id: NodeId,
        public_key: [u8; 32],
        nonce: [u8; 32],
        peer_nonce: [u8; 32],
        signature: Vec<u8>,
    },
    /// 发起方的回签，让接收方也确认对面身份（双向认证）。
    Auth { signature: Vec<u8> },
    /// 双方确认身份，可以开始传。
    Ready,

    /// 发送端下发文件清单。
    Manifest(Box<FileManifest>),
    /// 接收端声明自己已校验通过的分片位图，用于断点续传。
    Resume { have: Vec<u8> },
    /// 接收端请求某一片。
    RequestChunk { index: u32 },
    /// 发送端回应一片数据。
    Chunk { index: u32, data: Vec<u8> },
    /// 接收端确认某一片已落盘并通过校验。
    ChunkAck { index: u32 },
    /// 全部收完，回报根哈希。
    Complete { root_hash: ChunkHash },

    /// 保活，维持 NAT 映射和 QUIC 连接。
    KeepAlive,
    /// 出错了，附带原因。
    Abort { reason: String },
    /// 礼貌结束。
    Bye,
}

impl ControlMessage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(postcard::from_bytes(bytes)?)
    }

    /// 便于日志阅读的简短名字。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::HelloAck { .. } => "HelloAck",
            Self::Auth { .. } => "Auth",
            Self::Ready => "Ready",
            Self::Manifest(_) => "Manifest",
            Self::Resume { .. } => "Resume",
            Self::RequestChunk { .. } => "RequestChunk",
            Self::Chunk { .. } => "Chunk",
            Self::ChunkAck { .. } => "ChunkAck",
            Self::Complete { .. } => "Complete",
            Self::KeepAlive => "KeepAlive",
            Self::Abort { .. } => "Abort",
            Self::Bye => "Bye",
        }
    }
}

/// 握手签名载荷。
///
/// 双方都要算出**完全相同**的字节串。为避免依赖「谁是发起方」，
/// 这里按公钥字节序排序后拼接，两侧结果自然一致。
pub fn handshake_payload(
    public_key_a: &[u8; 32],
    nonce_a: &[u8; 32],
    public_key_b: &[u8; 32],
    nonce_b: &[u8; 32],
) -> Vec<u8> {
    let (first, second) = if public_key_a <= public_key_b {
        ((public_key_a, nonce_a), (public_key_b, nonce_b))
    } else {
        ((public_key_b, nonce_b), (public_key_a, nonce_a))
    };

    let mut payload = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 2 * (32 + 32));
    payload.extend_from_slice(HANDSHAKE_DOMAIN);
    payload.extend_from_slice(first.0);
    payload.extend_from_slice(first.1);
    payload.extend_from_slice(second.0);
    payload.extend_from_slice(second.1);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, NodeId, signature_from_bytes};

    #[test]
    fn 消息编解码往返() {
        let identity = Identity::generate();
        let messages = vec![
            ControlMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                node_id: identity.node_id(),
                public_key: identity.public_key_bytes(),
                nonce: [1u8; 32],
            },
            ControlMessage::Auth {
                signature: vec![9u8; 64],
            },
            ControlMessage::Ready,
            ControlMessage::Resume {
                have: vec![0b1010_1010, 0b0000_0001],
            },
            ControlMessage::RequestChunk { index: 42 },
            ControlMessage::Chunk {
                index: 42,
                data: vec![0xab; 1024],
            },
            ControlMessage::KeepAlive,
            ControlMessage::Abort {
                reason: "对端掉线".into(),
            },
            ControlMessage::Bye,
        ];

        for message in messages {
            let bytes = message.encode().unwrap();
            let decoded = ControlMessage::decode(&bytes).unwrap();
            assert_eq!(message, decoded, "{} 往返失败", message.kind());
        }
    }

    #[test]
    fn 清单消息往返() {
        let manifest = FileManifest::new("a.bin", 0, 65536, vec![]).unwrap();
        let message = ControlMessage::Manifest(Box::new(manifest));
        let decoded = ControlMessage::decode(&message.encode().unwrap()).unwrap();
        assert_eq!(message, decoded);
    }

    #[test]
    fn 握手载荷与角色无关() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let nonce_a = [0xaa; 32];
        let nonce_b = [0xbb; 32];

        let from_alice = handshake_payload(
            &alice.public_key_bytes(),
            &nonce_a,
            &bob.public_key_bytes(),
            &nonce_b,
        );
        let from_bob = handshake_payload(
            &bob.public_key_bytes(),
            &nonce_b,
            &alice.public_key_bytes(),
            &nonce_a,
        );
        assert_eq!(from_alice, from_bob, "双方算出的握手载荷必须一致");
    }

    #[test]
    fn 握手载荷对随机数敏感() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let base = handshake_payload(
            &alice.public_key_bytes(),
            &[1u8; 32],
            &bob.public_key_bytes(),
            &[2u8; 32],
        );
        let changed = handshake_payload(
            &alice.public_key_bytes(),
            &[1u8; 32],
            &bob.public_key_bytes(),
            &[3u8; 32],
        );
        assert_ne!(base, changed, "随机数必须进入签名载荷，防重放");
    }

    #[test]
    fn 握手签名能被对方验证_并挡住冒名者() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();
        let nonce_a = [7u8; 32];
        let nonce_b = [8u8; 32];

        let payload = handshake_payload(
            &alice.public_key_bytes(),
            &nonce_a,
            &bob.public_key_bytes(),
            &nonce_b,
        );

        // Bob 用自己算出的载荷验证 Alice 的签名。
        let alice_payload = handshake_payload(
            &bob.public_key_bytes(),
            &nonce_b,
            &alice.public_key_bytes(),
            &nonce_a,
        );
        assert_eq!(payload, alice_payload);

        let signature = alice.sign(&payload);
        let parsed = signature_from_bytes(&signature.to_bytes()).unwrap();
        assert!(alice.verify(&alice_payload, &parsed).is_ok());

        // Mallory 冒用 Alice 的公钥，签名验不过。
        assert!(
            alice
                .verify(&alice_payload, &mallory.sign(&payload))
                .is_err()
        );
    }

    #[test]
    fn 节点_id_能编码进消息() {
        let id = NodeId::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let message = ControlMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            node_id: id,
            public_key: [0u8; 32],
            nonce: [0u8; 32],
        };
        let decoded = ControlMessage::decode(&message.encode().unwrap()).unwrap();
        match decoded {
            ControlMessage::Hello { node_id, .. } => assert_eq!(node_id, id),
            other => panic!("意料之外的消息: {other:?}"),
        }
    }
}
