//! 控制消息与握手签名载荷。

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::identity::NodeId;
use crate::protocol::manifest::{ChunkHash, FileManifest};

/// 协议版本。不兼容改动时递增。
///
/// v3：文件传输的 `Complete` 只在接收端 finalize 成功后发送；同时保留 v2 的
/// TLS 会话绑定握手。v2 节点仍使用 finalize 前的 Complete 语义，必须在握手阶段
/// 以明确的版本错误拒绝，不能静默互通。
pub const PROTOCOL_VERSION: u32 = 3;

/// 握手签名的用途标签，避免签名被挪用到别处。
///
/// 载荷格式在 v2 改成了「双方公钥 + 双方随机数 + 会话绑定值」。v3 的传输完成
/// 语义也不与旧节点混用，因此握手域同步升到 v3。
pub const HANDSHAKE_DOMAIN: &[u8] = b"p2p_file/handshake/v3";

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

    /// 请求转发一条 TCP 连接到 `target`（形如 `127.0.0.1:22`）。
    TunnelOpen { target: String },
    /// 隧道已就绪，可以开始搬字节了。
    TunnelReady,
    /// 隧道建立失败。
    TunnelError { reason: String },

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

    /// 解码控制消息。
    ///
    /// `Manifest` 是「不可信字节直接变成一个会被大量使用的结构体」的唯一入口，
    /// 所以在这里就把清单完整校验掉：解码成功的 `ControlMessage::Manifest`
    /// **一定**已经通过 [`FileManifest::validate`]，下游不必再怀疑它。这样
    /// 未来新增的接收路径也不会因为忘记校验而踩到畸形清单。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let message: Self = postcard::from_bytes(bytes)?;
        if let Self::Manifest(manifest) = &message {
            manifest.validate()?;
        }
        Ok(message)
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
            Self::TunnelOpen { .. } => "TunnelOpen",
            Self::TunnelReady => "TunnelReady",
            Self::TunnelError { .. } => "TunnelError",
            Self::KeepAlive => "KeepAlive",
            Self::Abort { .. } => "Abort",
            Self::Bye => "Bye",
        }
    }
}

/// 握手签名载荷。
///
/// 双方都要算出**完全相同**的字节串。为避免依赖「谁是发起方」，
/// 前四项按公钥字节序排序后拼接，两侧结果自然一致。
///
/// `channel_binding` 是当前 QUIC/TLS 会话导出的绑定值（见
/// [`crate::transport::quic::ChannelBinding`]），附加在末尾。因为两侧会话相同、
/// 导出的绑定值相同，排序后的角色无关性仍然成立。
///
/// 为什么必须带上它：只签「双方公钥 + 随机数」时，中间人可以建两条独立
/// TLS 会话（A↔M、M↔B），把 A 侧握手的消息原样搬到 B 侧。A、B 的签名和随机数
/// 都自洽，验证全过，但业务流量实际经过 M。把会话绑定值写进签名载荷后，
/// 搬运过去的签名用的是**另一条**会话的绑定值，必然验不过。
pub fn handshake_payload(
    public_key_a: &[u8; 32],
    nonce_a: &[u8; 32],
    public_key_b: &[u8; 32],
    nonce_b: &[u8; 32],
    channel_binding: &[u8; 32],
) -> Vec<u8> {
    let (first, second) = if public_key_a <= public_key_b {
        ((public_key_a, nonce_a), (public_key_b, nonce_b))
    } else {
        ((public_key_b, nonce_b), (public_key_a, nonce_a))
    };

    let mut payload = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 2 * (32 + 32) + 32);
    payload.extend_from_slice(HANDSHAKE_DOMAIN);
    payload.extend_from_slice(first.0);
    payload.extend_from_slice(first.1);
    payload.extend_from_slice(second.0);
    payload.extend_from_slice(second.1);
    payload.extend_from_slice(channel_binding);
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
            ControlMessage::TunnelOpen {
                target: "127.0.0.1:22".into(),
            },
            ControlMessage::TunnelReady,
            ControlMessage::TunnelError {
                reason: "目标拒绝连接".into(),
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

    /// Issue #3：畸形清单必须在解码这一层就被拒绝。
    ///
    /// 旧代码 `decode` 只是 `postcard::from_bytes`，攻击者可以自己算出根哈希，
    /// 却把 `chunk_size` 写成 0 —— 解出来的清单一路走到接收端才 `div_ceil(0)` panic。
    #[test]
    fn 畸形清单在解码时就被拒绝() {
        use crate::error::Error;
        use crate::protocol::manifest::{ChunkHash, MIN_CHUNK_SIZE, root_hash_of};

        // chunk_size = 0，但根哈希是自洽的（攻击者自己算的）。
        let zero_chunk_size = {
            let chunks = vec![ChunkHash::of(b"x")];
            let root_hash = root_hash_of("evil.bin", 1024, 0, &chunks);
            FileManifest {
                file_name: "evil.bin".into(),
                total_len: 1024,
                chunk_size: 0,
                chunks,
                root_hash,
            }
        };
        let bytes = ControlMessage::Manifest(Box::new(zero_chunk_size.clone()))
            .encode()
            .unwrap();
        // postcard 自己能解出来，说明「能解码」不代表「可用」。
        assert!(postcard::from_bytes::<ControlMessage>(&bytes).is_ok());
        let err = ControlMessage::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "实际 {err:?}");

        // 分片数与 total_len 不符：根哈希同样自洽。
        let mismatched = {
            let chunks = vec![ChunkHash::of(b"a")];
            let root_hash = root_hash_of("a.bin", 10_000_000, MIN_CHUNK_SIZE, &chunks);
            FileManifest {
                file_name: "a.bin".into(),
                total_len: 10_000_000,
                chunk_size: MIN_CHUNK_SIZE,
                chunks,
                root_hash,
            }
        };
        let bytes = ControlMessage::Manifest(Box::new(mismatched))
            .encode()
            .unwrap();
        assert!(matches!(
            ControlMessage::decode(&bytes).unwrap_err(),
            Error::Protocol(_)
        ));

        // 根哈希根本不对。
        let mut bad_root = FileManifest::new("b.bin", 0, MIN_CHUNK_SIZE, vec![]).unwrap();
        bad_root.root_hash = ChunkHash::of(b"nope");
        let bytes = ControlMessage::Manifest(Box::new(bad_root))
            .encode()
            .unwrap();
        assert!(matches!(
            ControlMessage::decode(&bytes).unwrap_err(),
            Error::Protocol(_)
        ));
    }

    #[test]
    fn 握手载荷与角色无关() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let nonce_a = [0xaa; 32];
        let nonce_b = [0xbb; 32];
        let binding = [0xcc; 32];

        let from_alice = handshake_payload(
            &alice.public_key_bytes(),
            &nonce_a,
            &bob.public_key_bytes(),
            &nonce_b,
            &binding,
        );
        let from_bob = handshake_payload(
            &bob.public_key_bytes(),
            &nonce_b,
            &alice.public_key_bytes(),
            &nonce_a,
            &binding,
        );
        assert_eq!(from_alice, from_bob, "双方算出的握手载荷必须一致");
    }

    #[test]
    fn 握手载荷对随机数敏感() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let binding = [0u8; 32];
        let base = handshake_payload(
            &alice.public_key_bytes(),
            &[1u8; 32],
            &bob.public_key_bytes(),
            &[2u8; 32],
            &binding,
        );
        let changed = handshake_payload(
            &alice.public_key_bytes(),
            &[1u8; 32],
            &bob.public_key_bytes(),
            &[3u8; 32],
            &binding,
        );
        assert_ne!(base, changed, "随机数必须进入签名载荷，防重放");
    }

    #[test]
    fn 握手载荷对会话绑定敏感() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let nonce_a = [1u8; 32];
        let nonce_b = [2u8; 32];

        let base = handshake_payload(
            &alice.public_key_bytes(),
            &nonce_a,
            &bob.public_key_bytes(),
            &nonce_b,
            &[0x11; 32],
        );
        // 只翻转 1 bit：载荷必须随之改变，否则绑定形同虚设。
        let mut flipped = [0x11u8; 32];
        flipped[7] ^= 0x01;
        let changed = handshake_payload(
            &alice.public_key_bytes(),
            &nonce_a,
            &bob.public_key_bytes(),
            &nonce_b,
            &flipped,
        );
        assert_ne!(base, changed, "会话绑定值必须进入签名载荷");

        // 绑定值必须真的被拼进去，而不是被忽略。
        let mut expected_tail = [0u8; 32];
        expected_tail.copy_from_slice(&base[base.len() - 32..]);
        assert_eq!(expected_tail, [0x11u8; 32], "载荷末尾应当是绑定值");
    }

    #[test]
    fn 握手签名能被对方验证_并挡住冒名者() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();
        let nonce_a = [7u8; 32];
        let nonce_b = [8u8; 32];
        let binding = [9u8; 32];

        let payload = handshake_payload(
            &alice.public_key_bytes(),
            &nonce_a,
            &bob.public_key_bytes(),
            &nonce_b,
            &binding,
        );

        // Bob 用自己算出的载荷验证 Alice 的签名。
        let alice_payload = handshake_payload(
            &bob.public_key_bytes(),
            &nonce_b,
            &alice.public_key_bytes(),
            &nonce_a,
            &binding,
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
