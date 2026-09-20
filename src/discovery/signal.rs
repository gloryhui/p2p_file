//! 公网信令：让两个素不相识的节点交换各自的候选地址。
//!
//! 信令服务器只做「牵线」，不碰文件数据。职责是：
//!
//! 1. 节点上线时登记自己的节点 ID 和公钥；
//! 2. 双方各自把 STUN 观测到的公网映射、局域网地址、IPv6 地址报上去；
//! 3. 把对方的候选列表取回来，然后双方同时开始打洞。
//!
//! 这一层**目前还是空壳**：线格式（[`SignalMessage`]）和候选排序已经定下来
//! 并且有测试，但收发通道还没实现——传输方式（HTTP + WebSocket 还是裸
//! TCP + postcard）属于待定问题，见 `docs/ARCHITECTURE.md` 第 7 节。

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::NodeId;

/// 候选地址的类型，决定了它的优先级。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum CandidateKind {
    /// 服务器反射地址（STUN 看到的公网映射）。
    ServerReflexive,
    /// 中继地址（TURN / relay），成功率最高但绕远路。
    Relay,
    /// 用端口预测猜出来的地址，只在对称型 NAT 下才用。
    Predicted,
    /// 直连地址（局域网或本机地址）。
    Host,
}

impl CandidateKind {
    /// 数字越小越优先尝试。
    ///
    /// 顺序是刻意排的：先试公网映射（直连、延迟低），再试局域网和 IPv6
    /// 直连（同网段时最快），打洞不成才用中继，最后才是猜出来的地址。
    pub fn priority(self) -> u32 {
        match self {
            Self::ServerReflexive => 0,
            Self::Host => 1,
            Self::Predicted => 2,
            Self::Relay => 3,
        }
    }
}

/// 一个候选地址。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: SocketAddr,
}

impl Candidate {
    pub fn new(kind: CandidateKind, addr: SocketAddr) -> Self {
        Self { kind, addr }
    }
}

/// 把候选地址按尝试顺序排好。
///
/// 同优先级里 IPv6 排前面：没有 NAT 的可能性大，成功率高。
pub fn sort_candidates(candidates: &mut [Candidate]) {
    candidates.sort_by_key(|candidate| {
        let family_bonus = if candidate.addr.is_ipv6() { 0 } else { 1 };
        (candidate.kind.priority(), family_bonus)
    });
}

/// 去重（同类型同地址只留一个）。
pub fn dedup_candidates(candidates: &mut Vec<Candidate>) {
    let mut seen = Vec::new();
    candidates.retain(|candidate| {
        if seen.contains(candidate) {
            false
        } else {
            seen.push(*candidate);
            true
        }
    });
}

/// 信令消息。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalMessage {
    /// 上线登记。
    Register {
        node_id: NodeId,
        public_key: [u8; 32],
        candidates: Vec<Candidate>,
    },
    /// 节点下线。
    Unregister { node_id: NodeId },
    /// 查询某个节点的候选地址。
    Lookup { node_id: NodeId },
    /// 查询结果。`candidates` 为空表示对方不在线。
    LookupResult {
        node_id: NodeId,
        candidates: Vec<Candidate>,
    },
    /// 出错。
    Error { reason: String },
}

impl SignalMessage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

/// 信令客户端。
///
/// TODO(M2)：实现与信令服务器的连接。接口先定下来，方便先写打洞逻辑。
pub struct SignalingClient {
    server: String,
}

impl SignalingClient {
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
        }
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    /// 登记自己并取回当前在线节点。
    pub async fn register(&self, _message: SignalMessage) -> Result<Vec<Candidate>> {
        Err(Error::Unimplemented(
            "信令客户端尚未实现（M2），暂时只能用局域网 mDNS 发现对端",
        ))
    }

    /// 查询某个节点的候选地址。
    pub async fn lookup(&self, _node_id: NodeId) -> Result<Vec<Candidate>> {
        Err(Error::Unimplemented(
            "信令客户端尚未实现（M2），暂时只能用局域网 mDNS 发现对端",
        ))
    }
}

impl std::fmt::Debug for SignalingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalingClient")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(kind: CandidateKind, addr: &str) -> Candidate {
        Candidate::new(kind, addr.parse().unwrap())
    }

    #[test]
    fn 候选排序_公网映射优先于中继() {
        let mut candidates = vec![
            candidate(CandidateKind::Relay, "10.0.0.1:1000"),
            candidate(CandidateKind::ServerReflexive, "203.0.113.5:5000"),
            candidate(CandidateKind::Host, "192.168.1.20:9000"),
        ];
        sort_candidates(&mut candidates);
        assert_eq!(candidates[0].kind, CandidateKind::ServerReflexive);
        assert_eq!(candidates[1].kind, CandidateKind::Host);
        assert_eq!(candidates[2].kind, CandidateKind::Relay);
    }

    #[test]
    fn 候选排序_同类里_ipv6_优先() {
        let mut candidates = vec![
            candidate(CandidateKind::Host, "192.168.1.20:9000"),
            candidate(CandidateKind::Host, "[2001:db8::20]:9000"),
        ];
        sort_candidates(&mut candidates);
        assert!(candidates[0].addr.is_ipv6());
    }

    #[test]
    fn 优先级数值单调() {
        assert!(CandidateKind::ServerReflexive.priority() < CandidateKind::Host.priority());
        assert!(CandidateKind::Host.priority() < CandidateKind::Predicted.priority());
        assert!(CandidateKind::Predicted.priority() < CandidateKind::Relay.priority());
    }

    #[test]
    fn 候选去重() {
        let mut candidates = vec![
            candidate(CandidateKind::Host, "192.168.1.20:9000"),
            candidate(CandidateKind::Host, "192.168.1.20:9000"),
            candidate(CandidateKind::ServerReflexive, "203.0.113.5:5000"),
            candidate(CandidateKind::Host, "192.168.1.21:9000"),
        ];
        dedup_candidates(&mut candidates);
        assert_eq!(candidates.len(), 3);
        // 同地址不同类型不算重复。
        candidates.push(candidate(CandidateKind::Predicted, "192.168.1.20:9000"));
        dedup_candidates(&mut candidates);
        assert_eq!(candidates.len(), 4);
    }

    #[test]
    fn 信令消息往返() {
        let messages = vec![
            SignalMessage::Register {
                node_id: NodeId::from_hex("00112233445566778899aabbccddeeff").unwrap(),
                public_key: [7u8; 32],
                candidates: vec![candidate(CandidateKind::Host, "192.168.1.20:9000")],
            },
            SignalMessage::Lookup {
                node_id: NodeId::from_hex("00112233445566778899aabbccddeeff").unwrap(),
            },
            SignalMessage::LookupResult {
                node_id: NodeId::from_hex("00112233445566778899aabbccddeeff").unwrap(),
                candidates: vec![],
            },
            SignalMessage::Unregister {
                node_id: NodeId::from_hex("00112233445566778899aabbccddeeff").unwrap(),
            },
            SignalMessage::Error {
                reason: "对端不在线".into(),
            },
        ];

        for message in messages {
            let decoded = SignalMessage::decode(&message.encode().unwrap()).unwrap();
            assert_eq!(message, decoded);
        }
    }

    #[tokio::test]
    async fn 未实现的方法明确报错() {
        let client = SignalingClient::new("signal.example.com:7000");
        assert_eq!(client.server(), "signal.example.com:7000");
        let node_id = NodeId::from_hex("00112233445566778899aabbccddeeff").unwrap();
        assert!(matches!(
            client.lookup(node_id).await,
            Err(Error::Unimplemented(_))
        ));
    }
}
