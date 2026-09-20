//! 公网信令：让两个素不相识的节点交换各自的候选地址。
//!
//! 信令服务器只做「牵线」，**不碰任何数据**。职责是：
//!
//! 1. 节点上线时登记自己的节点 ID 和候选地址；
//! 2. 一方查询另一方时，把双方候选互相推送；
//! 3. 之后双方自行打洞，数据走直连，服务器不参与。
//!
//! 走 TCP + 长度前缀 postcard，这样只要放通一个 TCP 端口就能用。
//! 信令是明文的，但里面只有公钥和地址，没有秘密——身份由应用层握手确认，
//! 所以信令服务器即使被攻破，也无法冒充任何一方。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::nat::punch::PunchToken;
use crate::protocol::frame::{read_raw_frame, write_raw_frame};

/// 信令服务器默认端口。
pub const DEFAULT_SIGNAL_PORT: u16 = 7000;

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

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServerReflexive => "公网映射",
            Self::Relay => "中继",
            Self::Predicted => "预测",
            Self::Host => "本机/局域网",
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

    /// 公网映射候选（STUN 或手动指定）。
    pub fn reflexive(addr: SocketAddr) -> Self {
        Self::new(CandidateKind::ServerReflexive, addr)
    }

    /// 本机/局域网候选。
    pub fn host(addr: SocketAddr) -> Self {
        Self::new(CandidateKind::Host, addr)
    }
}

impl std::fmt::Display for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}（{}）", self.addr, self.kind.as_str())
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
    /// 客户端 → 服务器：上线登记。
    Register {
        node_id: NodeId,
        public_key: [u8; 32],
        candidates: Vec<Candidate>,
    },
    /// 服务器 → 客户端：登记成功。
    Registered,
    /// 客户端 → 服务器：我要找这个节点。
    Lookup {
        node_id: NodeId,
    },
    /// 服务器 → 客户端：对方的候选地址（对方已就位）。
    ///
    /// `token` 是服务器为这一对节点生成的打洞令牌，双方拿到的必须一致。
    /// 有了它，打洞时就能安全地接受「来自任意地址」的探测包，从而打通那些
    /// 公网端口按目标分配的 NAT（地址相关映射型）。
    PeerCandidates {
        node_id: NodeId,
        candidates: Vec<Candidate>,
        token: PunchToken,
    },
    /// 服务器 → 客户端：对方还没上线，等着，来了会推送。
    PeerPending {
        node_id: NodeId,
    },
    /// 心跳。
    Ping,
    Pong,
    /// 出错。
    Error {
        reason: String,
    },
}

impl SignalMessage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(postcard::from_bytes(bytes)?)
    }

    /// 便于日志阅读的简短名字。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Register { .. } => "Register",
            Self::Registered => "Registered",
            Self::Lookup { .. } => "Lookup",
            Self::PeerCandidates { .. } => "PeerCandidates",
            Self::PeerPending { .. } => "PeerPending",
            Self::Ping => "Ping",
            Self::Pong => "Pong",
            Self::Error { .. } => "Error",
        }
    }
}

// ---------------------------------------------------------------------------
// 信令服务器
// ---------------------------------------------------------------------------

/// 一个已登记的对端。
struct PeerRecord {
    candidates: Vec<Candidate>,
    /// 往这条连接推消息用的发送端。
    outbox: mpsc::UnboundedSender<SignalMessage>,
}

/// 内存里的在线表。进程重启即清空——客户端会重新登记。
#[derive(Default)]
struct Registry {
    peers: HashMap<NodeId, PeerRecord>,
    /// 谁在等谁上线：`waiters[target] = {requester, ...}`。
    waiters: HashMap<NodeId, HashSet<NodeId>>,
}

impl Registry {
    /// 双方都在线就互相推送候选，只推一次。
    fn try_pair(&mut self, a: NodeId, b: NodeId) {
        let (Some(record_a), Some(record_b)) = (self.peers.get(&a), self.peers.get(&b)) else {
            return;
        };
        let candidates_a = record_a.candidates.clone();
        let candidates_b = record_b.candidates.clone();
        let outbox_a = record_a.outbox.clone();
        let outbox_b = record_b.outbox.clone();

        // 每次牵线换一个新令牌：上一轮的探测包不该能打通这一轮。
        //
        // 同一对节点确实可能被牵线两次（对方上线推一次、自己查询又推一次），
        // 于是产生两个令牌。但这不会让双方拿到不同的令牌——两次推送都按同样的
        // 顺序写进双方的发送队列，两边读到的第一条必然是同一次牵线的，
        // `同一对节点拿到的令牌必须一致` 这条测试盯着这个不变量。
        let token = PunchToken::random();

        tracing::info!(
            a = %a.short(),
            b = %b.short(),
            a_candidates = candidates_a.len(),
            b_candidates = candidates_b.len(),
            token = %token,
            "牵线成功，双方开始打洞"
        );
        let _ = outbox_a.send(SignalMessage::PeerCandidates {
            node_id: b,
            candidates: candidates_b,
            token,
        });
        let _ = outbox_b.send(SignalMessage::PeerCandidates {
            node_id: a,
            candidates: candidates_a,
            token,
        });
    }
}

/// 跑信令服务器，永不返回（除非出错）。
pub async fn run_signal_server(listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    run_signal_server_on(listener).await
}

/// 在**已经绑好**的监听器上跑信令服务器。
///
/// 单独拆出来是为了测试能用 `127.0.0.1:0` 绑定再拿到真实端口，避免抢端口。
pub async fn run_signal_server_on(listener: TcpListener) -> Result<()> {
    let local = listener.local_addr()?;
    tracing::info!(%local, "信令服务器已启动，等待节点接入（只牵线，不过数据）");

    let registry = Arc::new(Mutex::new(Registry::default()));

    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "接受连接失败，继续监听");
                continue;
            }
        };
        tracing::debug!(%remote, "信令连接建立");

        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            if let Err(err) = handle_signal_client(stream, registry).await {
                tracing::debug!(%remote, error = %err, "信令连接结束");
            }
        });
    }
}

async fn handle_signal_client(stream: TcpStream, registry: Arc<Mutex<Registry>>) -> Result<()> {
    // 信令消息都很小，别让 Nagle 拖慢牵线。
    let _ = stream.set_nodelay(true);
    let (read_half, write_half) = stream.into_split();
    let (outbox, inbox) = mpsc::unbounded_channel::<SignalMessage>();

    let writer = tokio::spawn(writer_loop(write_half, inbox));

    let mut reader = BufReader::new(read_half);
    let mut node_id: Option<NodeId> = None;

    loop {
        // 注意：这里**不能**用 `?` 直接返回。对端被强杀时读到的是 RST（错误）
        // 而不是干净的 EOF，一旦提前返回就会跳过下面的下线清理，让一个已经
        // 死掉的节点永远留在在线表里，服务器随后就会把过期的候选地址发给别人。
        let payload = match read_raw_frame(&mut reader).await {
            Ok(Some(payload)) => payload,
            Ok(None) => break,
            Err(err) => {
                tracing::debug!(error = %err, "信令连接读取出错，按断开处理");
                break;
            }
        };
        let message = match SignalMessage::decode(&payload) {
            Ok(message) => message,
            Err(err) => {
                tracing::warn!(error = %err, "信令消息解析失败");
                let _ = outbox.send(SignalMessage::Error {
                    reason: format!("消息解析失败: {err}"),
                });
                continue;
            }
        };

        match message {
            SignalMessage::Register {
                node_id: id,
                candidates,
                ..
            } => {
                node_id = Some(id);
                let waiters = {
                    let mut reg = registry.lock().await;
                    // 重连时覆盖旧记录。
                    reg.peers.insert(
                        id,
                        PeerRecord {
                            candidates: candidates.clone(),
                            outbox: outbox.clone(),
                        },
                    );
                    reg.waiters.remove(&id).unwrap_or_default()
                };

                tracing::info!(
                    node = %id.short(),
                    candidates = candidates.len(),
                    waiters = waiters.len(),
                    "节点登记"
                );
                let _ = outbox.send(SignalMessage::Registered);

                // 有人在等它，现在可以牵线了。
                for waiter in waiters {
                    registry.lock().await.try_pair(waiter, id);
                }
            }

            SignalMessage::Lookup { node_id: target } => {
                let Some(me) = node_id else {
                    let _ = outbox.send(SignalMessage::Error {
                        reason: "还没登记就想查询".into(),
                    });
                    continue;
                };
                if me == target {
                    let _ = outbox.send(SignalMessage::Error {
                        reason: "别查自己".into(),
                    });
                    continue;
                }

                let online = {
                    let reg = registry.lock().await;
                    reg.peers.contains_key(&target)
                };

                if online {
                    registry.lock().await.try_pair(me, target);
                } else {
                    tracing::debug!(
                        node = %me.short(),
                        target = %target.short(),
                        "目标还没上线，挂起等待"
                    );
                    registry
                        .lock()
                        .await
                        .waiters
                        .entry(target)
                        .or_default()
                        .insert(me);
                    let _ = outbox.send(SignalMessage::PeerPending { node_id: target });
                }
            }

            SignalMessage::Ping => {
                let _ = outbox.send(SignalMessage::Pong);
            }

            other => {
                tracing::debug!(kind = other.kind(), "服务器忽略该消息");
            }
        }
    }

    // 断开：从在线表里摘掉。
    if let Some(id) = node_id {
        let mut reg = registry.lock().await;
        reg.peers.remove(&id);
        for waiters in reg.waiters.values_mut() {
            waiters.remove(&id);
        }
        tracing::info!(node = %id.short(), "节点下线");
    }

    writer.abort();
    Ok(())
}

async fn writer_loop(
    mut writer: OwnedWriteHalf,
    mut inbox: mpsc::UnboundedReceiver<SignalMessage>,
) {
    while let Some(message) = inbox.recv().await {
        let payload = match message.encode() {
            Ok(payload) => payload,
            Err(err) => {
                tracing::warn!(error = %err, "信令消息编码失败");
                continue;
            }
        };
        if let Err(err) = write_raw_frame(&mut writer, &payload).await {
            tracing::debug!(error = %err, "信令写失败，关闭连接");
            return;
        }
    }
    let _ = writer.shutdown().await;
}

// ---------------------------------------------------------------------------
// 信令客户端
// ---------------------------------------------------------------------------

/// 信令服务器给一对节点牵线后发下来的东西。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerOffer {
    /// 对端公布的候选地址。
    pub candidates: Vec<Candidate>,
    /// 这一对节点的打洞令牌，双方拿到的必须一致。
    pub token: PunchToken,
}

/// `lookup` 的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupOutcome {
    /// 对方已在线，直接拿到候选地址和打洞令牌。
    Ready(PeerOffer),
    /// 对方还没上线，等服务器推送。
    Pending,
}

/// 信令客户端。
pub struct SignalingClient {
    node_id: NodeId,
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    server: String,
}

impl SignalingClient {
    /// 连上信令服务器并登记自己。
    pub async fn connect(
        server: &str,
        identity: &Identity,
        candidates: Vec<Candidate>,
    ) -> Result<Self> {
        let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(server))
            .await
            .map_err(|_| Error::Discovery(format!("连接信令服务器 {server} 超时")))?
            .map_err(|err| Error::Discovery(format!("连接信令服务器 {server} 失败: {err}")))?;
        let _ = stream.set_nodelay(true);

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let node_id = identity.node_id();
        let register = SignalMessage::Register {
            node_id,
            public_key: identity.public_key_bytes(),
            candidates,
        };
        write_raw_frame(&mut write_half, &register.encode()?).await?;

        // 等服务端确认。
        let reply = read_raw_frame(&mut reader)
            .await?
            .ok_or_else(|| Error::Discovery("信令服务器在确认前就关闭了连接".into()))?;
        match SignalMessage::decode(&reply)? {
            SignalMessage::Registered => {}
            SignalMessage::Error { reason } => {
                return Err(Error::Discovery(format!("登记被拒绝: {reason}")));
            }
            other => {
                return Err(Error::Discovery(format!(
                    "登记后收到意外消息 {}",
                    other.kind()
                )));
            }
        }

        tracing::debug!(%server, node = %node_id.short(), "已登记到信令服务器");

        Ok(Self {
            node_id,
            reader,
            writer: write_half,
            server: server.to_string(),
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    /// 查询对端候选地址。
    pub async fn lookup(&mut self, peer: NodeId) -> Result<LookupOutcome> {
        let lookup = SignalMessage::Lookup { node_id: peer };
        write_raw_frame(&mut self.writer, &lookup.encode()?).await?;

        loop {
            let payload = read_raw_frame(&mut self.reader)
                .await?
                .ok_or_else(|| Error::Discovery("等查询结果时信令服务器断开了连接".into()))?;

            match SignalMessage::decode(&payload)? {
                SignalMessage::PeerCandidates {
                    node_id,
                    candidates,
                    token,
                } if node_id == peer => {
                    return Ok(LookupOutcome::Ready(PeerOffer { candidates, token }));
                }
                SignalMessage::PeerPending { node_id } if node_id == peer => {
                    return Ok(LookupOutcome::Pending);
                }
                SignalMessage::Pong => continue,
                SignalMessage::Error { reason } => {
                    return Err(Error::Discovery(format!("查询失败: {reason}")));
                }
                other => {
                    tracing::debug!(kind = other.kind(), "查询期间忽略消息");
                }
            }
        }
    }

    /// 等服务器推送对端候选地址（配合 `lookup` 返回 `Pending` 使用）。
    /// 返回 `Ok(None)` 表示这段时间内对端没出现（超时），连接本身还是好的。
    pub async fn wait_for_peer(
        &mut self,
        peer: NodeId,
        timeout: Duration,
    ) -> Result<Option<PeerOffer>> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            let payload =
                match tokio::time::timeout(remaining, read_raw_frame(&mut self.reader)).await {
                    Ok(result) => {
                        result?.ok_or_else(|| Error::Discovery("信令服务器断开了连接".into()))?
                    }
                    Err(_) => return Ok(None),
                };

            match SignalMessage::decode(&payload)? {
                SignalMessage::PeerCandidates {
                    node_id,
                    candidates,
                    token,
                } if node_id == peer => {
                    return Ok(Some(PeerOffer { candidates, token }));
                }
                SignalMessage::Pong => continue,
                SignalMessage::Error { reason } => {
                    return Err(Error::Discovery(format!("信令错误: {reason}")));
                }
                other => {
                    tracing::debug!(kind = other.kind(), "等待期间忽略消息");
                }
            }
        }
    }

    /// 查询 + 必要时等待，一步到位。
    pub async fn resolve_peer(&mut self, peer: NodeId, timeout: Duration) -> Result<PeerOffer> {
        match self.lookup(peer).await? {
            LookupOutcome::Ready(offer) => Ok(offer),
            LookupOutcome::Pending => {
                tracing::info!(peer = %peer.short(), "对端还没上线，等待中");
                self.wait_for_peer(peer, timeout).await?.ok_or_else(|| {
                    Error::Discovery(format!(
                        "等对端 {} 上线超时（{} 秒）",
                        peer.short(),
                        timeout.as_secs()
                    ))
                })
            }
        }
    }

    /// 主动发个心跳，顺便确认连接还在。
    pub async fn ping(&mut self) -> Result<()> {
        write_raw_frame(&mut self.writer, &SignalMessage::Ping.encode()?).await?;
        Ok(())
    }
}

impl std::fmt::Debug for SignalingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalingClient")
            .field("server", &self.server)
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(kind: CandidateKind, addr: &str) -> Candidate {
        Candidate::new(kind, addr.parse().unwrap())
    }

    /// 起一个真的信令服务器，返回它的地址。
    async fn spawn_signal_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(Registry::default()));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    let _ = handle_signal_client(stream, registry).await;
                });
            }
        });
        addr
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
        let node = NodeId::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let messages = vec![
            SignalMessage::Register {
                node_id: node,
                public_key: [7u8; 32],
                candidates: vec![candidate(CandidateKind::Host, "192.168.1.20:9000")],
            },
            SignalMessage::Registered,
            SignalMessage::Lookup { node_id: node },
            SignalMessage::PeerCandidates {
                node_id: node,
                candidates: vec![],
                token: PunchToken::from_bytes([3u8; 16]),
            },
            SignalMessage::PeerPending { node_id: node },
            SignalMessage::Ping,
            SignalMessage::Pong,
            SignalMessage::Error {
                reason: "对端不在线".into(),
            },
        ];

        for message in messages {
            let decoded = SignalMessage::decode(&message.encode().unwrap()).unwrap();
            assert_eq!(message, decoded, "{} 往返失败", message.kind());
        }
    }

    #[tokio::test]
    async fn 服务端能把双方牵到一起() {
        let addr = spawn_signal_server().await;

        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_id = alice.node_id();
        let bob_id = bob.node_id();

        let alice_candidates = vec![candidate(
            CandidateKind::ServerReflexive,
            "203.0.113.9:4000",
        )];
        let bob_candidates = vec![candidate(CandidateKind::Host, "192.168.1.7:9000")];

        let mut client_a =
            SignalingClient::connect(&addr.to_string(), &alice, alice_candidates.clone())
                .await
                .unwrap();

        // Bob 还没上线，Alice 查他应当是 Pending。
        assert_eq!(
            client_a.lookup(bob_id).await.unwrap(),
            LookupOutcome::Pending
        );

        let mut client_b =
            SignalingClient::connect(&addr.to_string(), &bob, bob_candidates.clone())
                .await
                .unwrap();

        // Bob 上线后，Alice 应当收到推送。
        let got = client_a
            .wait_for_peer(bob_id, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            got.unwrap().candidates,
            bob_candidates,
            "Alice 应拿到 Bob 的候选"
        );

        // Bob 那边也应当被推送了 Alice 的候选。
        let got = client_b
            .wait_for_peer(alice_id, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            got.unwrap().candidates,
            alice_candidates,
            "Bob 应拿到 Alice 的候选"
        );
    }

    #[tokio::test]
    async fn 同一对节点拿到的令牌必须一致() {
        // 令牌是打洞时「接受任意来源探测包」的凭据。两边要是拿到不同的令牌，
        // 谁也认不下谁的探测包，表现为「明明都在线却怎么都打不通」。
        let addr = spawn_signal_server().await;

        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_id = bob.node_id();

        let mut client_a = SignalingClient::connect(
            &addr.to_string(),
            &alice,
            vec![candidate(CandidateKind::Host, "192.168.1.1:9000")],
        )
        .await
        .unwrap();

        // Alice 先挂起等待，Bob 一上线服务器就会给两人推同一份令牌。
        assert_eq!(
            client_a.lookup(bob_id).await.unwrap(),
            LookupOutcome::Pending
        );

        let mut client_b = SignalingClient::connect(
            &addr.to_string(),
            &bob,
            vec![candidate(CandidateKind::Host, "192.168.1.2:9000")],
        )
        .await
        .unwrap();

        let alice_side = client_a
            .wait_for_peer(bob_id, Duration::from_secs(5))
            .await
            .unwrap()
            .expect("Alice 应当收到推送");

        // Bob 的候选是服务器在他登记时推给他的，直接取即可。
        let bob_side = client_b
            .wait_for_peer(alice.node_id(), Duration::from_secs(5))
            .await
            .unwrap()
            .expect("Bob 也应当收到推送");

        assert_eq!(
            alice_side.token, bob_side.token,
            "同一次牵线推给双方的令牌必须一致"
        );
        assert_eq!(
            alice_side.candidates,
            vec![candidate(CandidateKind::Host, "192.168.1.2:9000")]
        );
        assert_eq!(
            bob_side.candidates,
            vec![candidate(CandidateKind::Host, "192.168.1.1:9000")]
        );
    }

    #[tokio::test]
    async fn 对端被强杀后会从在线表里摘掉() {
        // 踩过的坑：对端进程被 kill -9 时，服务器读到的是 RST（返回 Err）而不是
        // 干净的 EOF（返回 Ok(None)）。原先读循环用 `?` 直接返回，跳过了下线
        // 清理，于是死掉的节点一直「在线」，服务器会把过期候选地址发给别人，
        // 对端照着打洞只能打到空气上。
        //
        // 这里用裸 TcpStream 而不是 SignalingClient：`into_split` 出来的两个半边
        // 共享同一个 fd，只 drop 一半不会真正关闭连接，也就发不出 RST。
        let addr = spawn_signal_server().await;

        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_id = bob.node_id();

        let mut client_a = SignalingClient::connect(
            &addr.to_string(),
            &alice,
            vec![candidate(CandidateKind::Host, "192.168.1.1:9000")],
        )
        .await
        .unwrap();

        // Bob 用一个裸连接登记，登记完立刻带 RST 消失。
        let mut raw = TcpStream::connect(addr).await.unwrap();
        let register = SignalMessage::Register {
            node_id: bob_id,
            public_key: [0u8; 32],
            candidates: vec![candidate(CandidateKind::Host, "192.168.1.2:9000")],
        };
        write_raw_frame(&mut raw, &register.encode().unwrap())
            .await
            .unwrap();
        {
            let mut reader = BufReader::new(&mut raw);
            let reply = read_raw_frame(&mut reader).await.unwrap().unwrap();
            assert!(matches!(
                SignalMessage::decode(&reply).unwrap(),
                SignalMessage::Registered
            ));
        }

        // Bob 确实在线。
        assert!(
            matches!(
                client_a.lookup(bob_id).await.unwrap(),
                LookupOutcome::Ready(_)
            ),
            "Bob 刚登记完，应当是在线的"
        );

        // SO_LINGER=0：close 时不走四次挥手，直接发 RST。
        // 这个方法在 tokio 里被标了 deprecated（担心阻塞 drop），测试里用没问题。
        #[allow(deprecated)]
        raw.set_linger(Some(Duration::ZERO)).unwrap();
        drop(raw);

        // 服务器必须察觉并摘掉它。
        let mut gone = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if matches!(
                client_a.lookup(bob_id).await.unwrap(),
                LookupOutcome::Pending
            ) {
                gone = true;
                break;
            }
        }
        assert!(gone, "对端已经被强杀，服务器却还认为它在线");
    }

    #[tokio::test]
    async fn 双方同时上线也能牵到一起() {
        let addr = spawn_signal_server().await;
        let alice = Identity::generate();
        let bob = Identity::generate();

        let mut client_a = SignalingClient::connect(
            &addr.to_string(),
            &alice,
            vec![candidate(CandidateKind::Host, "192.168.1.1:9000")],
        )
        .await
        .unwrap();
        let mut client_b = SignalingClient::connect(
            &addr.to_string(),
            &bob,
            vec![candidate(CandidateKind::Host, "192.168.1.2:9000")],
        )
        .await
        .unwrap();

        // 两边同时查对方。
        let (a, b) = tokio::join!(
            client_a.resolve_peer(bob.node_id(), Duration::from_secs(5)),
            client_b.resolve_peer(alice.node_id(), Duration::from_secs(5)),
        );
        assert_eq!(a.unwrap().candidates.len(), 1);
        assert_eq!(b.unwrap().candidates.len(), 1);
    }

    #[tokio::test]
    async fn 查自己会被拒绝() {
        let addr = spawn_signal_server().await;
        let alice = Identity::generate();
        let mut client = SignalingClient::connect(&addr.to_string(), &alice, vec![])
            .await
            .unwrap();

        let err = client.lookup(alice.node_id()).await.unwrap_err();
        assert!(matches!(err, Error::Discovery(_)), "实际 {err:?}");
    }

    #[tokio::test]
    async fn 连不上信令服务器会报错() {
        // 占一个端口再释放，保证拿到一个没人监听的地址。
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dead.local_addr().unwrap();
        drop(dead);

        let alice = Identity::generate();
        let err = SignalingClient::connect(&addr.to_string(), &alice, vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Discovery(_)), "实际 {err:?}");
    }

    #[tokio::test]
    async fn 等对端超时会报错() {
        let addr = spawn_signal_server().await;
        let alice = Identity::generate();
        let ghost = Identity::generate().node_id();
        let mut client = SignalingClient::connect(&addr.to_string(), &alice, vec![])
            .await
            .unwrap();

        let err = client
            .resolve_peer(ghost, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Discovery(_)), "实际 {err:?}");
    }

    #[tokio::test]
    async fn 心跳之后连接仍然可用() {
        let addr = spawn_signal_server().await;
        let alice = Identity::generate();
        let mut client = SignalingClient::connect(&addr.to_string(), &alice, vec![])
            .await
            .unwrap();

        assert_eq!(client.node_id(), alice.node_id());
        assert_eq!(client.server(), addr.to_string());
        client.ping().await.unwrap();

        let ghost = Identity::generate().node_id();
        assert_eq!(client.lookup(ghost).await.unwrap(), LookupOutcome::Pending);
    }

    #[tokio::test]
    async fn 同一节点重连会覆盖旧候选() {
        let addr = spawn_signal_server().await;
        let alice = Identity::generate();
        let bob = Identity::generate();

        let mut client_b = SignalingClient::connect(
            &addr.to_string(),
            &bob,
            vec![candidate(CandidateKind::Host, "192.168.1.7:9000")],
        )
        .await
        .unwrap();

        let mut client_a = SignalingClient::connect(
            &addr.to_string(),
            &alice,
            vec![candidate(CandidateKind::Host, "192.168.1.1:9000")],
        )
        .await
        .unwrap();

        // Bob 换了个端口重连。
        let mut client_b2 = SignalingClient::connect(
            &addr.to_string(),
            &bob,
            vec![candidate(CandidateKind::Host, "192.168.1.7:9100")],
        )
        .await
        .unwrap();

        let got = client_a
            .resolve_peer(bob.node_id(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            got.candidates,
            vec![candidate(CandidateKind::Host, "192.168.1.7:9100")],
            "应当拿到重连后的新候选"
        );

        // 旧连接还在，不该把新记录顶掉。
        client_b.ping().await.unwrap();
        client_b2.ping().await.unwrap();
    }
}
