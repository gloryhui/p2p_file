//! 公网信令：让两个素不相识的节点交换各自的候选地址。
//!
//! 信令服务器只做「牵线」，**不碰业务数据**。职责是：
//!
//! 1. 节点上线时登记自己的节点 ID 和候选地址；
//! 2. 一方查询另一方时，把双方候选互相推送；
//! 3. 之后双方自行打洞，数据走直连，服务器不参与。
//!
//! 走 TCP + 长度前缀 postcard，这样只要放通一个 TCP 端口就能用。
//!
//! # 信令本身是明文的，所以注册必须自证身份
//!
//! 信令跑在明文 TCP 上，任何人都能连上来。因此登记不能只看「你声称自己是谁」：
//!
//! ```text
//! 客户端                                  服务器
//!   RegisterHello { ver, id, pubkey }  ───►
//!                                       ◄─── RegisterChallenge { ver, nonce }
//!   Register { id, pubkey, cands, sig } ──►
//!                                       ◄─── Registered | Error
//! ```
//!
//! `sig` 覆盖 `domain + nonce + node_id + public_key + hash(candidates)`：
//!
//! - `node_id == hash(public_key)` 只证明「公钥自洽」，不证明持有私钥；
//!   签名才证明这一点。
//! - `nonce` 由服务器每条连接新生成、一次性使用，旧连接的注册消息原样重放会失败。
//! - 候选地址进签名：否则明文信令上的中间人可以篡改候选，把对端引到别处。
//!
//! 身份最终仍由 QUIC 之上的应用层握手确认；信令认证是为了让服务器自己的
//! 在线表不被随意污染（冒名、幽灵节点、内存耗尽）。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};

use crate::error::{Error, Result};
use crate::identity::{
    Identity, NodeId, public_key_from_bytes, signature_from_bytes, verify_signature,
};
use crate::nat::punch::PunchToken;
use crate::protocol::frame::{read_raw_frame_limited, write_raw_frame_limited};

/// 信令服务器默认端口。
pub const DEFAULT_SIGNAL_PORT: u16 = 7000;

/// 信令协议版本。
///
/// - v1：`Register { node_id, public_key, candidates }`，没有任何认证。
/// - v2：challenge-response 注册认证（见本模块文档），单连接单身份。
///
/// 两者不兼容：新版服务器收到 v1 的 `Register` 会在握手阶段明确拒绝，
/// 新版客户端也会拒绝 v1 服务器的应答，不会静默降级到无认证路径。
pub const SIGNAL_PROTOCOL_VERSION: u32 = 2;

/// 注册 challenge 长度（256 bit）。
pub const CHALLENGE_LEN: usize = 32;

/// 注册签名的域标签，避免签名被挪用到别处。
pub const REGISTER_DOMAIN: &[u8] = b"p2p_file/signal-register/v2";

/// 信令单帧上限。
///
/// 信令全是小控制消息（候选地址最多 [`MAX_CANDIDATES`] 个），不该复用业务
/// 分片那 16 MiB 的通用上限，否则公网端口上一个长度头就能逼服务端提前分配大缓冲。
pub const MAX_SIGNAL_FRAME_LEN: u32 = 64 * 1024;

/// 单个节点允许公布的候选地址数量上限。
pub const MAX_CANDIDATES: usize = 32;
/// 在线节点总数上限。
pub const MAX_REGISTERED_PEERS: usize = 4096;
/// waiter 条目（target → requester）总数上限。
pub const MAX_WAITER_ENTRIES: usize = 16 * 1024;
/// 单条连接挂起（等对方上线）的查询数量上限。
pub const MAX_PENDING_LOOKUPS: usize = 64;
/// 每条连接待写队列容量。
pub const OUTBOX_CAPACITY: usize = 64;
/// 关闭连接时，留给 writer 冲刷最后几帧的时间。
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// 信令服务器资源与超时参数。
///
/// 默认值面向公网部署；测试用更小的值来快速验证边界行为。
#[derive(Clone, Debug)]
pub struct SignalServerConfig {
    /// 单节点候选地址上限。
    pub max_candidates: usize,
    /// 在线节点总数上限。
    pub max_registered_peers: usize,
    /// waiter 条目总数上限。
    pub max_waiter_entries: usize,
    /// 单连接挂起查询上限。
    pub max_pending_lookups: usize,
    /// 每条连接待写队列容量。
    pub outbox_capacity: usize,
    /// 连接建立后，等第一帧的时间。
    pub first_frame_timeout: Duration,
    /// 发出 challenge 之后，等 `Register` 的时间。
    pub register_timeout: Duration,
    /// 登记成功后，两次收到帧之间的最大空闲时间。
    ///
    /// 这是一条兜底：真正的业务数据走 P2P 直连，长时间不碰信令是正常的，
    /// 所以给得比较宽松，只用来回收半死连接。
    pub idle_timeout: Duration,
    /// 单帧写入超时。
    ///
    /// 客户端只发不读时，TCP 发送缓冲会写满、writer 会卡住；超过这个时间
    /// 就认为它是异常客户端，直接断开，避免积压。
    pub write_timeout: Duration,
    /// challenge 的有效期。
    pub challenge_ttl: Duration,
}

impl Default for SignalServerConfig {
    fn default() -> Self {
        Self {
            max_candidates: MAX_CANDIDATES,
            max_registered_peers: MAX_REGISTERED_PEERS,
            max_waiter_entries: MAX_WAITER_ENTRIES,
            max_pending_lookups: MAX_PENDING_LOOKUPS,
            outbox_capacity: OUTBOX_CAPACITY,
            first_frame_timeout: Duration::from_secs(10),
            register_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(180),
            write_timeout: Duration::from_secs(30),
            challenge_ttl: Duration::from_secs(10),
        }
    }
}

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
///
/// 变体顺序就是 postcard 的线格式（enum 用变体序号编码），**不要重排**：
/// 前 8 个变体与 v1 保持同样的序号，这样 v1 客户端收到 v2 服务器的
/// `RegisterChallenge`（序号 9，超出 v1 的范围）会解析失败并明确报错，
/// 而不是把挑战错认成 `Registered`、假装登记成功。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalMessage {
    /// 客户端 → 服务器：带签名的正式登记。
    ///
    /// 与 v1 的 `Register { node_id, public_key, candidates }` 同序号但多一个
    /// `signature` 字段：v1 客户端发来的帧会因为字段缺失而解析失败，被明确拒绝。
    Register {
        node_id: NodeId,
        public_key: [u8; 32],
        candidates: Vec<Candidate>,
        /// 对 [`register_payload`] 的 Ed25519 签名。
        signature: Vec<u8>,
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
    /// 客户端 → 服务器：v2 注册第一步，声明身份。
    RegisterHello {
        protocol_version: u32,
        node_id: NodeId,
        public_key: [u8; 32],
    },
    /// 服务器 → 客户端：v2 本次连接的注册挑战。
    RegisterChallenge {
        protocol_version: u32,
        challenge: [u8; CHALLENGE_LEN],
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
            Self::RegisterHello { .. } => "RegisterHello",
            Self::RegisterChallenge { .. } => "RegisterChallenge",
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

/// 注册签名载荷。
///
/// 双方（客户端签名、服务器校验）必须算出完全相同的字节串：
///
/// ```text
/// REGISTER_DOMAIN + challenge + node_id + public_key + blake3(postcard(candidates))
/// ```
///
/// `challenge` 绑定本次连接的新鲜性；`candidates` 进签名是为了让明文信令上的
/// 中间人无法篡改对端地址。postcard 对这些类型是确定性编码，两侧重新编码结果
/// 一致，所以服务器可以只对收到的候选列表重新求哈希。
pub fn register_payload(
    challenge: &[u8; CHALLENGE_LEN],
    node_id: NodeId,
    public_key: &[u8; 32],
    candidates: &[Candidate],
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(REGISTER_DOMAIN.len() + CHALLENGE_LEN + 16 + 32 + 32);
    payload.extend_from_slice(REGISTER_DOMAIN);
    payload.extend_from_slice(challenge);
    payload.extend_from_slice(node_id.as_bytes());
    payload.extend_from_slice(public_key);
    let encoded = postcard::to_allocvec(candidates)?;
    payload.extend_from_slice(blake3::hash(&encoded).as_bytes());
    Ok(payload)
}

// ---------------------------------------------------------------------------
// 信令服务器
// ---------------------------------------------------------------------------

/// 一次成功登记的所有权凭证。
#[derive(Clone, Copy, Debug)]
struct ActiveRegistration {
    node_id: NodeId,
    connection_id: u64,
}

/// 正在等待 `Register` 的注册。
struct PendingRegistration {
    node_id: NodeId,
    public_key: [u8; 32],
    challenge: [u8; CHALLENGE_LEN],
    issued_at: tokio::time::Instant,
}

/// 一个已登记的对端。
struct PeerRecord {
    /// 登记这条记录的连接。清理时只有拥有者能删，避免旧连接顶掉新连接。
    connection_id: u64,
    candidates: Vec<Candidate>,
    /// 往这条连接推消息用的发送端（有界）。
    outbox: mpsc::Sender<SignalMessage>,
    /// 需要主动断开这条连接时（队列积压等）用它通知。
    close: watch::Sender<bool>,
}

/// 内存里的在线表。进程重启即清空——客户端会重新登记。
#[derive(Default)]
struct Registry {
    peers: HashMap<NodeId, PeerRecord>,
    /// 谁在等谁上线：`waiters[target] = {requester, ...}`。
    waiters: HashMap<NodeId, HashSet<NodeId>>,
}

impl Registry {
    /// waiter 条目总数（所有集合的大小之和）。
    fn waiter_entries(&self) -> usize {
        self.waiters.values().map(HashSet::len).sum()
    }

    /// 双方都在线就互相推送候选，只推一次。
    fn try_pair(&self, a: NodeId, b: NodeId) {
        let (Some(record_a), Some(record_b)) = (self.peers.get(&a), self.peers.get(&b)) else {
            return;
        };
        let candidates_a = record_a.candidates.clone();
        let candidates_b = record_b.candidates.clone();
        let outbox_a = record_a.outbox.clone();
        let outbox_b = record_b.outbox.clone();
        let close_a = record_a.close.clone();
        let close_b = record_b.close.clone();

        // 两边都必须能立刻排队，否则这次牵线不完整：令牌必须成对下发，只给一边
        // 等于制造「双方拿到不同令牌」的机会。排不下说明那条连接已经卡死，
        // 直接请它断开，而不是无限积压。
        let permit_a = match outbox_a.try_reserve() {
            Ok(permit) => permit,
            Err(_) => {
                let _ = close_a.send(true);
                return;
            }
        };
        let permit_b = match outbox_b.try_reserve() {
            Ok(permit) => permit,
            Err(_) => {
                let _ = close_b.send(true);
                return;
            }
        };

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
        permit_a.send(SignalMessage::PeerCandidates {
            node_id: b,
            candidates: candidates_b,
            token,
        });
        permit_b.send(SignalMessage::PeerCandidates {
            node_id: a,
            candidates: candidates_a,
            token,
        });
    }

    /// 连接断开：只删除仍然属于自己的记录，并清掉自己在所有 waiter 里的痕迹。
    fn unregister(&mut self, node_id: NodeId, connection_id: u64) {
        let owned = self
            .peers
            .get(&node_id)
            .is_some_and(|record| record.connection_id == connection_id);
        if owned {
            // 记录已经被更新的连接取代时，绝不能在这里删掉。
            self.peers.remove(&node_id);
        }

        for waiters in self.waiters.values_mut() {
            waiters.remove(&node_id);
        }
        // 空集合会一直占着 key，是内存 DoS 的入口，及时收掉。
        self.waiters.retain(|_, waiters| !waiters.is_empty());
    }
}

/// 跑信令服务器，永不返回（除非出错）。
pub async fn run_signal_server(listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    run_signal_server_on_with(listener, SignalServerConfig::default()).await
}

/// 在**已经绑好**的监听器上跑信令服务器（默认配置）。
///
/// 单独拆出来是为了测试能用 `127.0.0.1:0` 绑定再拿到真实端口，避免抢端口。
pub async fn run_signal_server_on(listener: TcpListener) -> Result<()> {
    run_signal_server_on_with(listener, SignalServerConfig::default()).await
}

/// 在已经绑好的监听器上跑信令服务器，使用给定配置。
pub async fn run_signal_server_on_with(
    listener: TcpListener,
    config: SignalServerConfig,
) -> Result<()> {
    let local = listener.local_addr()?;
    tracing::info!(%local, "信令服务器已启动，等待节点接入（只牵线，不过数据）");

    let registry = Arc::new(Mutex::new(Registry::default()));
    let config = Arc::new(config);

    // 连接所有权凭证：单调递增，保证「旧连接断开」不会误删「新连接」的记录。
    let mut next_connection_id: u64 = 1;

    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "接受连接失败，继续监听");
                continue;
            }
        };
        tracing::debug!(%remote, "信令连接建立");

        let connection_id = next_connection_id;
        next_connection_id = next_connection_id.wrapping_add(1);
        if next_connection_id == 0 {
            next_connection_id = 1;
        }

        let registry = Arc::clone(&registry);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(err) = handle_signal_client(stream, registry, connection_id, config).await {
                tracing::debug!(%remote, error = %err, "信令连接结束");
            }
        });
    }
}

/// 把一个错误回给客户端（尽力而为，队列满就丢）。
fn reject(outbox: &mpsc::Sender<SignalMessage>, reason: impl Into<String>) {
    let _ = outbox.try_send(SignalMessage::Error {
        reason: reason.into(),
    });
}

/// 入队一条消息；队列满说明客户端已经卡死，调用方应当断开。
fn send_or_close(outbox: &mpsc::Sender<SignalMessage>, message: SignalMessage) -> bool {
    outbox.try_send(message).is_ok()
}

async fn handle_signal_client(
    stream: TcpStream,
    registry: Arc<Mutex<Registry>>,
    connection_id: u64,
    config: Arc<SignalServerConfig>,
) -> Result<()> {
    // 信令消息都很小，别让 Nagle 拖慢牵线。
    let _ = stream.set_nodelay(true);
    let (read_half, write_half) = stream.into_split();

    // 有界队列：慢客户端最多积压这么多条，写不出去就断开，不会无限占内存。
    let (outbox, inbox) = mpsc::channel::<SignalMessage>(config.outbox_capacity);
    // 服务器 → 连接内部：请求主动断开（队列积压 / 被更好的记录取代等）。
    // 这里保留一个 sender，保证只要本任务还活着，`changed()` 就只会在显式
    // `send(true)` 时才就绪，不会因为记录被移除而误触发。
    let (close_tx, mut close_rx) = watch::channel(false);
    let mut writer = tokio::spawn(writer_loop(write_half, inbox, Arc::clone(&config)));

    let mut reader = BufReader::new(read_half);
    let mut pending: Option<PendingRegistration> = None;
    let mut active: Option<ActiveRegistration> = None;
    // 本连接挂起等待的目标，用于去重和上限判断。
    let mut pending_lookups: HashSet<NodeId> = HashSet::new();

    let disconnect_reason: &str = loop {
        // 未登记时给一个较短的窗口，避免匿名连接长期占着资源。
        let read_timeout = if active.is_some() {
            config.idle_timeout
        } else if pending.is_some() {
            config.register_timeout
        } else {
            config.first_frame_timeout
        };

        let payload = tokio::select! {
            biased;
            // 服务器主动要求断开（例如这条连接的待写队列已经满了）。
            _ = close_rx.changed() => break "服务器主动断开",
            result = tokio::time::timeout(
                read_timeout,
                read_raw_frame_limited(&mut reader, MAX_SIGNAL_FRAME_LEN),
            ) => {
                match result {
                    Err(_) => break "读取超时",
                    Ok(Ok(Some(payload))) => payload,
                    Ok(Ok(None)) => break "对端关闭连接",
                    Ok(Err(err)) => {
                        tracing::debug!(error = %err, "信令读取出错，按断开处理");
                        break "读取出错";
                    }
                }
            }
        };

        // 注意：这里**不能**用 `?` 直接返回。对端被强杀时读到的是 RST（错误）
        // 而不是干净的 EOF，一旦提前返回就会跳过下面的下线清理，让一个已经
        // 死掉的节点永远留在在线表里。
        let message = match SignalMessage::decode(&payload) {
            Ok(message) => message,
            Err(err) => {
                tracing::warn!(error = %err, "信令消息解析失败");
                reject(&outbox, format!("消息解析失败: {err}"));
                break "消息解析失败";
            }
        };

        match message {
            SignalMessage::RegisterHello {
                protocol_version,
                node_id,
                public_key,
            } => {
                // 一条连接只能注册一个身份：登记过、或已经在注册流程里，
                // 再来 RegisterHello 一律拒绝并断开，杜绝「一条连接留下多个
                // 幽灵节点」。
                if active.is_some() || pending.is_some() {
                    reject(&outbox, "本连接已经开始或完成注册，不能重复 RegisterHello");
                    break "重复 RegisterHello";
                }
                if protocol_version != SIGNAL_PROTOCOL_VERSION {
                    reject(
                        &outbox,
                        format!(
                            "信令协议版本不兼容：本机 {SIGNAL_PROTOCOL_VERSION}，对端 {protocol_version}"
                        ),
                    );
                    break "信令协议版本不兼容";
                }
                let key = match public_key_from_bytes(&public_key) {
                    Ok(key) => key,
                    Err(err) => {
                        reject(&outbox, format!("公钥非法: {err}"));
                        break "公钥非法";
                    }
                };
                // 只证明「公钥自洽」，真正的私钥持有证明在 Register 的签名里。
                if NodeId::from_public_key(&key) != node_id {
                    reject(&outbox, "节点 ID 与公钥不符");
                    break "节点 ID 与公钥不符";
                }

                let challenge: [u8; CHALLENGE_LEN] = rand::random();
                let issued_at = tokio::time::Instant::now();
                if !send_or_close(
                    &outbox,
                    SignalMessage::RegisterChallenge {
                        protocol_version: SIGNAL_PROTOCOL_VERSION,
                        challenge,
                    },
                ) {
                    break "待写队列已满";
                }
                pending = Some(PendingRegistration {
                    node_id,
                    public_key,
                    challenge,
                    issued_at,
                });
            }

            SignalMessage::Register {
                node_id,
                public_key,
                candidates,
                signature,
            } => {
                let Some(pending_registration) = pending.take() else {
                    reject(&outbox, "没有先发 RegisterHello 就发 Register");
                    break "未按握手顺序注册";
                };
                if active.is_some() {
                    reject(&outbox, "本连接已经登记过，不能再次注册");
                    break "重复注册";
                }
                // 最终 Register 必须和 RegisterHello 声明的身份完全一致，
                // 不允许在挑战中途换人。
                if pending_registration.node_id != node_id
                    || pending_registration.public_key != public_key
                {
                    reject(&outbox, "Register 与 RegisterHello 的身份不一致");
                    break "注册身份前后不一致";
                }
                if pending_registration.issued_at.elapsed() > config.challenge_ttl {
                    reject(&outbox, "challenge 已过期，请重新连接");
                    break "challenge 过期";
                }
                if candidates.len() > config.max_candidates {
                    reject(
                        &outbox,
                        format!(
                            "候选地址过多：{}，上限 {}",
                            candidates.len(),
                            config.max_candidates
                        ),
                    );
                    break "候选地址超限";
                }

                let key = match public_key_from_bytes(&public_key) {
                    Ok(key) => key,
                    Err(err) => {
                        reject(&outbox, format!("公钥非法: {err}"));
                        break "公钥非法";
                    }
                };
                if NodeId::from_public_key(&key) != node_id {
                    reject(&outbox, "节点 ID 与公钥不符");
                    break "节点 ID 与公钥不符";
                }
                let payload = match register_payload(
                    &pending_registration.challenge,
                    node_id,
                    &public_key,
                    &candidates,
                ) {
                    Ok(payload) => payload,
                    Err(err) => {
                        reject(&outbox, format!("无法构造注册载荷: {err}"));
                        break "注册载荷构造失败";
                    }
                };
                let signature = match signature_from_bytes(&signature) {
                    Ok(signature) => signature,
                    Err(err) => {
                        reject(&outbox, format!("签名非法: {err}"));
                        break "签名非法";
                    }
                };
                if let Err(err) = verify_signature(&key, &payload, &signature) {
                    reject(&outbox, format!("注册签名校验失败: {err}"));
                    break "注册签名校验失败";
                }

                // 认证通过，才允许写进在线表。
                let waiters = {
                    let mut reg = registry.lock().await;
                    let is_new = !reg.peers.contains_key(&node_id);
                    if is_new && reg.peers.len() >= config.max_registered_peers {
                        drop(reg);
                        reject(&outbox, "服务器在线表已满");
                        break "在线表已满";
                    }
                    reg.peers.insert(
                        node_id,
                        PeerRecord {
                            connection_id,
                            candidates: candidates.clone(),
                            outbox: outbox.clone(),
                            close: close_tx.clone(),
                        },
                    );
                    reg.waiters.remove(&node_id).unwrap_or_default()
                };

                active = Some(ActiveRegistration {
                    node_id,
                    connection_id,
                });

                tracing::info!(
                    node = %node_id.short(),
                    candidates = candidates.len(),
                    waiters = waiters.len(),
                    "节点登记（已通过私钥挑战认证）"
                );

                if !send_or_close(&outbox, SignalMessage::Registered) {
                    break "待写队列已满";
                }

                // 有人在等它，现在可以牵线了。
                for waiter in waiters {
                    registry.lock().await.try_pair(waiter, node_id);
                }
            }

            SignalMessage::Lookup { node_id: target } => {
                let Some(registration) = active.as_ref() else {
                    reject(&outbox, "还没登记就想查询");
                    break "未登记就查询";
                };
                let me = registration.node_id;
                let my_connection = registration.connection_id;

                if me == target {
                    if !send_or_close(
                        &outbox,
                        SignalMessage::Error {
                            reason: "别查自己".into(),
                        },
                    ) {
                        break "待写队列已满";
                    }
                    continue;
                }

                let mut reg = registry.lock().await;
                // 所有权：本连接必须仍然是这个节点的当前记录。否则说明该节点
                // 已经在别处重新登记，这条连接不能再代表它。
                let still_owner = reg
                    .peers
                    .get(&me)
                    .is_some_and(|record| record.connection_id == my_connection);
                if !still_owner {
                    drop(reg);
                    reject(&outbox, "本连接已被该节点的新连接取代");
                    break "连接所有权已被取代";
                }

                if reg.peers.contains_key(&target) {
                    // 目标在线：直接牵线，顺便清掉可能残留的挂起记录。
                    pending_lookups.remove(&target);
                    reg.try_pair(me, target);
                    continue;
                }

                // 目标不在线：挂起等待，先做去重，再检查上限。
                let already_waiting = reg
                    .waiters
                    .get(&target)
                    .is_some_and(|waiters| waiters.contains(&me));
                if !already_waiting {
                    if pending_lookups.len() >= config.max_pending_lookups {
                        drop(reg);
                        if !send_or_close(
                            &outbox,
                            SignalMessage::Error {
                                reason: format!(
                                    "挂起的查询过多（上限 {}）",
                                    config.max_pending_lookups
                                ),
                            },
                        ) {
                            break "待写队列已满";
                        }
                        continue;
                    }
                    if reg.waiter_entries() >= config.max_waiter_entries {
                        drop(reg);
                        if !send_or_close(
                            &outbox,
                            SignalMessage::Error {
                                reason: "服务器等待队列已满".into(),
                            },
                        ) {
                            break "待写队列已满";
                        }
                        continue;
                    }
                    reg.waiters.entry(target).or_default().insert(me);
                    pending_lookups.insert(target);
                }
                drop(reg);

                tracing::debug!(
                    node = %me.short(),
                    target = %target.short(),
                    "目标还没上线，挂起等待"
                );
                if !send_or_close(&outbox, SignalMessage::PeerPending { node_id: target }) {
                    break "待写队列已满";
                }
            }

            SignalMessage::Ping => {
                // 未登记的连接不允许用心跳续命，否则匿名连接可以一直占着资源。
                if active.is_none() {
                    reject(&outbox, "还没登记就想心跳");
                    break "未登记就心跳";
                }
                if !send_or_close(&outbox, SignalMessage::Pong) {
                    break "待写队列已满";
                }
            }

            other => {
                tracing::debug!(kind = other.kind(), "客户端发来了不该由它发送的消息");
                reject(&outbox, format!("服务器不接受 {} 消息", other.kind()));
                break "非法消息方向";
            }
        }
    };

    // 断开：只摘掉属于自己的记录，避免旧连接删掉新连接。
    if let Some(registration) = active {
        registry
            .lock()
            .await
            .unregister(registration.node_id, registration.connection_id);
        tracing::info!(
            node = %registration.node_id.short(),
            reason = disconnect_reason,
            "节点下线"
        );
    }

    // 先把队列里最后的消息（例如 Error）尽量送出去，再关连接。
    drop(outbox);
    if tokio::time::timeout(SHUTDOWN_GRACE, &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
    Ok(())
}

async fn writer_loop(
    mut writer: OwnedWriteHalf,
    mut inbox: mpsc::Receiver<SignalMessage>,
    config: Arc<SignalServerConfig>,
) {
    while let Some(message) = inbox.recv().await {
        let payload = match message.encode() {
            Ok(payload) => payload,
            Err(err) => {
                tracing::warn!(error = %err, "信令消息编码失败");
                continue;
            }
        };
        match tokio::time::timeout(
            config.write_timeout,
            write_raw_frame_limited(&mut writer, &payload, MAX_SIGNAL_FRAME_LEN),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::debug!(error = %err, "信令写失败，关闭连接");
                return;
            }
            Err(_) => {
                // 客户端只发不读时，TCP 发送缓冲会满，这里就会卡住。
                // 卡住的连接属于异常客户端，直接断开。
                tracing::warn!("信令写超时，关闭异常连接");
                return;
            }
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
    /// 连上信令服务器，通过 challenge-response 认证完成登记。
    pub async fn connect(
        server: &str,
        identity: &Identity,
        candidates: Vec<Candidate>,
    ) -> Result<Self> {
        // 服务端也会拦，但客户端自己收一下，避免明知超限还去发一个大包。
        let mut candidates = candidates;
        if candidates.len() > MAX_CANDIDATES {
            tracing::warn!(
                count = candidates.len(),
                max = MAX_CANDIDATES,
                "候选地址过多，按上限截断后再登记"
            );
            candidates.truncate(MAX_CANDIDATES);
        }

        let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(server))
            .await
            .map_err(|_| Error::Discovery(format!("连接信令服务器 {server} 超时")))?
            .map_err(|err| Error::Discovery(format!("连接信令服务器 {server} 失败: {err}")))?;
        let _ = stream.set_nodelay(true);

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let node_id = identity.node_id();

        // 整个注册交换（Hello → Challenge → Register → Registered）都要在
        // 超时内完成，避免服务器不回包时客户端无限等待。
        tokio::time::timeout(
            Duration::from_secs(10),
            register_session(&mut reader, &mut write_half, identity, candidates),
        )
        .await
        .map_err(|_| Error::Discovery(format!("连接信令服务器 {server} 注册超时")))??;

        tracing::debug!(%server, node = %node_id.short(), "已登记到信令服务器（已通过私钥挑战认证）");

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
        write_raw_frame_limited(&mut self.writer, &lookup.encode()?, MAX_SIGNAL_FRAME_LEN).await?;

        loop {
            let payload = read_raw_frame_limited(&mut self.reader, MAX_SIGNAL_FRAME_LEN)
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

            let payload = match tokio::time::timeout(
                remaining,
                read_raw_frame_limited(&mut self.reader, MAX_SIGNAL_FRAME_LEN),
            )
            .await
            {
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
        write_raw_frame_limited(
            &mut self.writer,
            &SignalMessage::Ping.encode()?,
            MAX_SIGNAL_FRAME_LEN,
        )
        .await?;
        Ok(())
    }
}

/// 完成一次 challenge-response 注册（连接建立后的前两个来回）。
async fn register_session(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
    identity: &Identity,
    candidates: Vec<Candidate>,
) -> Result<()> {
    let node_id = identity.node_id();
    let public_key = identity.public_key_bytes();

    let hello = SignalMessage::RegisterHello {
        protocol_version: SIGNAL_PROTOCOL_VERSION,
        node_id,
        public_key,
    };
    write_raw_frame_limited(writer, &hello.encode()?, MAX_SIGNAL_FRAME_LEN).await?;

    let reply = read_raw_frame_limited(reader, MAX_SIGNAL_FRAME_LEN)
        .await?
        .ok_or_else(|| Error::Discovery("信令服务器在 challenge 之前就关闭了连接".into()))?;
    let challenge = match SignalMessage::decode(&reply)? {
        SignalMessage::RegisterChallenge {
            protocol_version,
            challenge,
        } => {
            if protocol_version != SIGNAL_PROTOCOL_VERSION {
                return Err(Error::Discovery(format!(
                    "信令协议版本不兼容：本机 {SIGNAL_PROTOCOL_VERSION}，对端 {protocol_version}"
                )));
            }
            challenge
        }
        SignalMessage::Error { reason } => {
            return Err(Error::Discovery(format!("登记被拒绝: {reason}")));
        }
        other => {
            return Err(Error::Discovery(format!(
                "期待 RegisterChallenge，收到 {}",
                other.kind()
            )));
        }
    };

    let payload = register_payload(&challenge, node_id, &public_key, &candidates)?;
    let register = SignalMessage::Register {
        node_id,
        public_key,
        candidates,
        signature: identity.sign(&payload).to_bytes().to_vec(),
    };
    write_raw_frame_limited(writer, &register.encode()?, MAX_SIGNAL_FRAME_LEN).await?;

    let reply = read_raw_frame_limited(reader, MAX_SIGNAL_FRAME_LEN)
        .await?
        .ok_or_else(|| Error::Discovery("信令服务器在确认前就关闭了连接".into()))?;
    match SignalMessage::decode(&reply)? {
        SignalMessage::Registered => Ok(()),
        SignalMessage::Error { reason } => Err(Error::Discovery(format!("登记被拒绝: {reason}"))),
        other => Err(Error::Discovery(format!(
            "登记后收到意外消息 {}",
            other.kind()
        ))),
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
        spawn_signal_server_with(SignalServerConfig::default())
            .await
            .0
    }

    /// 起一个带自定义配置的信令服务器，并把在线表暴露给测试。
    async fn spawn_signal_server_with(
        config: SignalServerConfig,
    ) -> (SocketAddr, Arc<Mutex<Registry>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(Registry::default()));
        let shared = Arc::clone(&registry);
        let config = Arc::new(config);
        let mut next_connection_id = 1u64;
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let registry = Arc::clone(&shared);
                let config = Arc::clone(&config);
                let connection_id = next_connection_id;
                next_connection_id = next_connection_id.wrapping_add(1);
                if next_connection_id == 0 {
                    next_connection_id = 1;
                }
                tokio::spawn(async move {
                    let _ = handle_signal_client(stream, registry, connection_id, config).await;
                });
            }
        });
        (addr, registry)
    }

    /// 轮询等待在线表满足条件（清理是连接 handler 异步做的）。
    async fn wait_for_registry<F>(registry: &Arc<Mutex<Registry>>, predicate: F)
    where
        F: Fn(&Registry) -> bool,
    {
        for _ in 0..200 {
            {
                let reg = registry.lock().await;
                if predicate(&reg) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("等待在线表状态超时");
    }

    /// 裸信令连接：直接读写帧，用来构造畸形/攻击场景。
    struct Raw {
        stream: TcpStream,
    }

    impl Raw {
        async fn connect(addr: SocketAddr) -> Self {
            let stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).unwrap();
            Self { stream }
        }

        async fn send(&mut self, message: &SignalMessage) {
            write_raw_frame_limited(
                &mut self.stream,
                &message.encode().unwrap(),
                MAX_SIGNAL_FRAME_LEN,
            )
            .await
            .unwrap();
        }

        /// 只写一个长度头，后面不跟载荷（用于验证长度上限）。
        async fn send_len_header(&mut self, len: u32) {
            self.stream.write_all(&len.to_le_bytes()).await.unwrap();
            self.stream.flush().await.unwrap();
        }

        async fn recv(&mut self) -> Option<SignalMessage> {
            let payload = read_raw_frame_limited(&mut self.stream, MAX_SIGNAL_FRAME_LEN)
                .await
                .unwrap()?;
            Some(SignalMessage::decode(&payload).unwrap())
        }

        /// 发 RegisterHello 并取回 challenge。
        async fn hello(&mut self, identity: &Identity) -> [u8; CHALLENGE_LEN] {
            self.send(&SignalMessage::RegisterHello {
                protocol_version: SIGNAL_PROTOCOL_VERSION,
                node_id: identity.node_id(),
                public_key: identity.public_key_bytes(),
            })
            .await;
            match self.recv().await {
                Some(SignalMessage::RegisterChallenge {
                    protocol_version,
                    challenge,
                }) => {
                    assert_eq!(protocol_version, SIGNAL_PROTOCOL_VERSION);
                    challenge
                }
                other => panic!("期待 RegisterChallenge，收到 {other:?}"),
            }
        }

        /// 用 `signer` 对 `identity` 的身份签名并发出 Register。
        async fn register_with(
            &mut self,
            identity: &Identity,
            signer: &Identity,
            challenge: &[u8; CHALLENGE_LEN],
            candidates: Vec<Candidate>,
        ) -> Option<SignalMessage> {
            let node_id = identity.node_id();
            let public_key = identity.public_key_bytes();
            let payload = register_payload(challenge, node_id, &public_key, &candidates).unwrap();
            self.send(&SignalMessage::Register {
                node_id,
                public_key,
                candidates,
                signature: signer.sign(&payload).to_bytes().to_vec(),
            })
            .await;
            self.recv().await
        }

        /// 走完一次合法注册。
        async fn full_register(
            &mut self,
            identity: &Identity,
            candidates: Vec<Candidate>,
        ) -> [u8; CHALLENGE_LEN] {
            let challenge = self.hello(identity).await;
            match self
                .register_with(identity, identity, &challenge, candidates)
                .await
            {
                Some(SignalMessage::Registered) => challenge,
                other => panic!("注册应当成功，实际 {other:?}"),
            }
        }
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
            SignalMessage::RegisterHello {
                protocol_version: SIGNAL_PROTOCOL_VERSION,
                node_id: node,
                public_key: [7u8; 32],
            },
            SignalMessage::RegisterChallenge {
                protocol_version: SIGNAL_PROTOCOL_VERSION,
                challenge: [5u8; CHALLENGE_LEN],
            },
            SignalMessage::Register {
                node_id: node,
                public_key: [7u8; 32],
                candidates: vec![candidate(CandidateKind::Host, "192.168.1.20:9000")],
                signature: vec![1u8; 64],
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

    #[test]
    fn 注册载荷绑定_challenge_与候选() {
        let alice = Identity::generate();
        let candidates = vec![candidate(CandidateKind::Host, "192.168.1.5:9000")];
        let base = register_payload(
            &[1u8; CHALLENGE_LEN],
            alice.node_id(),
            &alice.public_key_bytes(),
            &candidates,
        )
        .unwrap();

        // challenge 变了，载荷必须变（否则重放可行）。
        let other_challenge = register_payload(
            &[2u8; CHALLENGE_LEN],
            alice.node_id(),
            &alice.public_key_bytes(),
            &candidates,
        )
        .unwrap();
        assert_ne!(base, other_challenge);

        // 候选地址变了，载荷必须变（否则明文信令上的中间人可篡改地址）。
        let tampered = vec![candidate(CandidateKind::Host, "192.168.1.6:9000")];
        let other_candidates = register_payload(
            &[1u8; CHALLENGE_LEN],
            alice.node_id(),
            &alice.public_key_bytes(),
            &tampered,
        )
        .unwrap();
        assert_ne!(base, other_candidates, "候选地址必须进签名");
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
        let mut raw = Raw::connect(addr).await;
        raw.full_register(
            &bob,
            vec![candidate(CandidateKind::Host, "192.168.1.2:9000")],
        )
        .await;

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
        raw.stream.set_linger(Some(Duration::ZERO)).unwrap();
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

    // -----------------------------------------------------------------------
    // Issue #2：注册认证
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn 节点_id_与公钥不匹配时注册被拒绝() {
        let (addr, registry) = spawn_signal_server_with(SignalServerConfig::default()).await;
        let alice = Identity::generate();
        let mallory = Identity::generate();

        let mut raw = Raw::connect(addr).await;
        raw.send(&SignalMessage::RegisterHello {
            protocol_version: SIGNAL_PROTOCOL_VERSION,
            node_id: alice.node_id(),
            public_key: mallory.public_key_bytes(),
        })
        .await;

        match raw.recv().await {
            Some(SignalMessage::Error { reason }) => {
                assert!(reason.contains("公钥"), "实际: {reason}");
            }
            other => panic!("公钥与节点 ID 不符时必须拒绝，实际 {other:?}"),
        }
        assert!(registry.lock().await.peers.is_empty(), "不能写进在线表");
        // 服务端应当关闭连接。
        assert!(
            tokio::time::timeout(Duration::from_secs(2), raw.recv())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn 签名不是对应私钥时注册被拒绝() {
        let (addr, registry) = spawn_signal_server_with(SignalServerConfig::default()).await;
        let mallory = Identity::generate();
        let impostor = Identity::generate();

        let mut raw = Raw::connect(addr).await;
        let challenge = raw.hello(&mallory).await;
        let reply = raw
            .register_with(
                &mallory,
                &impostor,
                &challenge,
                vec![candidate(CandidateKind::Host, "192.168.1.9:9000")],
            )
            .await;

        match reply {
            Some(SignalMessage::Error { reason }) => {
                assert!(reason.contains("签名"), "实际: {reason}");
            }
            other => panic!("签名不匹配私钥时必须拒绝，实际 {other:?}"),
        }
        assert!(
            registry.lock().await.peers.is_empty(),
            "验签失败绝对不能写进在线表"
        );
    }

    #[tokio::test]
    async fn 重放上一连接的注册签名会被拒绝() {
        let (addr, registry) = spawn_signal_server_with(SignalServerConfig::default()).await;
        let bob = Identity::generate();
        let candidates = vec![candidate(CandidateKind::Host, "192.168.1.7:9000")];

        // 第一条连接合法注册，留下 (challenge1, signature1)。
        let mut first = Raw::connect(addr).await;
        let challenge1 = first.hello(&bob).await;
        let payload1 = register_payload(
            &challenge1,
            bob.node_id(),
            &bob.public_key_bytes(),
            &candidates,
        )
        .unwrap();
        let replay = SignalMessage::Register {
            node_id: bob.node_id(),
            public_key: bob.public_key_bytes(),
            candidates: candidates.clone(),
            signature: bob.sign(&payload1).to_bytes().to_vec(),
        };
        first.send(&replay).await;
        assert!(matches!(
            first.recv().await,
            Some(SignalMessage::Registered)
        ));

        // 第二条连接会拿到一个新 challenge，把旧 Register 原样搬过去必须失败。
        let mut second = Raw::connect(addr).await;
        let challenge2 = second.hello(&bob).await;
        assert_ne!(challenge1, challenge2, "每条连接必须是新随机 challenge");
        second.send(&replay).await;
        match second.recv().await {
            Some(SignalMessage::Error { reason }) => {
                assert!(reason.contains("签名"), "实际: {reason}");
            }
            other => panic!("重放必须失败，实际 {other:?}"),
        }

        // 第一条连接不受影响，仍然是当前记录。
        assert!(registry.lock().await.peers.contains_key(&bob.node_id()));
    }

    #[tokio::test]
    async fn 篡改候选地址会导致签名校验失败() {
        let (addr, registry) = spawn_signal_server_with(SignalServerConfig::default()).await;
        let alice = Identity::generate();

        let mut raw = Raw::connect(addr).await;
        let challenge = raw.hello(&alice).await;
        // 签名覆盖的是这些候选……
        let signed = vec![candidate(CandidateKind::Host, "192.168.1.5:9000")];
        let payload = register_payload(
            &challenge,
            alice.node_id(),
            &alice.public_key_bytes(),
            &signed,
        )
        .unwrap();
        // ……但发出去的是被篡改过的候选。
        let tampered = vec![candidate(CandidateKind::Host, "203.0.113.66:9000")];
        raw.send(&SignalMessage::Register {
            node_id: alice.node_id(),
            public_key: alice.public_key_bytes(),
            candidates: tampered,
            signature: alice.sign(&payload).to_bytes().to_vec(),
        })
        .await;

        assert!(matches!(
            raw.recv().await,
            Some(SignalMessage::Error { .. })
        ));
        assert!(registry.lock().await.peers.is_empty());
    }

    #[tokio::test]
    async fn 同一连接不能重复注册或切换身份() {
        let (addr, registry) = spawn_signal_server_with(SignalServerConfig::default()).await;
        let alice = Identity::generate();
        let bob = Identity::generate();

        let mut raw = Raw::connect(addr).await;
        raw.full_register(
            &alice,
            vec![candidate(CandidateKind::Host, "192.168.1.1:9000")],
        )
        .await;

        // 想在同一条连接上再注册另一个身份（旧代码会留下幽灵记录）。
        raw.send(&SignalMessage::RegisterHello {
            protocol_version: SIGNAL_PROTOCOL_VERSION,
            node_id: bob.node_id(),
            public_key: bob.public_key_bytes(),
        })
        .await;
        match raw.recv().await {
            Some(SignalMessage::Error { reason }) => {
                assert!(reason.contains("注册"), "实际: {reason}");
            }
            other => panic!("重复注册必须被拒绝，实际 {other:?}"),
        }

        // 连接被关闭；registry 里不能有 bob，alice 也随连接断开被清掉。
        assert!(
            tokio::time::timeout(Duration::from_secs(2), raw.recv())
                .await
                .unwrap()
                .is_none()
        );
        wait_for_registry(&registry, |reg| reg.peers.is_empty()).await;
        let reg = registry.lock().await;
        assert!(!reg.peers.contains_key(&bob.node_id()), "不能留下幽灵节点");
        assert!(reg.peers.is_empty());
    }

    #[tokio::test]
    async fn 旧连接断开不会删除新连接() {
        let (addr, registry) = spawn_signal_server_with(SignalServerConfig::default()).await;
        let alice = Identity::generate();
        let old_candidates = vec![candidate(CandidateKind::Host, "192.168.1.1:9000")];
        let new_candidates = vec![candidate(CandidateKind::Host, "192.168.1.1:9100")];

        let mut old = Raw::connect(addr).await;
        old.full_register(&alice, old_candidates).await;

        let mut new = Raw::connect(addr).await;
        new.full_register(&alice, new_candidates.clone()).await;

        {
            let reg = registry.lock().await;
            let record = reg.peers.get(&alice.node_id()).expect("alice 应当在线");
            assert_eq!(record.candidates, new_candidates);
        }

        // 旧连接断开，它的清理不能删掉新连接的记录。
        drop(old);
        tokio::time::sleep(Duration::from_millis(300)).await;
        {
            let reg = registry.lock().await;
            let record = reg.peers.get(&alice.node_id()).expect("新连接必须仍然在线");
            assert_eq!(record.candidates, new_candidates);
        }

        // 新连接依然可用。
        new.send(&SignalMessage::Ping).await;
        assert!(matches!(new.recv().await, Some(SignalMessage::Pong)));
    }

    #[tokio::test]
    async fn 旧连接注销不会删除新连接的记录() {
        // 直接对 Registry 做确定性验证：connection_id 所有权。
        let (outbox_old, _rx_old) = mpsc::channel(1);
        let (close_old, _) = watch::channel(false);
        let (outbox_new, _rx_new) = mpsc::channel(1);
        let (close_new, _) = watch::channel(false);

        let alice = Identity::generate().node_id();
        let mut reg = Registry::default();
        reg.peers.insert(
            alice,
            PeerRecord {
                connection_id: 1,
                candidates: vec![],
                outbox: outbox_old,
                close: close_old,
            },
        );
        reg.peers.insert(
            alice,
            PeerRecord {
                connection_id: 2,
                candidates: vec![],
                outbox: outbox_new,
                close: close_new,
            },
        );

        // 旧连接（generation 1）的清理不得删除 generation 2 的记录。
        reg.unregister(alice, 1);
        assert_eq!(
            reg.peers.get(&alice).map(|record| record.connection_id),
            Some(2)
        );

        // 新连接断开时才真正摘掉。
        reg.unregister(alice, 2);
        assert!(!reg.peers.contains_key(&alice));
    }

    #[test]
    fn 断开后空_waiter_会被清理() {
        let requester = Identity::generate().node_id();
        let other = Identity::generate().node_id();
        let mut reg = Registry::default();

        for _ in 0..8 {
            reg.waiters
                .entry(Identity::generate().node_id())
                .or_default()
                .insert(requester);
        }
        // 另一个 requester 的等待不该被误删。
        let kept_target = Identity::generate().node_id();
        reg.waiters.entry(kept_target).or_default().insert(other);
        // 一个从一开始就空的集合。
        reg.waiters
            .entry(Identity::generate().node_id())
            .or_default();

        reg.unregister(requester, 1);

        assert!(
            reg.waiters.values().all(|waiters| !waiters.is_empty()),
            "不该留下空 set"
        );
        assert_eq!(reg.waiter_entries(), 1, "只应剩下 other 的那一条");
        assert!(reg.waiters.get(&kept_target).unwrap().contains(&other));
    }

    #[tokio::test]
    async fn lookup_会去重且每连接有上限() {
        let config = SignalServerConfig {
            max_pending_lookups: 2,
            ..SignalServerConfig::default()
        };
        let (addr, registry) = spawn_signal_server_with(config).await;
        let alice = Identity::generate();
        let mut client = SignalingClient::connect(&addr.to_string(), &alice, vec![])
            .await
            .unwrap();

        let first = Identity::generate().node_id();
        let second = Identity::generate().node_id();
        let third = Identity::generate().node_id();

        assert_eq!(client.lookup(first).await.unwrap(), LookupOutcome::Pending);
        // 重复查询同一个目标不该重复计数。
        assert_eq!(client.lookup(first).await.unwrap(), LookupOutcome::Pending);
        assert_eq!(
            registry.lock().await.waiter_entries(),
            1,
            "重复 lookup 必须去重"
        );

        assert_eq!(client.lookup(second).await.unwrap(), LookupOutcome::Pending);
        assert_eq!(registry.lock().await.waiter_entries(), 2);

        // 超过单连接上限：明确报错，且不写入。
        let err = client.lookup(third).await.unwrap_err();
        assert!(matches!(err, Error::Discovery(_)), "实际 {err:?}");
        assert_eq!(
            registry.lock().await.waiter_entries(),
            2,
            "超限的查询不得写入"
        );
    }

    #[tokio::test]
    async fn 候选地址超限会被拒绝() {
        let (addr, registry) = spawn_signal_server_with(SignalServerConfig::default()).await;
        let alice = Identity::generate();
        let mut raw = Raw::connect(addr).await;
        let challenge = raw.hello(&alice).await;

        let mut candidates = Vec::new();
        for index in 0..(MAX_CANDIDATES + 1) {
            let addr = format!("192.168.1.{}:{}", (index % 250) + 1, 9000 + index);
            candidates.push(candidate(CandidateKind::Host, &addr));
        }
        let reply = raw
            .register_with(&alice, &alice, &challenge, candidates)
            .await;

        match reply {
            Some(SignalMessage::Error { reason }) => {
                assert!(reason.contains("候选"), "实际: {reason}");
            }
            other => panic!("候选超限必须拒绝，实际 {other:?}"),
        }
        assert!(registry.lock().await.peers.is_empty());
    }

    #[tokio::test]
    async fn 信令帧超限会被拒绝并断开() {
        let addr = spawn_signal_server().await;
        let mut raw = Raw::connect(addr).await;
        // 只写一个超过信令上限的长度头，服务端必须在分配前拒绝并断开。
        raw.send_len_header(MAX_SIGNAL_FRAME_LEN + 1).await;

        let closed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if raw.recv().await.is_none() {
                    break true;
                }
            }
        })
        .await;
        assert!(closed.unwrap(), "帧超限时必须关闭连接");
    }

    #[tokio::test]
    async fn outbox_满时牵线会关闭异常连接而不是只发一边() {
        // 有界队列 + try_reserve 的意义：排不下就断开，而不是无限积压，
        // 也不是把令牌只发给一边（那会让双方拿到不同令牌）。
        let (outbox_a, mut rx_a) = mpsc::channel(1);
        let (close_a, _close_a_rx) = watch::channel(false);
        let (outbox_b, _rx_b) = mpsc::channel(1);
        let (close_b, close_b_rx) = watch::channel(false);

        let a = Identity::generate().node_id();
        let b = Identity::generate().node_id();

        // 把 B 的队列占满。
        outbox_b.try_send(SignalMessage::Pong).unwrap();

        let mut reg = Registry::default();
        reg.peers.insert(
            a,
            PeerRecord {
                connection_id: 1,
                candidates: vec![],
                outbox: outbox_a,
                close: close_a,
            },
        );
        reg.peers.insert(
            b,
            PeerRecord {
                connection_id: 2,
                candidates: vec![],
                outbox: outbox_b,
                close: close_b,
            },
        );

        reg.try_pair(a, b);

        assert!(
            close_b_rx.has_changed().unwrap_or(false),
            "队列已满的连接应当被要求断开"
        );
        assert!(rx_a.try_recv().is_err(), "牵线失败时不能只把令牌发给一边");
    }

    #[tokio::test]
    async fn 首帧超时会关闭连接() {
        let config = SignalServerConfig {
            first_frame_timeout: Duration::from_millis(150),
            ..SignalServerConfig::default()
        };
        let (addr, _) = spawn_signal_server_with(config).await;
        let mut raw = Raw::connect(addr).await;

        let closed = tokio::time::timeout(Duration::from_secs(3), raw.recv())
            .await
            .expect("不该挂死");
        assert!(closed.is_none(), "首帧超时后应关闭连接");
    }

    #[tokio::test]
    async fn 注册应答超时会关闭连接() {
        let config = SignalServerConfig {
            register_timeout: Duration::from_millis(150),
            ..SignalServerConfig::default()
        };
        let (addr, registry) = spawn_signal_server_with(config).await;
        let alice = Identity::generate();
        let mut raw = Raw::connect(addr).await;
        let _ = raw.hello(&alice).await; // 拿到 challenge 后故意不发 Register

        let closed = tokio::time::timeout(Duration::from_secs(3), raw.recv())
            .await
            .expect("不该挂死");
        assert!(closed.is_none(), "注册超时后应关闭连接");
        assert!(registry.lock().await.peers.is_empty());
    }

    #[tokio::test]
    async fn 登记后长时间空闲会被断开() {
        let config = SignalServerConfig {
            idle_timeout: Duration::from_millis(150),
            ..SignalServerConfig::default()
        };
        let (addr, registry) = spawn_signal_server_with(config).await;
        let alice = Identity::generate();
        let mut raw = Raw::connect(addr).await;
        raw.full_register(&alice, vec![]).await;

        let closed = tokio::time::timeout(Duration::from_secs(3), raw.recv())
            .await
            .expect("不该挂死");
        assert!(closed.is_none(), "空闲超时后应关闭连接");
        wait_for_registry(&registry, |reg| reg.peers.is_empty()).await;
    }

    #[tokio::test]
    async fn 信令协议版本不匹配会被拒绝() {
        let addr = spawn_signal_server().await;
        let alice = Identity::generate();
        let mut raw = Raw::connect(addr).await;
        raw.send(&SignalMessage::RegisterHello {
            protocol_version: SIGNAL_PROTOCOL_VERSION + 1,
            node_id: alice.node_id(),
            public_key: alice.public_key_bytes(),
        })
        .await;

        match raw.recv().await {
            Some(SignalMessage::Error { reason }) => {
                assert!(reason.contains("版本"), "实际: {reason}");
            }
            other => panic!("版本不匹配必须明确拒绝，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn 客户端拒绝版本不匹配的挑战() {
        // 假服务器回一个版本号不对的 challenge，客户端必须明确报错，
        // 不能当作正常流程继续。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let _ = read_raw_frame_limited(&mut reader, MAX_SIGNAL_FRAME_LEN).await;
            let reply = SignalMessage::RegisterChallenge {
                protocol_version: SIGNAL_PROTOCOL_VERSION + 1,
                challenge: [0u8; CHALLENGE_LEN],
            };
            let _ = write_raw_frame_limited(
                &mut write_half,
                &reply.encode().unwrap(),
                MAX_SIGNAL_FRAME_LEN,
            )
            .await;
        });

        let alice = Identity::generate();
        let err = SignalingClient::connect(&addr.to_string(), &alice, vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Discovery(_)), "实际 {err:?}");
        assert!(err.to_string().contains("版本"), "实际: {err}");
    }

    #[test]
    fn 线格式变体序号保持稳定() {
        // postcard 的 enum 用变体序号编码，而这些序号就是 v1 的线格式：一旦
        // 重排，跨版本会**静默错解**（例如 v1 客户端把 v2 的 RegisterChallenge
        // 当成 Registered，假装登记成功了）。这里把序号钉死，防止以后不小心改。
        let node = Identity::generate().node_id();
        let index = |message: &SignalMessage| message.encode().unwrap()[0];

        assert_eq!(
            index(&SignalMessage::Register {
                node_id: node,
                public_key: [0u8; 32],
                candidates: vec![],
                signature: vec![]
            }),
            0
        );
        assert_eq!(index(&SignalMessage::Registered), 1);
        assert_eq!(index(&SignalMessage::Lookup { node_id: node }), 2);
        assert_eq!(
            index(&SignalMessage::PeerCandidates {
                node_id: node,
                candidates: vec![],
                token: PunchToken::from_bytes([0u8; 16]),
            }),
            3
        );
        assert_eq!(index(&SignalMessage::PeerPending { node_id: node }), 4);
        assert_eq!(index(&SignalMessage::Ping), 5);
        assert_eq!(index(&SignalMessage::Pong), 6);
        assert_eq!(
            index(&SignalMessage::Error {
                reason: String::new()
            }),
            7
        );
        assert_eq!(
            index(&SignalMessage::RegisterHello {
                protocol_version: SIGNAL_PROTOCOL_VERSION,
                node_id: node,
                public_key: [0u8; 32],
            }),
            8
        );
        assert_eq!(
            index(&SignalMessage::RegisterChallenge {
                protocol_version: SIGNAL_PROTOCOL_VERSION,
                challenge: [0u8; CHALLENGE_LEN],
            }),
            9
        );
    }

    #[tokio::test]
    async fn v1_无签名注册帧会被明确拒绝() {
        // 手工拼一个 v1 的 `Register` 帧：变体 0 + node_id + public_key +
        // candidates，没有 signature 字段。服务器必须解析失败并拒绝，
        // 绝不能把它当成一次合法登记（那正是 #2 要修的冒名路径）。
        let addr = spawn_signal_server().await;
        let alice = Identity::generate();

        let mut body = vec![0u8];
        body.extend(postcard::to_allocvec(&alice.node_id()).unwrap());
        body.extend(postcard::to_allocvec(&alice.public_key_bytes()).unwrap());
        body.extend(
            postcard::to_allocvec(&vec![candidate(CandidateKind::Host, "192.168.1.9:9000")])
                .unwrap(),
        );

        let mut raw = Raw::connect(addr).await;
        write_raw_frame_limited(&mut raw.stream, &body, MAX_SIGNAL_FRAME_LEN)
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(3), raw.recv())
            .await
            .expect("服务端不该挂死");
        assert!(
            !matches!(reply, Some(SignalMessage::Registered)),
            "v1 无签名注册帧必须被拒绝，实际 {reply:?}"
        );
    }
}
