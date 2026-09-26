//! QUIC 端点与连接。
//!
//! # 关于跳过 TLS 证书校验
//!
//! P2P 场景里没有 CA，也不该有：节点身份由 Ed25519 公钥决定，公钥到节点 ID
//! 的映射是自证的。所以这里**故意**装了一个不校验证书的 verifier，信任建立
//! 推迟到应用层握手（见 [`crate::transport::handshake`]）。
//!
//! 成立的前提是：**任何连接都必须先跑完应用层握手**。QUIC 提供的是加密和
//! 完整性，握手提供的是身份确认；少了握手，中间人就挡不住了。
//! 这条约束不能省。
//!
//! 但「跑了握手」还不够：如果签名载荷不含任何和当前 TLS 会话相关的东西，
//! 攻击者可以建立两条独立连接（A↔M、M↔B）原样转发握手消息，让 A、B 各自
//! 都验证通过。为此应用层握手必须把 [`ChannelBinding`]（由当前连接的 TLS
//! exporter 导出）纳入签名载荷，见 [`crate::transport::handshake`]。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use quinn::{
    AsyncUdpSocket, ClientConfig, Endpoint, IdleTimeout, Runtime, ServerConfig, TransportConfig,
    UdpPoller, VarIntBoundsExceeded,
};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::nat::punch::{PROBE_MAGIC, PunchToken};

const PUNCH_PROBE_PADDING_LEN: usize = 16;
const PUNCH_EVENT_CAPACITY: usize = 4;
const MAX_PUNCH_SOURCES_PER_ROUTE: usize = 8;
const MAX_AUTHORIZED_PUNCH_SOURCES: usize = 128;

/// ALPN 标识，防止连到别的 QUIC 服务上。
pub const ALPN: &[u8] = b"p2pfile/1";

/// 空闲多久发一次 keepalive。NAT 映射通常 30~120 秒超时，10 秒足够稳。
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// 空闲超时。超过这个时间没有任何活动就认为连接死了。
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 应用层握手各阶段允许的最大静默时间。
pub const APPLICATION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 等待 QUIC transport handshake 完成的最大时间；与应用层四阶段握手分开计时。
pub const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 等待一条连接的第一条双向业务流的最大时间。
pub const ACCEPT_FIRST_BI_STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// 等待业务流首帧的最大时间。
pub const STREAM_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// 文件控制流两帧之间允许的最大静默时间；不是整个文件的总时限。
pub const TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// 导出会话绑定值时使用的 TLS exporter 标签（RFC 5705）。
///
/// 标签是固定的：只要双方在同一条 TLS 会话上、传同样的标签和 context，
/// 就会导出完全相同的字节。
pub const CHANNEL_BINDING_LABEL: &[u8] = b"p2p_file/channel-binding/v1";

/// 会话绑定值长度。32 字节足够，且不会触发 exporter 的长度限制。
pub const CHANNEL_BINDING_LEN: usize = 32;

/// 当前 QUIC/TLS 会话的通道绑定值（channel binding）。
///
/// 这是把应用层 Ed25519 认证钉死在**这一条** TLS 会话上的关键：绑定值由
/// [`quinn::Connection::export_keying_material`] 从当前会话的 TLS 密钥材料派生，
/// 不同 TLS 会话（哪怕对端、参数完全相同）导出的是各自独立的伪随机值。
///
/// 因此中间人无法建立 A↔M、M↔B 两条连接后原样转发应用层握手：A 用 A↔M 的
/// 绑定值签名，B 用 M↔B 的绑定值校验，签名必然对不上。
///
/// 安全约束：绑定值**只能**来自当前连接。本类型字段私有，唯一的公开构造入口
/// 是 [`ChannelBinding::from_connection`]，从类型上杜绝调用方传常量、空值或
/// 自己随机出来的值。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChannelBinding([u8; CHANNEL_BINDING_LEN]);

impl ChannelBinding {
    /// 从当前 QUIC/TLS 会话导出绑定值。
    ///
    /// 必须在 TLS 握手完成后调用；调用方拿到 [`quinn::Connection`] 时握手
    /// 已经完成，所以正常路径不会失败，失败会得到明确错误而不是 panic。
    pub fn from_connection(connection: &quinn::Connection) -> Result<Self> {
        let mut binding = [0u8; CHANNEL_BINDING_LEN];
        connection
            .export_keying_material(&mut binding, CHANNEL_BINDING_LABEL, b"")
            .map_err(|_| {
                Error::Transport("导出 TLS 会话绑定值失败：TLS 握手尚未完成或连接已失效".into())
            })?;
        Ok(Self(binding))
    }

    /// 供签名载荷使用。
    pub fn as_bytes(&self) -> &[u8; CHANNEL_BINDING_LEN] {
        &self.0
    }
}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 绑定值是会话相关的伪随机串，不是长期密钥，但也没有进日志的必要。
        f.write_str("ChannelBinding(<32 bytes>)")
    }
}

/// 仅测试用：直接指定绑定值。
///
/// 用来模拟「不同会话导出不同绑定值」以及「翻转 1 bit」这类场景；
/// 生产代码拿不到这个入口（`cfg(test)`），只能从真实连接导出。
#[cfg(test)]
impl ChannelBinding {
    pub(crate) fn from_bytes_for_test(bytes: [u8; CHANNEL_BINDING_LEN]) -> Self {
        Self(bytes)
    }
}

static CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

/// 安装 rustls 的默认加密后端。
///
/// rustls 要求进程内只装一次。重复调用是安全的：已经装过就什么也不做。
pub fn install_crypto_provider() {
    CRYPTO_PROVIDER.get_or_init(|| {
        // 失败只可能是别的库先装过了，那也算装好了。
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 共享的传输参数：keepalive + 空闲超时。
fn transport_config() -> Result<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    let idle: IdleTimeout = MAX_IDLE_TIMEOUT
        .try_into()
        .map_err(|err: VarIntBoundsExceeded| Error::Transport(format!("空闲超时非法: {err}")))?;
    transport.max_idle_timeout(Some(idle));
    Ok(transport)
}

/// 构造服务端 TLS/QUIC 配置。
///
/// 每次调用生成一张新的自签证书。这不影响身份安全——身份由应用层握手保证。
fn server_config() -> Result<ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["p2pfile".to_string()])
        .map_err(|err| Error::Transport(format!("生成自签证书失败: {err}")))?;
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|err| Error::Transport(format!("TLS 服务端配置失败: {err}")))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|err| Error::Transport(format!("QUIC 服务端配置失败: {err}")))?;

    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

/// 构造客户端 TLS/QUIC 配置。
fn client_config() -> Result<ClientConfig> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| Error::Transport(format!("QUIC 客户端配置失败: {err}")))?;

    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

/// 用**现成的** UDP socket 建一个 QUIC 端点。
///
/// 这是打洞能真正生效的关键：NAT 映射是按「本地端口」分配的，只有让 QUIC
/// 复用那个刚刚打过洞、已经建立了映射的 socket，数据才会走直连。
/// 换一个新 socket 就等于重新开一条 NAT 映射，洞白打了。
///
/// 端点同时装了服务端和客户端配置，所以两边都既能 accept 也能 connect——
/// 打洞是对称的，谁先连谁后连由上层角色决定。
pub fn endpoint_from_socket(socket: std::net::UdpSocket) -> Result<Endpoint> {
    install_crypto_provider();

    // quinn 内部会用 tokio 的 from_std 接管这个 socket，而它要求 socket 处于
    // 非阻塞模式。从 tokio UdpSocket 转出来的本来就是非阻塞的，这里再设一次
    // 是为了不依赖上层的调用方式。
    socket
        .set_nonblocking(true)
        .map_err(|err| Error::Transport(format!("设置非阻塞失败: {err}")))?;

    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Transport("当前没有可用的异步运行时".into()))?;

    let config = server_config()?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )
    .map_err(|err| Error::Transport(format!("用已有 socket 创建 QUIC 端点失败: {err}")))?;

    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}

/// A send-only view of the UDP socket whose receive side is owned by Quinn.
///
/// Desktop punch traffic is demultiplexed inside Quinn's `AsyncUdpSocket::poll_recv`
/// implementation. Callers can register a token and send probes, but cannot create a
/// competing receive loop on this handle.
#[derive(Clone, Debug)]
pub struct PunchSocketHandle {
    io: Arc<UdpSocket>,
    router: PunchRouter,
}

impl PunchSocketHandle {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub fn register_probe(&self, token: &PunchToken) -> Result<PunchProbeReceiver> {
        self.router.register(token, None, 0)
    }

    pub fn register_peer_probe(
        &self,
        token: &PunchToken,
        peer: crate::identity::NodeId,
        generation: u64,
    ) -> Result<PunchProbeReceiver> {
        self.router.register(token, Some(peer), generation)
    }

    /// Consume an address authorization created by a token-validated punch datagram.
    pub fn claim_authorized_peer(
        &self,
        source: SocketAddr,
    ) -> Option<(crate::identity::NodeId, u64)> {
        self.router.claim_authorized_peer(source)
    }

    pub async fn send_probe_to(
        &self,
        token: &PunchToken,
        destination: SocketAddr,
    ) -> io::Result<()> {
        let packet = crate::nat::punch::probe_packet(token);
        let sent = self.io.send_to(&packet, destination).await?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP punch probe was only partially sent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PunchRoute {
    id: u64,
    expected_peer: Option<crate::identity::NodeId>,
    generation: u64,
    sender: mpsc::Sender<SocketAddr>,
    sources: HashSet<SocketAddr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorizedPunchSource {
    peer: crate::identity::NodeId,
    generation: u64,
    route_id: u64,
}

#[derive(Debug, Default)]
struct PunchRoutes {
    by_token: HashMap<[u8; 16], PunchRoute>,
    by_source: HashMap<SocketAddr, Vec<AuthorizedPunchSource>>,
    source_count: usize,
}

#[derive(Clone, Debug, Default)]
struct PunchRouter {
    routes: Arc<Mutex<PunchRoutes>>,
    next_id: Arc<AtomicU64>,
}

impl PunchRouter {
    fn register(
        &self,
        token: &PunchToken,
        expected_peer: Option<crate::identity::NodeId>,
        generation: u64,
    ) -> Result<PunchProbeReceiver> {
        let (sender, receiver) = mpsc::channel(PUNCH_EVENT_CAPACITY);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let key = *token.as_bytes();
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| Error::Transport("打洞事件路由锁已损坏".into()))?;
        if routes.by_token.len() >= 16 {
            return Err(Error::Transport("打洞令牌注册已达资源上限".into()));
        }
        if routes.by_token.contains_key(&key) {
            return Err(Error::Transport("同一打洞令牌已有活动接收者".into()));
        }
        routes.by_token.insert(
            key,
            PunchRoute {
                id,
                expected_peer,
                generation,
                sender,
                sources: HashSet::new(),
            },
        );
        Ok(PunchProbeReceiver {
            token: key,
            id,
            router: self.clone(),
            receiver,
        })
    }

    /// Return true only for an exact-size probe carrying a currently registered token.
    /// This keeps ordinary QUIC packets on Quinn's path, even if their bytes happen to
    /// share the probe magic prefix.
    fn route_datagram(&self, packet: &[u8], source: SocketAddr) -> bool {
        let token_start = PROBE_MAGIC.len();
        let expected_len = token_start + 16 + PUNCH_PROBE_PADDING_LEN;
        if packet.len() != expected_len || !packet.starts_with(PROBE_MAGIC) {
            return false;
        }
        let mut token = [0u8; 16];
        let token_end = token_start + token.len();
        token.copy_from_slice(&packet[token_start..token_end]);
        let mut routes = match self.routes.lock() {
            Ok(routes) => routes,
            // The packet has the exact punch shape, so drop it if internal routing is
            // unavailable. Passing it to QUIC must never create punch progress.
            Err(_) => return true,
        };
        let Some(route) = routes.by_token.get(&token) else {
            return false;
        };
        let route_id = route.id;
        let expected_peer = route.expected_peer;
        let generation = route.generation;
        let already_registered = route.sources.contains(&source);
        let sender = route.sender.clone();
        if let Some(peer) = expected_peer
            && !already_registered
        {
            if route.sources.len() >= MAX_PUNCH_SOURCES_PER_ROUTE
                || routes.source_count >= MAX_AUTHORIZED_PUNCH_SOURCES
            {
                return true;
            }
            routes
                .by_token
                .get_mut(&token)
                .expect("route was checked above")
                .sources
                .insert(source);
            routes
                .by_source
                .entry(source)
                .or_default()
                .push(AuthorizedPunchSource {
                    peer,
                    generation,
                    route_id,
                });
            routes.source_count += 1;
        }
        drop(routes);
        let _ = sender.try_send(source);
        true
    }

    fn claim_authorized_peer(&self, source: SocketAddr) -> Option<(crate::identity::NodeId, u64)> {
        let mut routes = self.routes.lock().ok()?;
        let authorizations = routes.by_source.get(&source)?;
        let mut active_authorizations = authorizations.iter().filter(|authorization| {
            routes
                .by_token
                .values()
                .any(|route| route.id == authorization.route_id)
        });
        let authorization = *active_authorizations.next()?;
        // More than one live token advertised this source. Keep the entries so that
        // unregistering a stale route can make a later incoming QUIC connection
        // unambiguous instead of permanently consuming the authorization here.
        if active_authorizations.next().is_some() {
            return None;
        }

        if let Some(authorizations) = routes.by_source.remove(&source) {
            routes.source_count = routes.source_count.saturating_sub(authorizations.len());
        }
        for route in routes.by_token.values_mut() {
            route.sources.remove(&source);
        }
        Some((authorization.peer, authorization.generation))
    }

    fn unregister(&self, token: &[u8; 16], id: u64) {
        if let Ok(mut routes) = self.routes.lock()
            && routes
                .by_token
                .get(token)
                .is_some_and(|route| route.id == id)
            && let Some(route) = routes.by_token.remove(token)
        {
            for source in route.sources {
                if let Some(mut authorizations) = routes.by_source.remove(&source) {
                    let old_len = authorizations.len();
                    authorizations.retain(|authorization| authorization.route_id != id);
                    let removed = old_len - authorizations.len();
                    routes.source_count = routes.source_count.saturating_sub(removed);
                    if authorizations.is_empty() {
                        continue;
                    }
                    routes.by_source.insert(source, authorizations);
                }
            }
        }
    }
}

/// Receives validated sources for one punch token. Dropping it unregisters that token.
#[derive(Debug)]
pub struct PunchProbeReceiver {
    token: [u8; 16],
    id: u64,
    router: PunchRouter,
    receiver: mpsc::Receiver<SocketAddr>,
}

impl PunchProbeReceiver {
    pub async fn recv(&mut self) -> Option<SocketAddr> {
        self.receiver.recv().await
    }
}

impl Drop for PunchProbeReceiver {
    fn drop(&mut self) {
        self.router.unregister(&self.token, self.id);
    }
}

/// Build a bidirectional QUIC endpoint and a probe sender over one bound UDP socket.
///
/// Quinn remains the only receive owner. Its adapter consumes only exact-size punch
/// probes whose random token has an active registration; every other datagram is passed
/// to Quinn unchanged.
pub fn endpoint_from_socket_with_punch_dispatcher(
    socket: std::net::UdpSocket,
) -> Result<(Endpoint, PunchSocketHandle)> {
    install_crypto_provider();
    socket
        .set_nonblocking(true)
        .map_err(|err| Error::Transport(format!("设置非阻塞失败: {err}")))?;
    let io = Arc::new(
        UdpSocket::from_std(socket)
            .map_err(|err| Error::Transport(format!("接管 UDP socket 失败: {err}")))?,
    );
    let router = PunchRouter::default();
    let state = quinn::udp::UdpSocketState::new((&*io).into())
        .map_err(|err| Error::Transport(format!("初始化 QUIC UDP 状态失败: {err}")))?;
    let adapter: Arc<dyn AsyncUdpSocket> = Arc::new(PunchAwareUdpSocket {
        io: Arc::clone(&io),
        state,
        router: router.clone(),
    });
    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Transport("当前没有可用的异步运行时".into()))?;
    let mut endpoint = endpoint_from_abstract_socket(adapter, runtime)?;
    endpoint.set_default_client_config(client_config()?);
    Ok((endpoint, PunchSocketHandle { io, router }))
}

fn endpoint_from_abstract_socket(
    socket: Arc<dyn AsyncUdpSocket>,
    runtime: Arc<dyn Runtime>,
) -> Result<Endpoint> {
    let config = server_config()?;
    Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )
    .map_err(|err| Error::Transport(format!("用已有 socket 创建 QUIC 端点失败: {err}")))
}

#[derive(Debug)]
struct PunchAwareUdpSocket {
    io: Arc<UdpSocket>,
    state: quinn::udp::UdpSocketState,
    router: PunchRouter,
}

impl PunchAwareUdpSocket {
    fn filter_probes(
        &self,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
        received: usize,
    ) -> io::Result<usize> {
        let mut output = 0;
        for input in 0..received {
            let original = metadata[input];
            if original.len == 0 {
                continue; // A legal empty UDP datagram is not an endpoint I/O error.
            }
            if original.stride == 0 || original.len > buffers[input].len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "QUIC UDP receive metadata is invalid",
                ));
            }

            let mut read_offset = 0;
            let mut write_offset = 0;
            let mut kept = 0usize;
            let mut final_len = 0usize;
            while read_offset < original.len {
                let packet_len = (original.len - read_offset).min(original.stride);
                let packet_end = read_offset + packet_len;
                let source = original.addr;
                let routed = self
                    .router
                    .route_datagram(&buffers[input][read_offset..packet_end], source);
                if !routed {
                    if read_offset != write_offset {
                        buffers[input].copy_within(read_offset..packet_end, write_offset);
                    }
                    write_offset += packet_len;
                    kept += 1;
                    final_len = packet_len;
                }
                read_offset += original.stride;
            }

            if kept == 0 {
                continue;
            }
            if input != output {
                let (before, after) = buffers.split_at_mut(input);
                before[output][..write_offset].copy_from_slice(&after[0][..write_offset]);
            }
            let mut kept_metadata = original;
            kept_metadata.len = write_offset;
            if kept == 1 {
                kept_metadata.stride = final_len;
            }
            metadata[output] = kept_metadata;
            output += 1;
        }
        Ok(output)
    }
}

impl AsyncUdpSocket for PunchAwareUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PunchUdpPoller {
            io: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.state.try_send((&*self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        for _ in 0..32 {
            ready!(self.io.poll_recv_ready(cx))?;
            let received = match self.io.try_io(Interest::READABLE, || {
                self.state.recv((&*self.io).into(), buffers, metadata)
            }) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match self.filter_probes(buffers, metadata, received) {
                Ok(0) => continue,
                Ok(remaining) => return Poll::Ready(Ok(remaining)),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
}

#[derive(Debug)]
struct PunchUdpPoller {
    io: Arc<UdpSocket>,
}

impl UdpPoller for PunchUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }
}

/// 创建服务端端点，绑定到 `bind`。
pub fn server_endpoint(bind: SocketAddr) -> Result<Endpoint> {
    install_crypto_provider();
    Endpoint::server(server_config()?, bind)
        .map_err(|err| Error::Transport(format!("绑定 {bind} 失败: {err}")))
}

/// 创建客户端端点，绑定到 `bind`（通常写 `0.0.0.0:0`）。
pub fn client_endpoint(bind: SocketAddr) -> Result<Endpoint> {
    install_crypto_provider();
    let mut endpoint = Endpoint::client(bind)
        .map_err(|err| Error::Transport(format!("绑定 {bind} 失败: {err}")))?;
    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}

/// 连到 `remote`。`server_name` 只用于 TLS SNI，因为不校验证书，随便传。
pub async fn connect(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
) -> Result<quinn::Connection> {
    let connecting = endpoint
        .connect(remote, server_name)
        .map_err(|err| Error::Transport(format!("发起连接到 {remote} 失败: {err}")))?;

    connecting
        .await
        .map_err(|err| Error::Transport(format!("与 {remote} 建立连接失败: {err}")))
}

/// **不安全**的证书校验器：一律放行。
///
/// 见本模块顶部的说明——身份确认靠应用层握手，不靠证书链。
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::nat::punch::{PunchToken, probe_packet};
    use crate::protocol::frame::{read_frame, write_frame};
    use crate::protocol::message::ControlMessage;
    use crate::transport::handshake::{handshake_initiator, handshake_responder};

    #[test]
    fn 加密后端可以重复安装() {
        install_crypto_provider();
        install_crypto_provider();
    }

    #[test]
    fn 传输参数合法() {
        // 字段是 crate 私有的，只能确认构造本身不失败。
        assert!(transport_config().is_ok());
    }

    #[tokio::test]
    async fn 端点保持原有本地端口() {
        // 这是打洞能生效的前提：交给 QUIC 的必须是刚打过洞的那个本地端口，
        // 换了端口就等于换了 NAT 映射，洞白打。
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let expected = socket.local_addr().unwrap();
        let endpoint = endpoint_from_socket(socket).unwrap();
        assert_eq!(
            endpoint.local_addr().unwrap(),
            expected,
            "必须复用同一个本地端口"
        );
    }

    #[tokio::test]
    async fn punch_filter_preserves_quic_segments_and_ignores_empty_udp() {
        let io = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let adapter = PunchAwareUdpSocket {
            state: quinn::udp::UdpSocketState::new((&*io).into()).unwrap(),
            io,
            router: PunchRouter::default(),
        };
        let token = PunchToken::random();
        let mut route = adapter.router.register(&token, None, 0).unwrap();
        let probe = probe_packet(&token);
        let quic = vec![0xc0; probe.len()];
        let mut batch = [probe.as_slice(), quic.as_slice(), probe.as_slice()].concat();
        let mut empty = [0; 256];
        let mut output = [0; 256];
        let source = "127.0.0.1:32123".parse().unwrap();
        let mut metadata = [quinn::udp::RecvMeta::default(); 3];
        metadata[0].addr = source;
        metadata[1].addr = source;
        metadata[1].len = batch.len();
        metadata[1].stride = probe.len();
        output[..3].copy_from_slice(b"xyz");
        metadata[2].addr = source;
        metadata[2].len = 3;
        metadata[2].stride = 3;
        let mut buffers = [
            IoSliceMut::new(&mut empty),
            IoSliceMut::new(&mut batch),
            IoSliceMut::new(&mut output),
        ];
        assert_eq!(
            adapter
                .filter_probes(&mut buffers, &mut metadata, 3)
                .unwrap(),
            2
        );
        assert_eq!(&buffers[0][..metadata[0].len], quic);
        assert_eq!(&buffers[1][..metadata[1].len], b"xyz");
        assert_eq!(route.recv().await, Some(source));
    }

    #[test]
    fn ambiguous_punch_source_cannot_authorize_wrong_peer_or_outlive_route() {
        let router = PunchRouter::default();
        let a = Identity::generate().node_id();
        let b = Identity::generate().node_id();
        let token_a = PunchToken::random();
        let token_b = PunchToken::random();
        let route_a = router.register(&token_a, Some(a), 1).unwrap();
        let route_b = router.register(&token_b, Some(b), 2).unwrap();
        let source = "127.0.0.1:32000".parse().unwrap();
        assert!(router.route_datagram(&probe_packet(&token_a), source));
        assert!(router.route_datagram(&probe_packet(&token_b), source));
        assert_eq!(router.claim_authorized_peer(source), None);
        drop(route_a);
        assert_eq!(router.claim_authorized_peer(source), Some((b, 2)));
        drop(route_b);
        assert!(!router.route_datagram(&probe_packet(&token_b), source));
        assert_eq!(router.claim_authorized_peer(source), None);
    }

    #[tokio::test]
    async fn quinn接收所有者只分发匹配令牌的打洞包() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let expected = socket.local_addr().unwrap();
        let (endpoint, punch) = endpoint_from_socket_with_punch_dispatcher(socket).unwrap();
        assert_eq!(endpoint.local_addr().unwrap(), expected);

        let token = PunchToken::from_bytes([0x24; 16]);
        let wrong_token = PunchToken::from_bytes([0x42; 16]);
        let expected_peer = Identity::generate().node_id();
        let generation = 11;
        let mut receiver = punch
            .register_peer_probe(&token, expected_peer, generation)
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        sender
            .send_to(&probe_packet(&wrong_token), expected)
            .await
            .unwrap();
        sender
            .send_to(b"P2PF-PUNCH/1 truncated", expected)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver.recv())
                .await
                .is_err()
        );
        assert_eq!(
            punch.claim_authorized_peer(sender.local_addr().unwrap()),
            None
        );

        sender
            .send_to(&probe_packet(&token), expected)
            .await
            .unwrap();
        let source = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("匹配令牌的包应由 Quinn 的唯一接收所有者分发")
            .expect("令牌接收者仍应处于注册状态");
        assert_eq!(source, sender.local_addr().unwrap());
        assert_eq!(
            punch.claim_authorized_peer(source),
            Some((expected_peer, generation))
        );

        drop(receiver);
        endpoint.close(0u32.into(), b"test complete");
        endpoint.wait_idle().await;
    }

    #[tokio::test]
    async fn 关闭连接并释放端点后固定端口可以重新绑定() {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);

        let server = server_endpoint(bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_for_accept = server.clone();
        let server_accept = tokio::spawn(async move {
            server_for_accept
                .accept()
                .await
                .expect("服务端应接受连接")
                .await
                .expect("服务端 QUIC 握手应成功")
        });
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let server_connection = server_accept.await.unwrap();

        connection.close(0u32.into(), b"release");
        server_connection.close(0u32.into(), b"release");
        connection.closed().await;
        server_connection.closed().await;
        drop(server_connection);
        drop(connection);
        server.close(0u32.into(), b"release endpoint");
        client.wait_idle().await;
        server.wait_idle().await;
        drop(client);
        drop(server);
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }

        let rebound = server_endpoint(bind).expect("固定端口必须在完整释放后重新绑定");
        rebound.close(0u32.into(), b"done");
        rebound.wait_idle().await;
    }

    #[tokio::test]
    async fn 用现成_socket_建的端点能连上() {
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = endpoint_from_socket(server_socket).unwrap();

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = endpoint_from_socket(client_socket).unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("应当收到连接");
            let connection = incoming.await.expect("握手应当成功");

            let (mut send, mut recv) = connection.accept_bi().await.expect("应当收到流");
            let request = read_frame(&mut recv).await.unwrap().unwrap();
            assert_eq!(request, ControlMessage::KeepAlive);

            write_frame(&mut send, &ControlMessage::Ready)
                .await
                .unwrap();
            send.finish().unwrap();

            connection.closed().await;
            server.wait_idle().await;
        });

        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_frame(&mut send, &ControlMessage::KeepAlive)
            .await
            .unwrap();

        assert_eq!(
            read_frame(&mut recv).await.unwrap().unwrap(),
            ControlMessage::Ready
        );

        connection.close(0u32.into(), b"bye");
        client.wait_idle().await;
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn 端点能在环回地址上收发数据() {
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("应当收到连接");
            let connection = incoming.await.expect("握手应当成功");

            let (mut send, mut recv) = connection.accept_bi().await.expect("应当收到流");
            let request = read_frame(&mut recv).await.unwrap().unwrap();
            assert_eq!(request, ControlMessage::RequestChunk { index: 5 });

            write_frame(
                &mut send,
                &ControlMessage::Chunk {
                    index: 5,
                    data: b"hello from server".to_vec(),
                },
            )
            .await
            .unwrap();
            send.finish().unwrap();

            // 等客户端确认收到，避免连接被提前关掉。
            connection.closed().await;
            server.wait_idle().await;
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_frame(&mut send, &ControlMessage::RequestChunk { index: 5 })
            .await
            .unwrap();

        let response = read_frame(&mut recv).await.unwrap().unwrap();
        match response {
            ControlMessage::Chunk { index, data } => {
                assert_eq!(index, 5);
                assert_eq!(data, b"hello from server");
            }
            other => panic!("意料之外的消息: {other:?}"),
        }

        connection.close(0u32.into(), b"bye");
        client.wait_idle().await;
        server_task.await.unwrap();
    }

    /// 同一条 QUIC/TLS 会话上，两侧导出的绑定值必须一致，握手才能成功。
    ///
    /// 这是 channel binding 的基本前提：TLS exporter 是对称的。若两侧拿到的
    /// 绑定值不同，签名载荷就不同，正常握手都会被拒。
    #[tokio::test]
    async fn 同一条连接两侧绑定值一致且能完成握手() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_id = bob.node_id();

        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("应当收到连接");
            let connection = incoming.await.expect("握手应当成功");

            // 绑定值只能从当前会话导出，双方各导一份。
            let binding = ChannelBinding::from_connection(&connection).expect("导出绑定值");
            let (mut send, mut recv) = connection.accept_bi().await.expect("应当收到握手流");
            let outcome = handshake_responder(&mut send, &mut recv, &bob, &binding)
                .await
                .expect("接收方认证应当成功");
            let _ = send.finish();

            connection.closed().await;
            server.wait_idle().await;
            (binding, outcome)
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let client_binding = ChannelBinding::from_connection(&connection).expect("导出绑定值");

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let outcome = handshake_initiator(&mut send, &mut recv, &alice, &client_binding)
            .await
            .expect("发起方认证应当成功");
        let _ = send.finish();

        connection.close(0u32.into(), b"bye");
        client.wait_idle().await;

        let (server_binding, server_outcome) = server_task.await.unwrap();

        assert_eq!(
            client_binding.as_bytes(),
            server_binding.as_bytes(),
            "同一条连接两侧导出的绑定值必须一致"
        );
        assert_eq!(outcome.peer_node_id, bob_id);
        assert_eq!(server_outcome.peer_node_id, alice.node_id());
    }

    /// 两条不同的 QUIC/TLS 会话必须导出不同的绑定值。
    ///
    /// 这是防透明 MITM 的核心：攻击者的 A↔M、M↔B 是两条独立会话，绑定值不同，
    /// 原样转发的签名必然验不过。
    #[tokio::test]
    async fn 不同连接导出的绑定值不同() {
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let first = server.accept().await.expect("应当收到第一条连接");
            let first = first.await.expect("第一条握手应当成功");
            let first_binding = ChannelBinding::from_connection(&first).expect("导出第一条绑定值");

            let second = server.accept().await.expect("应当收到第二条连接");
            let second = second.await.expect("第二条握手应当成功");
            let second_binding =
                ChannelBinding::from_connection(&second).expect("导出第二条绑定值");

            first.closed().await;
            second.closed().await;
            server.wait_idle().await;
            (first_binding, second_binding)
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let first = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let first_binding = ChannelBinding::from_connection(&first).expect("导出绑定值");
        let second = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let second_binding = ChannelBinding::from_connection(&second).expect("导出绑定值");

        assert_ne!(
            first_binding.as_bytes(),
            second_binding.as_bytes(),
            "不同会话必须导出不同的绑定值"
        );

        first.close(0u32.into(), b"bye");
        second.close(0u32.into(), b"bye");
        client.wait_idle().await;

        let (server_first, server_second) = server_task.await.unwrap();
        assert_eq!(
            first_binding.as_bytes(),
            server_first.as_bytes(),
            "第一条连接两侧绑定值必须一致"
        );
        assert_eq!(
            second_binding.as_bytes(),
            server_second.as_bytes(),
            "第二条连接两侧绑定值必须一致"
        );
        assert_ne!(
            server_first.as_bytes(),
            server_second.as_bytes(),
            "服务端侧两条会话的绑定值也必须不同"
        );
    }
}
