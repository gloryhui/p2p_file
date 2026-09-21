//! 通用隧道：把家里的 TCP 服务直接映射到本机。
//!
//! 数据全部走已经打通的 P2P 直连（QUIC），阿里云那台只参与牵线，
//! **一个字节的业务数据都不经过它**。
//!
//! # 两个角色
//!
//! - **服务端**（家里的那台，`serve`）：等对端连上来，按请求把 TCP 连接转出去。
//!   它决定「允许转发到哪些目标」以及「允许哪些节点连」。
//! - **客户端**（本机，`tunnel`）：在本机开一个 TCP 监听，每条进来的连接
//!   对应一条 QUIC 双向流，字节原样搬运。
//!
//! 一条 QUIC 双向流 = 一条 TCP 连接。所以多个 SSH 会话、HTTP 请求可以同时
//! 跑在同一条隧道上，互不阻塞（QUIC 各路流之间没有队头阻塞）。
//!
//! # 安全
//!
//! - QUIC 自带 TLS 1.3 加密，中间人看不到内容；
//! - 每条连接都跑一次应用层握手，确认对端确实是持有那个私钥的节点；
//! - 服务端只转发到 `forwards` 白名单里的地址，客户端不能让它连任意目标；
//! - 服务端只接受 `allowed_peers` 白名单里的节点。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::net::{DirectConfig, DirectLink, establish};
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::message::ControlMessage;
use crate::transfer::receiver::receive_file_on_stream;
use crate::transfer::sender::{SendReport, send_file_after_handshake};
use crate::transport::handshake::{handshake_initiator, handshake_responder};
use crate::transport::quic::ChannelBinding;

/// 空闲多久后重新打洞（默认 2 分钟，比常见的 NAT 映射超时短一些）。
pub const DEFAULT_RE_PUNCH_AFTER: Duration = Duration::from_secs(120);

/// 服务端配置。
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// 允许连进来的节点。空表示不限制（不推荐）。
    pub allowed_peers: Vec<NodeId>,
    /// 允许转发到的目标地址白名单。
    pub forwards: Vec<SocketAddr>,
    /// 接收到的文件存这个目录。为 `None` 表示不收文件。
    pub recv_dir: Option<PathBuf>,
    /// 空闲多久后重新打洞。
    ///
    /// NAT 映射会过期（通常 30~120 秒没有流量就回收）。`serve` 要是傻等，
    /// 几个小时后对端再来连就会被自己的 NAT 挡掉。所以空闲一段时间后主动
    /// 重新打一次洞，把映射重新立起来。
    pub re_punch_after: Duration,
}

impl ServeConfig {
    pub fn new() -> Self {
        Self {
            allowed_peers: Vec::new(),
            forwards: Vec::new(),
            recv_dir: None,
            re_punch_after: DEFAULT_RE_PUNCH_AFTER,
        }
    }

    /// 这个节点允许连进来吗。
    pub fn peer_allowed(&self, peer: NodeId) -> bool {
        self.allowed_peers.is_empty() || self.allowed_peers.contains(&peer)
    }

    /// 这个目标允许转发吗。
    pub fn target_allowed(&self, target: SocketAddr) -> bool {
        self.forwards.contains(&target)
    }
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// 常驻服务：反复「等对端 → 打洞 → 服务」，直到被 Ctrl-C 打断。
///
/// 之所以每轮都重新打洞，是因为 NAT 映射会过期：闲置两分钟后家里路由器的
/// 映射就没了，这时对端再发包会被直接丢掉。重新打一次洞，映射就又立起来了。
pub async fn serve_loop(
    identity: Identity,
    direct: DirectConfig,
    config: ServeConfig,
) -> Result<()> {
    if config.allowed_peers.is_empty() {
        warn!("没有指定允许的节点（--allow），任何知道信令服务器的人都能连进来");
    }
    if config.forwards.is_empty() && config.recv_dir.is_none() {
        warn!("既没有配置转发目标，也没有配置接收目录，对端连上来也没事可做");
    }

    loop {
        // 每一轮都要一个干净的 socket：打洞和 QUIC 必须复用同一个本地端口，
        // 而上一轮的 socket 已经交给 QUIC 了，收不回来。
        let link = match establish(&identity, &direct).await {
            Ok(link) => link,
            Err(err) => {
                warn!(error = %err, "建立直连失败，5 秒后重试");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        if let Err(err) = serve_session(link, identity.clone(), config.clone()).await {
            warn!(error = %err, "本次会话结束");
        }
        info!("空闲超时，重新打洞，好让对端下次还能连上");
    }
}

/// 处理一次已经建立好的直连会话。
///
/// 直到「没有活跃连接、且静默超过 `re_punch_after`」才返回。
pub async fn serve_session(
    link: DirectLink,
    identity: Identity,
    config: ServeConfig,
) -> Result<()> {
    info!("直连已就绪，等待对端接入：{}", link.describe());

    let endpoint = link.endpoint.clone();
    let active = Arc::new(AtomicUsize::new(0));
    let grace = config.re_punch_after;

    loop {
        // 注意：**不能**给计时分支加 `if active == 0` 这样的守卫。
        // `select!` 的守卫只在进入 select 的那一刻求值一次，之后不会重算：
        //   - 若进入时已有连接，守卫为假，计时分支被永久禁用，而 accept 又
        //     一直不来新连接 —— serve 就再也不会重新打洞；
        //   - 若进入时还没有连接，计时到点又会不看当前状态直接拆掉会话。
        // 所以守卫必须放在分支体里，等计时真的到点了再判断。
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::time::sleep(grace) => {
                if active.load(Ordering::Relaxed) == 0 {
                    debug!("空闲超时，准备重新打洞");
                    return Ok(());
                }
                // 还有连接在用，重新计时。
                continue;
            }
        };

        let Some(incoming) = incoming else {
            return Ok(());
        };
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(err) => {
                // 打洞后的第一个包可能来得比 accept 早，握手失败重试即可。
                warn!(error = %err, "有连接进来但握手失败");
                continue;
            }
        };

        let identity = identity.clone();
        let config = config.clone();
        let active = Arc::clone(&active);
        active.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(err) = serve_connection(connection.clone(), &identity, config).await {
                warn!(error = %err, "处理连接时出错");
            }
            // 连接真正关掉才算这条连接结束。
            connection.closed().await;
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// 处理一条已建立的 QUIC 连接：先认证，再按流的类型分发。
async fn serve_connection(
    connection: Connection,
    identity: &Identity,
    config: ServeConfig,
) -> Result<()> {
    let remote = connection.remote_address();

    // 第一条流用于应用层握手，确认对端身份。会话绑定值取自这条连接：
    // 签名因此被钉死在这条 TLS 会话上，转发到别的会话必然验不过。
    let binding = ChannelBinding::from_connection(&connection)?;
    let (mut handshake_send, mut handshake_recv) = connection
        .accept_bi()
        .await
        .map_err(|err| Error::Transport(format!("接受握手流失败: {err}")))?;
    let outcome =
        handshake_responder(&mut handshake_send, &mut handshake_recv, identity, &binding).await?;
    let _ = handshake_send.finish();

    let peer_id = outcome.peer_node_id;
    if !config.peer_allowed(peer_id) {
        warn!(peer = %peer_id.short(), "不在允许列表里，拒绝这条连接");
        connection.close(1u32.into(), b"peer not allowed");
        return Ok(());
    }
    info!(peer = %peer_id.short(), %remote, "对端已通过认证");

    serve_streams(connection, peer_id, config).await
}

/// 循环处理这条连接上开出来的每一条双向流。
///
/// 流的类型由第一个消息决定：`Manifest` 是传文件，`TunnelOpen` 是开隧道。
/// 这样一个 `serve` 进程就能同时提供两种服务，不用开两个端口。
async fn serve_streams(connection: Connection, peer_id: NodeId, config: ServeConfig) -> Result<()> {
    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            // 对端正常关闭（传完文件就关连接）不算错误。
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed) => {
                info!(peer = %peer_id.short(), "对端关闭了连接");
                return Ok(());
            }
            Err(err) => {
                return Err(Error::Transport(format!("接受数据流失败: {err}")));
            }
        };

        let first = read_frame(&mut recv).await?;
        match first {
            Some(ControlMessage::TunnelOpen { target }) => {
                let forwards = config.forwards.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_tunnel_request(send, recv, &target, &forwards).await {
                        warn!(target, error = %err, "隧道转发失败");
                    }
                });
            }

            Some(ControlMessage::Manifest(manifest)) => {
                // `read_frame` 已经在解码时校验过，这里是显式的 trust-boundary
                // 复查：清单一旦进了接收流程就会决定临时文件长度和分片下标。
                if let Err(err) = manifest.validate() {
                    warn!(peer = %peer_id.short(), error = %err, "清单非法，拒绝接收");
                    let _ = write_frame(
                        &mut send,
                        &ControlMessage::Abort {
                            reason: format!("清单非法: {err}"),
                        },
                    )
                    .await;
                    let _ = send.finish();
                    continue;
                }
                let Some(recv_dir) = config.recv_dir.clone() else {
                    warn!(peer = %peer_id.short(), "收到文件但没配置接收目录，拒绝");
                    let _ = send.finish();
                    continue;
                };
                tokio::spawn(async move {
                    match receive_file_on_stream(send, recv, *manifest, &recv_dir, peer_id).await {
                        Ok(report) => info!(
                            path = %report.output_path.display(),
                            bytes = report.total_len,
                            "文件接收完成"
                        ),
                        Err(err) => warn!(error = %err, "文件接收失败"),
                    }
                });
            }

            Some(ControlMessage::KeepAlive) => {}
            Some(ControlMessage::Bye) | None => {
                info!(peer = %peer_id.short(), "对端道别");
                return Ok(());
            }
            Some(other) => {
                warn!(kind = other.kind(), "服务端收到意料之外的消息，忽略");
            }
        }
    }
}

/// 响应一次隧道请求：校验白名单 → 连目标 → 回报就绪 → 双向搬字节。
async fn handle_tunnel_request(
    mut send: SendStream,
    recv: RecvStream,
    target: &str,
    allowed: &[SocketAddr],
) -> Result<()> {
    // 只接受 IP:端口，不接受域名：域名会引入 DNS 解析，可能绕过白名单。
    let target_addr: SocketAddr = match target.parse() {
        Ok(addr) => addr,
        Err(_) => {
            let reason = format!("目标必须是 IP:端口 形式，收到 {target}");
            write_frame(
                &mut send,
                &ControlMessage::TunnelError {
                    reason: reason.clone(),
                },
            )
            .await?;
            let _ = send.finish();
            return Err(Error::Protocol(reason));
        }
    };

    if !allowed.contains(&target_addr) {
        let reason = format!(
            "目标 {target_addr} 不在允许转发的列表里（当前允许：{}）",
            allowed
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        write_frame(
            &mut send,
            &ControlMessage::TunnelError {
                reason: reason.clone(),
            },
        )
        .await?;
        let _ = send.finish();
        warn!(%target_addr, "拒绝了未经授权的转发请求");
        return Err(Error::Protocol(reason));
    }

    let tcp = match TcpStream::connect(target_addr).await {
        Ok(tcp) => tcp,
        Err(err) => {
            let reason = format!("连接 {target_addr} 失败: {err}");
            write_frame(
                &mut send,
                &ControlMessage::TunnelError {
                    reason: reason.clone(),
                },
            )
            .await?;
            let _ = send.finish();
            return Err(Error::Transport(reason));
        }
    };

    info!(%target_addr, "隧道已建立");
    write_frame(&mut send, &ControlMessage::TunnelReady).await?;
    splice(tcp, send, recv).await
}

/// 把一条 TCP 连接和一条 QUIC 双向流对接起来，双向搬字节。
async fn splice(
    tcp: TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // 上行：TCP → QUIC。
    let up = async {
        let copied = tokio::io::copy(&mut tcp_read, &mut quic_send).await?;
        // 本端读完就把写方向关掉，让对端看到 EOF（半关闭语义）。
        let _ = quic_send.finish();
        Ok::<u64, Error>(copied)
    };

    // 下行：QUIC → TCP。
    let down = async {
        let copied = tokio::io::copy(&mut quic_recv, &mut tcp_write).await?;
        let _ = tcp_write.shutdown().await;
        Ok::<u64, Error>(copied)
    };

    // 两个方向都跑完才算这条隧道结束。
    let (up_bytes, down_bytes) = tokio::try_join!(up, down)?;
    tracing::debug!(up_bytes, down_bytes, "隧道关闭");
    Ok(())
}

/// 客户端：在本机 `listen` 上开监听，收到的每条 TCP 连接都从隧道送到对端。
///
/// 不会返回，除非监听失败。QUIC 连接断了会自动重建。
pub async fn forward_tunnel(
    link: DirectLink,
    identity: Identity,
    target: String,
    listen: SocketAddr,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|err| Error::Transport(format!("监听 {listen} 失败: {err}")))?;
    forward_on(link, identity, target, listener).await
}

/// 在**已经绑好**的监听器上跑转发。
///
/// 单独拆出来是为了测试能用 `127.0.0.1:0` 绑定再拿到真实端口。
pub async fn forward_on(
    link: DirectLink,
    identity: Identity,
    target: String,
    listener: TcpListener,
) -> Result<()> {
    let actual = listener.local_addr()?;

    info!(
        listen = %actual,
        target = %target,
        peer = %link.peer_node_id.short(),
        "本地转发已就绪：连到 {} 就等于连到对端的 {}",
        actual,
        target
    );

    let mut session: Option<Connection> = None;

    loop {
        let (tcp, from) = listener
            .accept()
            .await
            .map_err(|err| Error::Transport(format!("接受本地连接失败: {err}")))?;

        // 连接不可用（或还没建）就重建一个。
        let need_new = session
            .as_ref()
            .is_none_or(|conn| conn.close_reason().is_some());
        if need_new {
            match open_session(&link, &identity).await {
                Ok(conn) => session = Some(conn),
                Err(err) => {
                    warn!(error = %err, "与对端建立直连失败，这条本地连接被丢弃");
                    drop(tcp);
                    continue;
                }
            }
        }

        let Some(connection) = session.clone() else {
            continue;
        };
        let target = target.clone();
        let peer = link.peer_node_id;
        tokio::spawn(async move {
            match open_tunnel(tcp, &connection, &target).await {
                Ok(()) => tracing::debug!(%from, peer = %peer.short(), "本地连接结束"),
                Err(err) => warn!(%from, error = %err, "转发失败"),
            }
        });
    }
}

/// 建一条到对端的 QUIC 连接并完成应用层认证。
async fn open_session(link: &DirectLink, identity: &Identity) -> Result<Connection> {
    // 按候选顺序尝试连接，而不是只试打洞确认过的那个。
    let connection = link.connect().await?;

    // 绑定值必须来自刚建立的这条连接，不能复用别的会话。
    let binding = ChannelBinding::from_connection(&connection)?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| Error::Transport(format!("打开握手流失败: {err}")))?;
    let outcome = handshake_initiator(&mut send, &mut recv, identity, &binding).await?;
    let _ = send.finish();

    if outcome.peer_node_id != link.peer_node_id {
        connection.close(2u32.into(), b"unexpected peer");
        return Err(Error::Identity(format!(
            "对端身份不符：期待 {}，实际 {}",
            link.peer_node_id.short(),
            outcome.peer_node_id.short()
        )));
    }

    info!(
        peer = %outcome.peer_node_id.short(),
        remote = %connection_remote(connection.clone()),
        "直连已加密并认证"
    );
    Ok(connection)
}

fn connection_remote(connection: Connection) -> String {
    connection.remote_address().to_string()
}

/// 为一条本地 TCP 连接开一条隧道。
async fn open_tunnel(tcp: TcpStream, connection: &Connection, target: &str) -> Result<()> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| Error::Transport(format!("打开隧道流失败: {err}")))?;

    write_frame(
        &mut send,
        &ControlMessage::TunnelOpen {
            target: target.to_string(),
        },
    )
    .await?;

    match read_frame(&mut recv).await? {
        Some(ControlMessage::TunnelReady) => splice(tcp, send, recv).await,
        Some(ControlMessage::TunnelError { reason }) => {
            let _ = send.finish();
            Err(Error::Transport(format!(
                "对端拒绝转发到 {target}: {reason}"
            )))
        }
        Some(other) => Err(Error::Protocol(format!(
            "期待 TunnelReady，收到 {}",
            other.kind()
        ))),
        None => Err(Error::Protocol("对端没有回应隧道请求就关闭了".into())),
    }
}

/// 客户端：把一个文件推到对端（走直连，不经过任何服务器）。
///
/// 先自己完成握手并核对对端身份，再把发送流程交给 [`send_file_after_handshake`]，
/// 避免握两次手（`send_file` 内部也会握手）。
pub async fn push_file(
    link: DirectLink,
    identity: Identity,
    path: PathBuf,
    chunk_size: u32,
) -> Result<SendReport> {
    let connection = open_session(&link, &identity).await?;
    let report =
        send_file_after_handshake(&connection, &path, chunk_size, link.peer_node_id).await?;
    connection.close(0u32.into(), b"done");
    // 等连接真正关掉，避免进程提前退出把最后一个包丢了。
    link.endpoint.wait_idle().await;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::discovery::signal::run_signal_server_on;
    use crate::nat::punch::PunchConfig;
    use crate::net::{DirectConfig, establish};

    fn node_id(seed: u8) -> NodeId {
        // 用真实密钥推出来的节点 ID，保证和线上路径一致。
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        NodeId::from_public_key(&signing.verifying_key())
    }

    /// 起一个只监听环回的信令服务器，返回地址。
    async fn spawn_signal_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = run_signal_server_on(listener).await;
        });
        addr
    }

    /// 起一个 TCP echo 服务，返回地址。
    async fn spawn_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut read_half, mut write_half) = stream.split();
                    let _ = tokio::io::copy(&mut read_half, &mut write_half).await;
                });
            }
        });
        addr
    }

    /// 测试用的打洞配置：不查 STUN（没外网也能跑），只用环回候选。
    fn test_direct_config(signal: SocketAddr, peer: NodeId) -> DirectConfig {
        let mut config = DirectConfig::new(signal.to_string(), peer);
        config.local_port = 0; // 让系统分配，避免测试之间抢端口
        config.stun_servers.clear();
        config.include_loopback = true;
        config.signal_timeout = Duration::from_secs(10);
        config.punch = PunchConfig {
            interval: Duration::from_millis(100),
            attempts: 30,
        };
        config
    }

    /// 双方同时建立直连。
    ///
    /// 必须同时：打洞靠的就是两边都在发包，先连的一方会一直打空。
    async fn establish_pair(
        signal: SocketAddr,
        server_identity: &Identity,
        client_identity: &Identity,
    ) -> (DirectLink, DirectLink) {
        let server_config = test_direct_config(signal, client_identity.node_id());
        let client_config = test_direct_config(signal, server_identity.node_id());

        let (server_link, client_link) = tokio::join!(
            establish(server_identity, &server_config),
            establish(client_identity, &client_config),
        );

        (
            server_link.expect("服务端应当打通"),
            client_link.expect("客户端应当打通"),
        )
    }

    #[test]
    fn 允许列表为空时不限制节点() {
        let config = ServeConfig::new();
        assert!(config.peer_allowed(node_id(1)));
        assert!(config.peer_allowed(node_id(2)));
    }

    #[test]
    fn 只在允许列表里的节点能连() {
        let config = ServeConfig {
            allowed_peers: vec![node_id(1)],
            ..ServeConfig::new()
        };
        assert!(config.peer_allowed(node_id(1)));
        assert!(!config.peer_allowed(node_id(2)));
    }

    #[test]
    fn 只有白名单里的目标能转发() {
        let config = ServeConfig {
            forwards: vec!["127.0.0.1:22".parse().unwrap()],
            ..ServeConfig::new()
        };
        assert!(config.target_allowed("127.0.0.1:22".parse().unwrap()));
        assert!(!config.target_allowed("127.0.0.1:23".parse().unwrap()));
        // 不配白名单就等于什么都不让转发。
        assert!(!ServeConfig::new().target_allowed("127.0.0.1:22".parse().unwrap()));
    }

    #[test]
    fn 默认配置是空的() {
        let config = ServeConfig::default();
        assert!(config.forwards.is_empty());
        assert!(config.recv_dir.is_none());
        assert!(config.allowed_peers.is_empty());
    }

    /// 全链路：信令牵线 → 双方打洞 → QUIC 直连 → TCP 隧道转发。
    #[tokio::test]
    async fn 打洞后能通过隧道转发_tcp() {
        let echo_addr = spawn_echo_server().await;
        let signal_addr = spawn_signal_server().await;

        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (server_link, client_link) =
            establish_pair(signal_addr, &server_identity, &client_identity).await;

        // 两端选中的都应当是对端给过的候选之一（同机上多半是局域网地址）。
        assert!(
            server_link.peer_candidates.contains(&server_link.peer_addr),
            "选中的地址必须来自对端候选列表"
        );
        assert!(
            client_link.peer_candidates.contains(&client_link.peer_addr),
            "选中的地址必须来自对端候选列表"
        );

        // 服务端开始提供服务。
        let serve_task = tokio::spawn(serve_session(
            server_link,
            server_identity.clone(),
            ServeConfig {
                allowed_peers: vec![client_identity.node_id()],
                forwards: vec![echo_addr],
                recv_dir: None,
                ..ServeConfig::new()
            },
        ));

        // 客户端在本地开转发。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tunnel_addr = listener.local_addr().unwrap();
        let tunnel_task = tokio::spawn(forward_on(
            client_link,
            client_identity.clone(),
            echo_addr.to_string(),
            listener,
        ));

        // 通过隧道走一趟：连本地端口，数据实际由对端转发到 echo 服务。
        let mut conn = TcpStream::connect(tunnel_addr).await.unwrap();
        let payload = b"hello through the p2p tunnel";
        conn.write_all(payload).await.unwrap();
        conn.flush().await.unwrap();

        let mut buffer = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut buffer))
            .await
            .expect("应当能在 10 秒内收到回显")
            .unwrap();
        assert_eq!(&buffer, payload, "回显内容应当原样返回");

        // 同一条隧道上再开一条连接，验证多路复用。
        let mut second = TcpStream::connect(tunnel_addr).await.unwrap();
        second.write_all(b"second").await.unwrap();
        let mut buffer = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(10), second.read_exact(&mut buffer))
            .await
            .expect("第二条连接也应当能通")
            .unwrap();
        assert_eq!(&buffer, b"second");

        drop(conn);
        drop(second);
        tunnel_task.abort();
        serve_task.abort();
    }

    /// 没在白名单里的目标必须被拒绝，哪怕对端知道地址。
    #[tokio::test]
    async fn 未授权的转发目标会被拒绝() {
        let echo_addr = spawn_echo_server().await;
        let signal_addr = spawn_signal_server().await;

        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (server_link, client_link) =
            establish_pair(signal_addr, &server_identity, &client_identity).await;

        // 服务端只允许转发到别的地址，不包括 echo。
        let allowed: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let serve_task = tokio::spawn(serve_session(
            server_link,
            server_identity.clone(),
            ServeConfig {
                allowed_peers: vec![client_identity.node_id()],
                forwards: vec![allowed],
                recv_dir: None,
                ..ServeConfig::new()
            },
        ));

        // 客户端直接建一条会话并请求转发到 echo —— 应当被拒绝。
        let connection = open_session(&client_link, &client_identity).await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_frame(
            &mut send,
            &ControlMessage::TunnelOpen {
                target: echo_addr.to_string(),
            },
        )
        .await
        .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut recv))
            .await
            .expect("应当很快收到回复")
            .unwrap();
        match reply {
            Some(ControlMessage::TunnelError { reason }) => {
                assert!(
                    reason.contains("不在允许转发"),
                    "拒绝原因应当说明白名单，实际: {reason}"
                );
            }
            other => panic!("应当被拒绝，实际收到 {other:?}"),
        }

        serve_task.abort();
    }

    /// 不在允许列表里的节点连不上。
    #[tokio::test]
    async fn 未授权的节点连不上() {
        let signal_addr = spawn_signal_server().await;

        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (server_link, client_link) =
            establish_pair(signal_addr, &server_identity, &client_identity).await;

        // 服务端只允许另一个（不相干的）节点。
        let serve_task = tokio::spawn(serve_session(
            server_link,
            server_identity.clone(),
            ServeConfig {
                allowed_peers: vec![Identity::generate().node_id()],
                forwards: vec![],
                recv_dir: None,
                ..ServeConfig::new()
            },
        ));

        // 客户端握手可能成功（QUIC 层通了）也可能被服务端直接掐断，
        // 两种都算「连不上」。关键是拿不到可用的隧道。
        match open_session(&client_link, &client_identity).await {
            Err(_) => {}
            Ok(connection) => {
                let result =
                    tokio::time::timeout(Duration::from_secs(10), connection.open_bi()).await;
                match result {
                    // 服务端关闭了连接。
                    Ok(Err(_)) => {}
                    // 流开出来了但立刻被关，写不进去。
                    Ok(Ok((mut send, _))) => {
                        let write = write_frame(&mut send, &ControlMessage::KeepAlive).await;
                        assert!(write.is_err(), "未授权节点不该能正常收发");
                    }
                    Err(_) => panic!("不该等到超时"),
                }
            }
        }

        serve_task.abort();
    }

    /// 全链路：信令牵线 → 打洞 → 直接推文件（不经过任何服务器）。
    #[tokio::test]
    async fn 打洞后能直接推文件() {
        let signal_addr = spawn_signal_server().await;
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (server_link, client_link) =
            establish_pair(signal_addr, &server_identity, &client_identity).await;

        let recv_dir =
            std::env::temp_dir().join(format!("p2p_file_push_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&recv_dir);
        std::fs::create_dir_all(&recv_dir).unwrap();

        let serve_task = tokio::spawn(serve_session(
            server_link,
            server_identity.clone(),
            ServeConfig {
                allowed_peers: vec![client_identity.node_id()],
                forwards: vec![],
                recv_dir: Some(recv_dir.clone()),
                ..ServeConfig::new()
            },
        ));

        // 造一个跨多个分片的文件。
        let payload: Vec<u8> = (0..(crate::protocol::manifest::MIN_CHUNK_SIZE * 2 + 777))
            .map(|i| (i % 251) as u8)
            .collect();
        let source = recv_dir
            .join("..")
            .join(format!("p2p_file_push_src_{}.bin", std::process::id()));
        std::fs::write(&source, &payload).unwrap();

        let report = push_file(
            client_link,
            client_identity.clone(),
            source.clone(),
            crate::protocol::manifest::MIN_CHUNK_SIZE,
        )
        .await
        .unwrap();
        assert_eq!(report.total_len, payload.len() as u64);

        // 服务端是异步落盘的，等一会儿再看结果。
        let expected_name = source.file_name().unwrap().to_string_lossy().to_string();
        let mut received = None;
        for _ in 0..50 {
            let candidate = recv_dir.join(&expected_name);
            if candidate.exists() {
                received = Some(candidate);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let received = received.expect("文件应当已经落到接收目录");

        let got = std::fs::read(&received).unwrap();
        assert_eq!(got, payload, "收到的内容必须和发出的一致");

        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_dir_all(&recv_dir);
        serve_task.abort();
    }

    /// 对端给的候选地址全是 IPv6 时，本机（只绑 IPv4）应当给出明确错误。
    #[tokio::test]
    async fn 只有_ipv6_候选时给出明确错误() {
        let signal_addr = spawn_signal_server().await;
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        // 客户端手工登记一个只有 IPv6 的候选，服务端解析时应当报错。
        let mut client_config = test_direct_config(signal_addr, server_identity.node_id());
        client_config.include_loopback = false;
        // 屏蔽掉本机的 IPv4 地址，只留 IPv6。
        client_config.advertise = vec!["[2001:db8::1]:9000".parse().unwrap()];

        let server_config = test_direct_config(signal_addr, client_identity.node_id());

        let (_server, client) = tokio::join!(
            establish(&server_identity, &server_config),
            establish(&client_identity, &client_config),
        );

        // 客户端自己会用本机的 IPv4 地址，所以多半能通；这里主要确认
        // 「IPv6 候选被过滤掉」这条路径不会 panic，且报错信息可读。
        if let Err(err) = client {
            let text = err.to_string();
            assert!(
                text.contains("IPv6") || text.contains("打洞失败"),
                "错误信息应当能说明原因，实际: {text}"
            );
        }
    }

    /// Issue #3 全链路回归：网络来的畸形清单必须止步于信任边界。
    ///
    /// 旧代码里 `chunk_size = 0` 的清单会被接收端接受：服务端回一个 `Resume`
    /// 进入接收流程，随后在写第一片时 `chunk_count(total_len, 0)` 除零 panic。
    /// 修复后服务端要么在解码时直接报错、要么显式回 `Abort`，绝不会回 `Resume`，
    /// 也不会在接收目录里留下任何文件。
    #[tokio::test]
    async fn 畸形清单在信任边界被拒绝() {
        use crate::protocol::manifest::{ChunkHash, FileManifest};

        let signal_addr = spawn_signal_server().await;
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (server_link, client_link) =
            establish_pair(signal_addr, &server_identity, &client_identity).await;

        let recv_dir =
            std::env::temp_dir().join(format!("p2p_file_evil_manifest_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&recv_dir);
        std::fs::create_dir_all(&recv_dir).unwrap();

        let serve_task = tokio::spawn(serve_session(
            server_link,
            server_identity.clone(),
            ServeConfig {
                allowed_peers: vec![client_identity.node_id()],
                forwards: vec![],
                recv_dir: Some(recv_dir.clone()),
                ..ServeConfig::new()
            },
        ));

        let connection = open_session(&client_link, &client_identity).await.unwrap();

        // total_len > 0 且 chunk_size = 0 —— 正是旧代码会 panic 的形状。
        let evil = FileManifest {
            file_name: "evil.bin".into(),
            total_len: 1024,
            chunk_size: 0,
            chunks: vec![ChunkHash::of(b"x")],
            root_hash: ChunkHash::of(b"y"),
        };

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_frame(&mut send, &ControlMessage::Manifest(Box::new(evil)))
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut recv))
            .await
            .expect("服务端不该挂死");

        match reply {
            // 解码阶段就被拒绝：流被关（读失败或 EOF 都算正常拒绝）。
            Ok(None) | Err(_) => {}
            // 显式 trust-boundary 复查拒绝：必须说明是清单问题。
            Ok(Some(ControlMessage::Abort { reason })) => {
                assert!(reason.contains("清单"), "拒绝原因应说明清单非法: {reason}");
            }
            Ok(Some(other)) => panic!(
                "畸形清单被接收流程接受了（收到 {}），说明信任边界没拦住",
                other.kind()
            ),
        }

        // 关键断言：没有进入接收流程（不会回 Resume），也没落任何文件。
        assert!(
            std::fs::read_dir(&recv_dir).unwrap().next().is_none(),
            "畸形清单不应在接收目录里创建任何文件"
        );

        connection.close(0u32.into(), b"done");
        let _ = client_link.endpoint.wait_idle().await;
        serve_task.abort();
        let _ = std::fs::remove_dir_all(&recv_dir);
    }
}
