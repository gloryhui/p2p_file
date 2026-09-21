//! 建立直连：STUN 探映射 → 信令换候选 → 同时打洞 → 把 socket 交给 QUIC。
//!
//! # 为什么全程只能用同一个 socket
//!
//! NAT 的映射是按「本地端口」分配的：`192.168.1.5:9000 → 203.0.113.7:41234`。
//! 打洞打的就是这条映射。所以从 STUN 探测、到发探测包打洞、再到之后跑 QUIC
//! 传数据，**必须自始至终是同一个本地端口**，否则就是另开一条映射，洞白打。
//!
//! 这也是要 [`crate::transport::quic::endpoint_from_socket`] 的原因：QUIC 得
//! 接受一个现成的 socket，而不是自己新绑一个。
//!
//! # 打洞能成功的前提
//!
//! 双方同时在发。NAT 只在**出站包**穿过时建立映射，所以两边都要主动往对方
//! 的候选地址发包，各自的 pinhole 才会在同一时间窗内打开。这也意味着家用
//! 路由器如果是对称型 NAT（用同一个本地端口访问不同目标会拿到不同公网端口），
//! 这套流程打不通，只能靠端口映射或中继。

use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::discovery::mdns::local_ip_addresses;
use crate::discovery::signal::{
    Candidate, PeerOffer, SignalingClient, dedup_candidates, sort_candidates,
};
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::nat::classify::{MappingBehavior, MappingEvidence, probe_rfc5780};
use crate::nat::punch::{PunchConfig, simultaneous_open_any};
use crate::nat::stun::resolve_server;
use crate::transport::quic::endpoint_from_socket;

/// 默认 STUN 服务器。
///
/// 选的都是国内可达性较好的；`stun.cloudflare.com` 是兜底（它在国内不一定通）。
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.miwifi.com:3478",
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// 建立直连所需的参数。
#[derive(Clone, Debug)]
pub struct DirectConfig {
    /// 信令服务器地址（阿里云那台）。
    pub signal_server: String,
    /// 对端节点 ID。
    pub peer: NodeId,
    /// 本机打洞用的 UDP 端口。0 表示让系统随便选一个。
    ///
    /// 固定端口有个好处：NAT 上的映射能复用，重复连接更快。
    pub local_port: u16,
    /// STUN 服务器列表。
    pub stun_servers: Vec<String>,
    /// 单个 STUN 查询的超时。
    pub stun_timeout: Duration,
    /// 手动指定的对外地址。
    ///
    /// 在路由器上做了端口映射（把公网 UDP 端口转到本机）时填这里，
    /// 这样即使 STUN 探测不到、或者本地是对称型 NAT，也能直接连通。
    pub advertise: Vec<SocketAddr>,
    /// 是否把环回地址也当成候选（只在同机测试时有意义）。
    pub include_loopback: bool,
    /// 打洞参数。
    pub punch: PunchConfig,
    /// 等对端上线的最长时间。**0 表示一直等**（常驻的 `serve` 用这个）。
    pub signal_timeout: Duration,
}

impl DirectConfig {
    pub fn new(signal_server: impl Into<String>, peer: NodeId) -> Self {
        Self {
            signal_server: signal_server.into(),
            peer,
            local_port: 9000,
            stun_servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            stun_timeout: Duration::from_secs(3),
            advertise: Vec::new(),
            include_loopback: false,
            punch: PunchConfig::default(),
            signal_timeout: Duration::from_secs(60),
        }
    }
}

/// 建立好的直连通道。
pub struct DirectLink {
    /// 已经绑定在打洞端口上的 QUIC 端点。两边都既能 `accept` 也能 `connect`。
    pub endpoint: quinn::Endpoint,
    /// 打洞确认可用的对端地址；没确认时是按优先级猜的首选候选。
    pub peer_addr: SocketAddr,
    /// 打洞时是否真的收到了对端的探测包。
    pub punch_confirmed: bool,
    /// 对端节点 ID。
    pub peer_node_id: NodeId,
    /// 对端提供的候选地址。
    pub peer_candidates: Vec<SocketAddr>,
    /// 我们提供给对端的候选地址。
    pub local_candidates: Vec<Candidate>,
    /// 本机 NAT 的映射行为。
    pub mapping: MappingBehavior,
    /// STUN 看到的公网映射（没探到就是 None）。
    pub public_addr: Option<SocketAddr>,
    /// 本机打洞使用的本地端口。
    pub local_port: u16,
    /// 与信令服务器的连接。
    ///
    /// **必须一直持有**：一旦 drop，服务器就会认为本节点下线，对端之后再也
    /// 查不到我们。常驻的 `serve` 靠它保持「在线」。
    ///
    /// 持有期间不需要手动保活：`SignalingClient` 后台会按
    /// `DEFAULT_HEARTBEAT_INTERVAL` 自动心跳，所以即使 QUIC/隧道长时间活跃、
    /// 上层完全不碰信令，服务器也不会因为空闲把本节点摘掉。
    signal: SignalingClient,
}

impl DirectLink {
    /// 消费直连并拆出 QUIC 端点和信令连接。
    ///
    /// serve 会话结束时必须先释放信令后台任务和其它 link 状态，再释放
    /// endpoint；否则上一轮的 socket 可能仍被 link 的内部句柄保留，固定端口
    /// 的下一轮重建会得到 `Address already in use`。
    pub fn into_parts(self) -> (quinn::Endpoint, SignalingClient) {
        let Self {
            endpoint, signal, ..
        } = self;
        (endpoint, signal)
    }

    /// 连到对端，按候选顺序依次尝试。
    ///
    /// 打洞确认过的地址排在最前面，给足时间（QUIC 会自己重传，慢一点没关系）；
    /// 其余的候选快试快换，避免在一个明显不通的地址上耗太久。
    ///
    /// 之所以要「依次尝试」而不是只用打洞确认的那个：打洞没收到回应并不代表
    /// 连不上——我们的探测包已经在 NAT 上开了映射，对端也可能已经收到了。
    /// 让 QUIC 去试，比在打洞阶段就放弃要靠谱得多。
    pub async fn connect(&self) -> Result<quinn::Connection> {
        let mut ordered = vec![self.peer_addr];
        for candidate in &self.peer_candidates {
            if !ordered.contains(candidate) {
                ordered.push(*candidate);
            }
        }

        let mut last_error: Option<Error> = None;

        for (index, addr) in ordered.iter().enumerate() {
            let timeout = if index == 0 && self.punch_confirmed {
                // 打洞确认过的地址，值得多等一会儿。
                DIRECT_CONNECT_TIMEOUT
            } else {
                FALLBACK_CONNECT_TIMEOUT
            };

            match tokio::time::timeout(
                timeout,
                crate::transport::quic::connect(&self.endpoint, *addr, "p2pfile"),
            )
            .await
            {
                Ok(Ok(connection)) => {
                    if index == 0 {
                        info!(%addr, "直连建立");
                    } else {
                        info!(%addr, "直连建立（换用了后面的候选地址）");
                    }
                    return Ok(connection);
                }
                Ok(Err(err)) => {
                    warn!(%addr, error = %err, "连接失败，试下一个候选");
                    last_error = Some(err);
                }
                Err(_) => {
                    warn!(%addr, timeout = ?timeout, "连接超时，试下一个候选");
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            Error::Transport(format!(
                "所有候选地址都连不上：{}",
                ordered
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }))
    }

    /// 信令服务器地址。
    ///
    /// 读一下这个字段也顺带说明：连接一直被持有，对端在整个进程存活期间
    /// 都能通过信令服务器查到我们。
    pub fn signal_server(&self) -> &str {
        self.signal.server()
    }

    /// 把候选地址列表打印出来，方便排查为什么打不通。
    pub fn describe(&self) -> String {
        let peers: Vec<String> = self
            .peer_candidates
            .iter()
            .map(|addr| addr.to_string())
            .collect();
        format!(
            "本地端口 {}，NAT 映射行为 {}，公网映射 {}，对端候选 [{}]，首选 {}（打洞{}）",
            self.local_port,
            self.mapping.describe(),
            self.public_addr
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "未知".into()),
            peers.join(", "),
            self.peer_addr,
            if self.punch_confirmed {
                "已确认"
            } else {
                "未确认"
            }
        )
    }
}

/// 打洞确认过时，等 QUIC 握手的时长。
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 打洞未确认时，每个候选地址试探的时长。
const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// 建立到 `config.peer` 的直连。
pub async fn establish(identity: &Identity, config: &DirectConfig) -> Result<DirectLink> {
    // ---- 1. 绑定打洞用的 socket，全程就这一个 ----
    let bind: SocketAddr = format!("0.0.0.0:{}", config.local_port).parse().unwrap();
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|err| Error::Transport(format!("绑定本地 UDP 端口 {bind} 失败: {err}")))?;
    let local_addr = socket.local_addr()?;
    let local_port = local_addr.port();
    info!(port = local_port, "打洞 socket 就绪");

    // ---- 2. STUN 探自己的公网映射 ----
    let (public_addr, mapping) = probe_public_addr(&socket, config).await?;

    // ---- 3. 组装候选地址 ----
    let mut candidates = build_candidates(local_port, public_addr, config);
    dedup_candidates(&mut candidates);
    sort_candidates(&mut candidates);
    let local_candidates = candidates.clone();

    info!(
        count = candidates.len(),
        list = %local_candidates
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" / "),
        "本机候选地址"
    );
    if public_addr.is_none() && config.advertise.is_empty() {
        warn!(
            "没探到公网映射，也没有手动指定对外地址：只有对端能直连到本机时才有戏。\
             若路由器上做了端口映射，用 --advertise 告诉我对外的地址"
        );
    }

    // ---- 4. 信令：登记自己，换回对端候选 ----
    let mut signal = SignalingClient::connect(&config.signal_server, identity, candidates).await?;
    info!(server = %config.signal_server, "已接入信令服务器");
    let offer = resolve_peer_waiting(&mut signal, config.peer, config.signal_timeout).await?;
    let peer_candidates_raw = offer.candidates;
    info!(
        peer = %config.peer.short(),
        count = peer_candidates_raw.len(),
        token = %offer.token,
        list = %peer_candidates_raw
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" / "),
        "拿到对端候选地址"
    );

    // ---- 5. 过滤出这个 socket 真能发过去的地址 ----
    let peer_candidates = filter_reachable(&peer_candidates_raw, local_addr);
    if peer_candidates.is_empty() {
        return Err(Error::Transport(format!(
            "对端给的候选地址没有一个能用（本机 socket 是 {}，对端给的是 [{}]）。\
             本机只绑了 IPv4，对端的 IPv6 地址暂时用不上",
            local_addr,
            peer_candidates_raw
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // ---- 6. 同时打洞 ----
    info!(
        candidates = peer_candidates.len(),
        "开始打洞（双方必须同时在发，这是 NAT 的行为决定的）"
    );
    let (peer_addr, punch_confirmed) =
        match simultaneous_open_any(&socket, &peer_candidates, &offer.token, &config.punch).await {
            Ok(addr) => {
                info!(%addr, "洞打通了，收到对端探测包");
                (addr, true)
            }
            Err(err) => {
                // 打洞没收到回应**不等于**连不上：
                //
                // - 我们发出去的探测包已经在本机 NAT 上建立了映射，这是关键的一半；
                // - 对端可能已经收到了我们的包，只是它的回应还没到；
                // - 有些情况下（比如对端是常驻服务、不再发包）本来就收不到回应。
                //
                // 所以这里不放弃，改为「按候选顺序逐个尝试连接」，让 QUIC 自己的
                // 重传去撞那扇门。真正决定成败的是 QUIC 握手，而不是探测包。
                warn!(
                    error = %err,
                    "打洞没收到对端回应，仍然会按候选顺序尝试直连"
                );
                warn!("{}", punch_diagnosis(mapping, public_addr));
                (peer_candidates[0], false)
            }
        };

    // ---- 7. 把同一个 socket 交给 QUIC ----
    let std_socket = socket
        .into_std()
        .map_err(|err| Error::Transport(format!("取回 socket 失败: {err}")))?;
    let endpoint = endpoint_from_socket(std_socket)?;
    info!(local = %endpoint.local_addr()?, "QUIC 端点已就绪（复用打洞的端口）");

    Ok(DirectLink {
        endpoint,
        peer_addr,
        punch_confirmed,
        peer_node_id: config.peer,
        peer_candidates,
        local_candidates,
        mapping,
        public_addr,
        local_port,
        signal,
    })
}

/// 等对端上线。`timeout` 为 0 表示一直等下去。
///
/// 无限等待时会周期性重查：既避免长时间没有推送，也顺便刷新服务器侧的登记。
async fn resolve_peer_waiting(
    signal: &mut SignalingClient,
    peer: NodeId,
    timeout: Duration,
) -> Result<PeerOffer> {
    use crate::discovery::signal::LookupOutcome;

    if !timeout.is_zero() {
        return signal.resolve_peer(peer, timeout).await;
    }

    info!(peer = %peer.short(), "常驻模式：等对端上线（Ctrl-C 退出）");
    let mut rounds: u64 = 0;
    loop {
        match signal.lookup(peer).await? {
            LookupOutcome::Ready(offer) => return Ok(offer),
            LookupOutcome::Pending => {
                rounds += 1;
                if let Some(offer) = signal.wait_for_peer(peer, Duration::from_secs(60)).await? {
                    return Ok(offer);
                }
                // 超时了再查一次：对端可能刚上线但推送没到。
                debug!(peer = %peer.short(), rounds, "还没等到对端，重新查询");
            }
        }
    }
}

/// 跑 RFC 5780 mapping probing，拿到公网映射和有证据支撑的 NAT 映射行为。
async fn probe_public_addr(
    socket: &UdpSocket,
    config: &DirectConfig,
) -> Result<(Option<SocketAddr>, MappingBehavior)> {
    if config.stun_servers.is_empty() {
        info!("没有配置 STUN 服务器，跳过公网探测");
        return Ok((None, MappingBehavior::Unknown));
    }

    let mut servers = Vec::new();
    for spec in &config.stun_servers {
        match resolve_server(spec).await {
            Ok(addr) => servers.push(addr),
            Err(err) => warn!(%spec, error = %err, "解析 STUN 服务器失败，跳过"),
        }
    }

    let mut fallback = None;
    for server in servers {
        match probe_rfc5780(socket, server, config.stun_timeout).await {
            Ok(probe) => {
                for observation in &probe.observations {
                    info!(
                        server = %observation.server,
                        mapped = %observation.mapped_addr,
                        "STUN mapping 观测"
                    );
                }
                let Some(first) = probe.observations.first() else {
                    continue;
                };
                if fallback.is_none() {
                    fallback = Some((first.mapped_addr, probe.mapping));
                }
                info!(
                    primary = %server,
                    evidence = probe.evidence.describe(),
                    filtering = probe.filtering.describe(),
                    behavior = probe.mapping.describe(),
                    "NAT mapping probing 结果"
                );
                if probe.evidence == MappingEvidence::Rfc5780 {
                    return Ok((Some(first.mapped_addr), probe.mapping));
                }
            }
            Err(err) => warn!(%server, error = %err, "STUN mapping probing 失败，跳过"),
        }
    }

    if let Some((public_addr, mapping)) = fallback {
        warn!(
            %public_addr,
            behavior = mapping.describe(),
            "没有充分 RFC 5780 行为发现证据，mapping 结果按证据不足处理"
        );
        return Ok((Some(public_addr), MappingBehavior::Unknown));
    }

    warn!("所有 STUN 服务器都没有响应，拿不到公网映射");
    Ok((None, MappingBehavior::Unknown))
}

/// 组装要报给信令服务器的候选地址。
fn build_candidates(
    local_port: u16,
    public_addr: Option<SocketAddr>,
    config: &DirectConfig,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    if let Some(addr) = public_addr {
        candidates.push(Candidate::reflexive(addr));
    }
    for addr in &config.advertise {
        candidates.push(Candidate::reflexive(*addr));
    }
    for ip in local_ip_addresses() {
        // IPv6 链路本地地址（fe80::/10）必须丢掉：它只在同一个二层网段内有效，
        // 出了路由器就没有意义，而且还得带 scope id 才能用。留着只会把候选
        // 列表撑得又长又没用（本机实测 11 个候选里有 8 个是这种东西）。
        //
        // 顺带一提：本机 socket 目前只绑 IPv4，所以就算留着 IPv6 全局地址也
        // 用不上。等以后做双栈监听时再把它们放回来。
        if matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
            continue;
        }
        candidates.push(Candidate::host(SocketAddr::new(ip, local_port)));
    }
    if config.include_loopback {
        candidates.push(Candidate::host(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            local_port,
        )));
    }

    candidates
}

/// 只留下这个 socket 发得出去的候选地址。
///
/// 本机绑的是 IPv4，往 IPv6 地址发会直接失败，所以先按地址族筛一遍。
fn filter_reachable(candidates: &[Candidate], local_addr: SocketAddr) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for candidate in candidates {
        if candidate.addr.is_ipv4() != local_addr.is_ipv4() {
            warn!(addr = %candidate.addr, "地址族不匹配，跳过该候选");
            continue;
        }
        if candidate.addr.ip().is_unspecified() {
            continue;
        }
        if !out.contains(&candidate.addr) {
            out.push(candidate.addr);
        }
    }
    out
}

/// 打洞没成功时，把可能的原因讲清楚。
///
/// 不再当成致命错误——连接成不成由 QUIC 握手决定，这里只负责解释。
fn punch_diagnosis(mapping: MappingBehavior, public_addr: Option<SocketAddr>) -> String {
    let hint = match mapping {
        MappingBehavior::AddressAndPortDependent => {
            "本机是地址端口相关（对称型）NAT：用同一端口访问不同目标会拿到不同的公网端口。\
             这种 NAT 下打洞基本没戏，需要在路由器上做 UDP 端口映射，再用 --advertise 指定对外地址。"
        }
        MappingBehavior::EndpointIndependent => {
            "mapping 对打洞较有利，但 filtering behavior 尚未测量，不能单独保证可以打洞。"
        }
        MappingBehavior::AddressDependent => {
            "mapping 呈地址相关，只能说明结果具有条件性；filtering behavior 尚未测量，不能宣称可以打洞。"
        }
        MappingBehavior::Unknown => {
            "没拿到充分 RFC 5780 行为发现证据，无法可靠判断 NAT mapping 类型。\
             建议在路由器上做一次 UDP 端口映射，然后用 --advertise 直接指定对外地址。"
        }
    };
    let addr_hint = if public_addr.is_none() {
        "（另外：本机根本没探到公网映射）"
    } else {
        ""
    };
    format!("诊断：{hint}{addr_hint}")
}

/// 把 `std::net::UdpSocket` 直接交给 [`crate::transport::quic::endpoint_from_socket`]。
///
/// 给调用方（比如测试）一个不用起 tokio socket 的入口。
pub fn endpoint_for_socket(socket: StdUdpSocket) -> Result<quinn::Endpoint> {
    endpoint_from_socket(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认参数合理() {
        let peer = Identity::generate().node_id();
        let config = DirectConfig::new("127.0.0.1:7000", peer);
        assert_eq!(config.local_port, 9000);
        assert_eq!(config.peer, peer);
        assert!(!config.stun_servers.is_empty());
        assert!(!config.include_loopback);
    }

    #[test]
    fn 地址族不匹配的候选会被过滤掉() {
        let local: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let candidates = vec![
            Candidate::reflexive("203.0.113.5:4000".parse().unwrap()),
            Candidate::host("[2001:db8::1]:9000".parse().unwrap()),
            Candidate::host("192.168.1.7:9000".parse().unwrap()),
        ];
        let reachable = filter_reachable(&candidates, local);
        assert_eq!(reachable.len(), 2);
        assert!(reachable.iter().all(|addr| addr.is_ipv4()));
    }

    #[test]
    fn 未指定地址会被过滤掉() {
        let local: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let candidates = vec![Candidate::host("0.0.0.0:9000".parse().unwrap())];
        assert!(filter_reachable(&candidates, local).is_empty());
    }

    #[test]
    fn 重复候选只留一个() {
        let local: SocketAddr = "0.0.0.0:9000".parse().unwrap();
        let candidates = vec![
            Candidate::reflexive("203.0.113.5:4000".parse().unwrap()),
            Candidate::host("203.0.113.5:4000".parse().unwrap()),
        ];
        assert_eq!(filter_reachable(&candidates, local).len(), 1);
    }

    #[test]
    fn 候选包含端口和环回() {
        let config = DirectConfig {
            include_loopback: true,
            advertise: vec!["198.51.100.9:4000".parse().unwrap()],
            ..DirectConfig::new("127.0.0.1:7000", Identity::generate().node_id())
        };
        let candidates =
            build_candidates(9123, Some("203.0.113.7:41234".parse().unwrap()), &config);
        assert!(
            candidates
                .iter()
                .any(|c| c.addr == "203.0.113.7:41234".parse().unwrap())
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.addr == "198.51.100.9:4000".parse().unwrap())
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.addr == "127.0.0.1:9123".parse().unwrap())
        );
    }

    #[test]
    fn 映射行为的说明文字不为空() {
        for mapping in [
            MappingBehavior::EndpointIndependent,
            MappingBehavior::AddressDependent,
            MappingBehavior::AddressAndPortDependent,
            MappingBehavior::Unknown,
        ] {
            assert!(!mapping.describe().is_empty());
        }
    }
}
