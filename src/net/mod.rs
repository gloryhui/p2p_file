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

pub mod family;
pub mod race;
pub use family::{AddressFamily, NetworkFamilies};

use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::discovery::mdns::local_ip_addresses;
use crate::discovery::signal::{
    Candidate, PeerOffer, SignalingClient, dedup_candidates, sort_candidates,
};
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::nat::classify::{MappingBehavior, MappingEvidence, MappingProbe, probe_rfc5780};
use crate::nat::punch::PunchConfig;
use crate::nat::stun::{query_binding_with, resolve_server_for};
use crate::transport::quic::{
    PunchSocketHandle, endpoint_from_socket, endpoint_from_socket_with_punch_dispatcher,
};

/// 默认 STUN 服务器。
///
/// 选的都是国内可达性较好的；`stun.cloudflare.com` 是兜底（它在国内不一定通）。
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.miwifi.com:3478",
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Network preparation settings for the long-lived desktop session.
#[derive(Clone, Debug)]
pub struct DesktopNetworkConfig {
    pub relay_server: Option<String>,
    /// Diagnostic override: advertise only explicit candidates (also used by local E2E).
    pub advertise_only: bool,
    pub local_port: u16,
    pub families: NetworkFamilies,
    pub stun_servers: Vec<String>,
    pub stun_timeout: Duration,
    pub advertise: Vec<SocketAddr>,
    pub include_loopback: bool,
}

impl Default for DesktopNetworkConfig {
    fn default() -> Self {
        Self {
            relay_server: None,
            advertise_only: false,
            local_port: 0,
            families: NetworkFamilies::DualStack,
            stun_servers: DEFAULT_STUN_SERVERS
                .iter()
                .map(|server| server.to_string())
                .collect(),
            stun_timeout: Duration::from_secs(3),
            advertise: Vec::new(),
            include_loopback: false,
        }
    }
}

/// Each family owns the exact socket used for its discovery, probes and QUIC.
#[derive(Clone)]
pub struct NetworkPath {
    pub family: AddressFamily,
    pub endpoint: quinn::Endpoint,
    pub punch_socket: PunchSocketHandle,
    pub local_addr: SocketAddr,
    pub local_candidates: Vec<Candidate>,
    /// Only IPv4 has RFC 5780 NAT classification.
    pub mapping: Option<MappingBehavior>,
    pub mapping_probe: Option<MappingProbe>,
    pub public_addr: Option<SocketAddr>,
}
impl NetworkPath {
    pub fn reachable_candidates(&self, candidates: &[Candidate]) -> Vec<SocketAddr> {
        filter_reachable(candidates, self.local_addr)
    }
}
pub struct DesktopNetwork {
    pub relay: Option<crate::relay::client::Fallback>,
    pub paths: Vec<NetworkPath>,
    pub local_candidates: Vec<Candidate>,
    pub diagnostics: Vec<String>,
}
impl DesktopNetwork {
    pub fn reachable_candidates(&self, candidates: &[Candidate]) -> Vec<SocketAddr> {
        self.paths
            .iter()
            .flat_map(|p| p.reachable_candidates(candidates))
            .collect()
    }
    pub fn path(&self, family: AddressFamily) -> Option<&NetworkPath> {
        self.paths.iter().find(|p| p.family == family)
    }
    pub fn close(&self) {
        if let Some(relay) = &self.relay {
            relay.endpoints.close();
        }
        for path in &self.paths {
            path.endpoint.close(0u32.into(), b"network shutdown");
        }
    }
    pub async fn wait_idle(&self) {
        if let Some(relay) = &self.relay {
            for endpoint in relay.endpoints.endpoints() {
                endpoint.wait_idle().await;
            }
        }
        for path in &self.paths {
            path.endpoint.wait_idle().await;
        }
    }
    pub fn transport_label(&self, connection: &quinn::Connection) -> String {
        let kind = if self
            .relay
            .as_ref()
            .is_some_and(|r| r.endpoints.is_relay(connection))
        {
            "Relay"
        } else {
            "Direct"
        };
        if kind == "Relay" {
            format!(
                "Relay {} {}",
                AddressFamily::of(connection.remote_address()),
                connection.remote_address()
            )
        } else {
            format!(
                "{} Direct {}",
                AddressFamily::of(connection.remote_address()),
                connection.remote_address()
            )
        }
    }
}

/// 建立直连所需的参数。
#[derive(Clone, Debug)]
pub struct DirectConfig {
    pub relay_server: Option<String>,
    pub advertise_only: bool,
    /// 信令服务器地址（阿里云那台）。
    pub signal_server: String,
    /// 对端节点 ID。
    pub peer: NodeId,
    /// 本机打洞用的 UDP 端口。0 表示让系统随便选一个。
    ///
    /// 固定端口有个好处：NAT 上的映射能复用，重复连接更快。
    pub local_port: u16,
    pub families: NetworkFamilies,
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
            relay_server: None,
            advertise_only: false,
            signal_server: signal_server.into(),
            peer,
            local_port: 9000,
            families: NetworkFamilies::DualStack,
            stun_servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            stun_timeout: Duration::from_secs(3),
            advertise: Vec::new(),
            include_loopback: false,
            punch: PunchConfig::default(),
            signal_timeout: Duration::from_secs(60),
        }
    }
}

/// Prepared native paths. No candidate or probe is an authenticated winner.
pub struct DirectLink {
    pub token: crate::nat::punch::PunchToken,
    pub network: DesktopNetwork,
    pub peer_addr: SocketAddr,
    pub peer_node_id: NodeId,
    pub peer_candidates: Vec<SocketAddr>,
    signal: tokio::sync::Mutex<SignalingClient>,
    relay_used: tokio::sync::Mutex<bool>,
    signal_server: String,
    probes: tokio::task::JoinSet<()>,
    observations: Vec<race::ProbeObservation>,
}
impl DirectLink {
    pub(crate) fn probe_observations(&self) -> Vec<race::ProbeObservation> {
        self.observations.clone()
    }
    pub fn into_parts(self) -> (DesktopNetwork, SignalingClient, tokio::task::JoinSet<()>) {
        (self.network, self.signal.into_inner(), self.probes)
    }
    pub fn endpoints(&self) -> Vec<quinn::Endpoint> {
        let mut endpoints: Vec<_> = self
            .network
            .paths
            .iter()
            .map(|p| p.endpoint.clone())
            .collect();
        if let Some(relay) = &self.network.relay {
            endpoints.extend(relay.endpoints.endpoints());
        }
        endpoints
    }
    /// Unauthenticated QUIC helper retained for the pending-handshake regression.
    pub async fn connect(&self) -> Result<quinn::Connection> {
        let path = self
            .network
            .path(AddressFamily::of(self.peer_addr))
            .ok_or_else(|| Error::Transport("missing address family".into()))?;
        crate::transport::quic::connect(&path.endpoint, self.peer_addr, "p2pfile").await
    }
    pub fn signal_server(&self) -> &str {
        &self.signal_server
    }
    pub fn describe(&self) -> String {
        format!(
            "{}; 对端候选 [{}]；等待 QUIC + Ed25519/TLS 身份认证",
            self.network.diagnostics.join("; "),
            self.peer_candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
    pub async fn connect_authenticated(&self, identity: &Identity) -> Result<quinn::Connection> {
        let candidates = self
            .network
            .paths
            .iter()
            .flat_map(|path| {
                self.peer_candidates
                    .iter()
                    .filter(|a| path.family.accepts(**a))
                    .map(|a| (path.endpoint.clone(), *a))
            })
            .collect();
        if let Some(relay) = &self.network.relay {
            // Reconnect is a new pairing/transport, never an inherited relay socket or grant.
            // A fresh signaling registration avoids confusing queued offers from an older attempt.
            let mut used = self.relay_used.lock().await;
            let mut probes = tokio::task::JoinSet::new();
            let (token, candidates, observations) = if *used {
                let mut signal = SignalingClient::connect(
                    &self.signal_server,
                    identity,
                    self.network.local_candidates.clone(),
                )
                .await?;
                let offer =
                    resolve_peer_waiting(&mut signal, self.peer_node_id, Duration::from_secs(15))
                        .await?;
                *self.signal.lock().await = signal;
                let mut candidates = Vec::new();
                let mut observations = Vec::new();
                for path in &self.network.paths {
                    let reachable = path.reachable_candidates(&offer.candidates);
                    if reachable.is_empty() {
                        continue;
                    }
                    candidates.extend(reachable.iter().map(|addr| (path.endpoint.clone(), *addr)));
                    let socket = path.punch_socket.clone();
                    let mut receiver = socket.register_probe(&offer.token)?;
                    let token = offer.token;
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    observations.push((path.endpoint.clone(), rx));
                    probes.spawn(async move {
                        for _ in 0..PunchConfig::default().attempts {
                            for address in &reachable {
                                let _ = socket.send_probe_to(&token, *address).await;
                            }
                            if let Ok(Some(source)) =
                                tokio::time::timeout(Duration::from_millis(200), receiver.recv())
                                    .await
                            {
                                let _ = socket.send_probe_to(&token, source).await;
                                tx.send_replace(Some(source));
                            }
                        }
                    });
                }
                (offer.token, candidates, observations)
            } else {
                (self.token, candidates, self.observations.clone())
            };
            *used = true;
            let mut tasks =
                race::prepared_tasks(candidates, observations, identity, self.peer_node_id);
            let fallback = relay.clone();
            let identity = identity.clone();
            let peer = self.peer_node_id;
            tasks.spawn(async move { fallback.prepare(identity, peer, token).await });
            let result = race::finish_prepared_guard(tasks).await;
            probes.abort_all();
            while probes.join_next().await.is_some() {}
            let mut guard = result?;
            guard.retain_relay_endpoint(&relay.endpoints)?;
            return Ok(guard.release());
        }
        race::authenticated_race_with_probes(
            candidates,
            self.observations.clone(),
            identity,
            self.peer_node_id,
        )
        .await
    }
}

pub async fn establish(identity: &Identity, config: &DirectConfig) -> Result<DirectLink> {
    let network = prepare_desktop_network(&DesktopNetworkConfig {
        relay_server: config.relay_server.clone(),
        advertise_only: config.advertise_only,
        local_port: config.local_port,
        families: config.families,
        stun_servers: config.stun_servers.clone(),
        stun_timeout: config.stun_timeout,
        advertise: config.advertise.clone(),
        include_loopback: config.include_loopback,
    })
    .await?;
    let mut signal = SignalingClient::connect(
        &config.signal_server,
        identity,
        network.local_candidates.clone(),
    )
    .await?;
    let offer = resolve_peer_waiting(&mut signal, config.peer, config.signal_timeout).await?;
    let peer_candidates = network.reachable_candidates(&offer.candidates);
    let peer_addr = match peer_candidates.first() {
        Some(address) => *address,
        None if network.relay.is_some() => offer
            .candidates
            .first()
            .map(|c| c.addr)
            .unwrap_or(AddressFamily::Ipv4.loopback(0)),
        None => {
            return Err(Error::Transport(
                "no peer candidate matches an available native path".into(),
            ));
        }
    };
    let mut probes = tokio::task::JoinSet::new();
    let mut observations = Vec::new();
    for path in &network.paths {
        let candidates = path.reachable_candidates(&offer.candidates);
        if candidates.is_empty() {
            continue;
        }
        let socket = path.punch_socket.clone();
        let mut receiver = socket.register_probe(&offer.token)?;
        let token = offer.token;
        let punch = config.punch;
        let (observation, changes) = tokio::sync::watch::channel(None);
        observations.push((path.endpoint.clone(), changes));
        probes.spawn(async move {
            for _ in 0..punch.attempts {
                for candidate in &candidates {
                    let _ = socket.send_probe_to(&token, *candidate).await;
                }
                if let Ok(Some(source)) =
                    tokio::time::timeout(punch.interval, receiver.recv()).await
                {
                    let _ = socket.send_probe_to(&token, source).await;
                    observation.send_replace(Some(source));
                    if source.is_ipv6() {
                        info!(%source, "IPv6 原生 UDP 可达性探测已确认");
                    } else {
                        info!(%source, "洞打通了，收到对端探测包");
                    }
                    // Keep sending through the full probe window for the other side.
                }
            }
        });
    }
    Ok(DirectLink {
        token: offer.token,
        network,
        peer_addr,
        peer_node_id: config.peer,
        peer_candidates,
        signal_server: config.signal_server.clone(),
        signal: tokio::sync::Mutex::new(signal),
        relay_used: tokio::sync::Mutex::new(false),
        probes,
        observations,
    })
}

/// One family may fail without disabling the other. Fixed ports are bound once
/// per family; ephemeral ports are independently advertised with their real value.
pub async fn prepare_desktop_network(config: &DesktopNetworkConfig) -> Result<DesktopNetwork> {
    if let Some(spec) = &config.relay_server {
        crate::relay::client::validate_server_spec(spec)?;
    }
    let mut tasks = tokio::task::JoinSet::new();
    for family in [AddressFamily::Ipv6, AddressFamily::Ipv4] {
        if !config.families.enabled(family) {
            continue;
        }
        let config = config.clone();
        tasks.spawn(async move { (family, prepare_path(family, &config).await) });
    }
    let mut paths = Vec::new();
    let mut diagnostics = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let (family, result) = result.map_err(|e| Error::Transport(e.to_string()))?;
        match result {
            Ok(path) => {
                diagnostics.push(format!(
                    "{family} UDP {}；Host {}；STUN {}{}",
                    path.local_addr,
                    path.local_candidates
                        .iter()
                        .filter(|c| c.kind == crate::discovery::signal::CandidateKind::Host)
                        .count(),
                    path.public_addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "不可用（保留 Host）".into()),
                    path.mapping
                        .map(|m| format!("；IPv4 mapping {}", m.describe()))
                        .unwrap_or_default()
                ));
                paths.push(path);
            }
            Err(error) => diagnostics.push(format!("{family} path unavailable: {error}")),
        }
    }
    if paths.is_empty() && config.relay_server.is_none() {
        return Err(Error::Transport(diagnostics.join("; ")));
    }
    paths.sort_by_key(|p| p.family);
    let mut local_candidates: Vec<_> = paths
        .iter()
        .flat_map(|p| p.local_candidates.clone())
        .collect();
    dedup_candidates(&mut local_candidates);
    sort_candidates(&mut local_candidates);
    bound_candidates(&mut local_candidates);
    Ok(DesktopNetwork {
        relay: config
            .relay_server
            .clone()
            .map(|server| crate::relay::client::Fallback::new(server, config.families)),
        paths,
        local_candidates,
        diagnostics,
    })
}
fn bound_candidates(candidates: &mut Vec<Candidate>) {
    let mut v6 = candidates.iter().copied().filter(|c| c.addr.is_ipv6());
    let mut v4 = candidates.iter().copied().filter(|c| c.addr.is_ipv4());
    let mut selected = Vec::new();
    while selected.len() < crate::discovery::signal::MAX_CANDIDATES {
        let next = if selected.len() % 2 == 0 {
            v6.next().or_else(|| v4.next())
        } else {
            v4.next().or_else(|| v6.next())
        };
        let Some(next) = next else {
            break;
        };
        selected.push(next);
    }
    sort_candidates(&mut selected);
    *candidates = selected;
}

async fn prepare_path(family: AddressFamily, config: &DesktopNetworkConfig) -> Result<NetworkPath> {
    let socket = UdpSocket::from_std(family::bind_udp(family.wildcard(config.local_port))?)?;
    let local_addr = socket.local_addr()?;
    let (public_addr, mapping, mapping_probe) = if family == AddressFamily::Ipv4 {
        let report = probe_public_addr(&socket, &config.stun_servers, config.stun_timeout).await?;
        let addr = report
            .as_ref()
            .and_then(|r| r.observations.first())
            .map(|o| o.mapped_addr);
        let mapping = report
            .as_ref()
            .map(|r| r.mapping)
            .unwrap_or(MappingBehavior::Unknown);
        (addr, Some(mapping), report)
    } else {
        let mut observation = None;
        for spec in &config.stun_servers {
            if let Ok(Ok(servers)) =
                tokio::time::timeout(config.stun_timeout, resolve_server_for(spec, family)).await
            {
                for server in servers {
                    match query_binding_with(&socket, server, config.stun_timeout).await {
                        Ok(result) => {
                            observation = Some(result.mapped_addr);
                            break;
                        }
                        Err(error) => {
                            debug!(%server, %error, "IPv6 STUN observation failed; Host candidates remain usable")
                        }
                    }
                }
            }
            if observation.is_some() {
                break;
            }
        }
        (observation, None, None)
    };
    let mut candidates = if config.advertise_only {
        config
            .advertise
            .iter()
            .filter(|addr| family.accepts(**addr))
            .copied()
            .map(|address| {
                if family == AddressFamily::Ipv4 {
                    Candidate::reflexive(address)
                } else {
                    Candidate::host(address)
                }
            })
            .collect()
    } else {
        build_candidates_for(
            family,
            local_addr.port(),
            public_addr,
            &config.advertise,
            config.include_loopback,
        )
    };
    dedup_candidates(&mut candidates);
    sort_candidates(&mut candidates);
    let (endpoint, punch_socket) = endpoint_from_socket_with_punch_dispatcher(socket.into_std()?)?;
    if endpoint.local_addr()? != local_addr {
        return Err(Error::Transport("QUIC socket changed after STUN".into()));
    }
    Ok(NetworkPath {
        family,
        endpoint,
        punch_socket,
        local_addr,
        local_candidates: candidates,
        mapping,
        mapping_probe,
        public_addr,
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
    stun_servers: &[String],
    stun_timeout: Duration,
) -> Result<Option<MappingProbe>> {
    if stun_servers.is_empty() {
        info!("没有配置 STUN 服务器，跳过公网探测");
        return Ok(None);
    }

    let mut servers = Vec::new();
    for spec in stun_servers {
        match tokio::time::timeout(stun_timeout, resolve_server_for(spec, AddressFamily::Ipv4))
            .await
        {
            Ok(Ok(addresses)) => servers.extend(addresses),
            other => warn!(%spec, error = ?other, "解析 IPv4 STUN 服务器失败，跳过"),
        }
    }

    let mut fallback = None;
    for server in servers {
        match probe_rfc5780(socket, server, stun_timeout).await {
            Ok(probe) => {
                for observation in &probe.observations {
                    info!(
                        server = %observation.server,
                        mapped = %observation.mapped_addr,
                        "STUN mapping 观测"
                    );
                }
                if probe.observations.is_empty() {
                    continue;
                }
                if fallback.is_none() {
                    fallback = Some(probe.clone());
                }
                info!(
                    primary = %server,
                    evidence = probe.evidence.describe(),
                    filtering = probe.filtering.describe(),
                    behavior = probe.mapping.describe(),
                    "NAT mapping probing 结果"
                );
                if probe.evidence == MappingEvidence::Rfc5780 {
                    return Ok(Some(probe));
                }
            }
            Err(err) => warn!(%server, error = %err, "STUN mapping probing 失败，跳过"),
        }
    }

    if let Some(mut report) = fallback {
        let public_addr = report.observations[0].mapped_addr;
        let mapping = report.mapping;
        warn!(
            %public_addr,
            behavior = mapping.describe(),
            "没有充分 RFC 5780 行为发现证据，mapping 结果按证据不足处理"
        );
        report.mapping = MappingBehavior::Unknown;
        return Ok(Some(report));
    }

    warn!("所有 STUN 服务器都没有响应，拿不到公网映射");
    Ok(None)
}

#[cfg(test)]
fn build_candidates(
    port: u16,
    public: Option<SocketAddr>,
    advertise: &[SocketAddr],
    loopback: bool,
) -> Vec<Candidate> {
    build_candidates_for(AddressFamily::Ipv4, port, public, advertise, loopback)
}
fn build_candidates_for(
    family: AddressFamily,
    port: u16,
    public: Option<SocketAddr>,
    advertise: &[SocketAddr],
    loopback: bool,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    if let Some(addr) = public.filter(|a| family.accepts(*a)) {
        candidates.push(Candidate::reflexive(addr));
    }
    for addr in advertise.iter().filter(|a| family.accepts(**a)) {
        candidates.push(if family == AddressFamily::Ipv6 {
            Candidate::host(*addr)
        } else {
            Candidate::reflexive(*addr)
        });
    }
    for ip in local_ip_addresses() {
        let addr = SocketAddr::new(ip, port);
        if family.accepts(addr) {
            candidates.push(Candidate::host(addr));
        }
    }
    if loopback {
        candidates.push(Candidate::host(family.loopback(port)));
    }
    candidates
}
fn filter_reachable(candidates: &[Candidate], local_addr: SocketAddr) -> Vec<SocketAddr> {
    let family = AddressFamily::of(local_addr);
    let mut out = Vec::new();
    for candidate in candidates {
        if candidate.kind != crate::discovery::signal::CandidateKind::Relay
            && family.accepts(candidate.addr)
            && !out.contains(&candidate.addr)
        {
            out.push(candidate.addr);
        }
    }
    out
}

/// 打洞没成功时，把可能的原因讲清楚。
///
/// 不再当成致命错误——连接成不成由 QUIC 握手决定，这里只负责解释。
pub fn punch_diagnosis(mapping: MappingBehavior, public_addr: Option<SocketAddr>) -> String {
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
    #[tokio::test]
    async fn independent_family_bind_failures_and_both_fail_closed() {
        if !family::ipv6_test_available() {
            return;
        }
        for blocked_family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let held = family::bind_udp(blocked_family.wildcard(0)).unwrap();
            let port = held.local_addr().unwrap().port();
            let config = DesktopNetworkConfig {
                local_port: port,
                stun_servers: Vec::new(),
                include_loopback: true,
                ..Default::default()
            };
            let network = prepare_desktop_network(&config).await.unwrap();
            assert_eq!(network.paths.len(), 1);
            assert_ne!(network.paths[0].family, blocked_family);
            assert_eq!(network.paths[0].local_addr.port(), port);
            assert!(
                network
                    .local_candidates
                    .iter()
                    .all(|c| network.paths[0].family.accepts(c.addr))
            );
            let other = family::bind_udp(network.paths[0].family.wildcard(port));
            assert!(other.is_err());
            network.close();
            network.wait_idle().await;
        }
        let v6 = family::bind_udp(AddressFamily::Ipv6.wildcard(0)).unwrap();
        let port = v6.local_addr().unwrap().port();
        let _v4 = family::bind_udp(AddressFamily::Ipv4.wildcard(port)).unwrap();
        let config = DesktopNetworkConfig {
            local_port: port,
            stun_servers: Vec::new(),
            ..Default::default()
        };
        let error = prepare_desktop_network(&config)
            .await
            .err()
            .expect("both held paths must fail closed")
            .to_string();
        assert!(error.contains("IPv4"));
        assert!(error.contains("IPv6"));
    }
    #[tokio::test]
    async fn ipv6_stun_failure_retains_host_and_paths_advertise_their_own_real_port() {
        if !family::ipv6_test_available() {
            return;
        }
        let held = UdpSocket::from_std(family::bind_udp(AddressFamily::Ipv6.loopback(0)).unwrap())
            .unwrap();
        let config = DesktopNetworkConfig {
            stun_servers: vec![held.local_addr().unwrap().to_string()],
            stun_timeout: Duration::from_millis(10),
            include_loopback: true,
            advertise: vec!["[fd00::7]:7777".parse().unwrap()],
            ..Default::default()
        };
        let network = prepare_desktop_network(&config).await.unwrap();
        let v6 = network.path(AddressFamily::Ipv6).unwrap();
        assert_eq!(v6.mapping, None);
        assert_eq!(v6.public_addr, None);
        assert!(
            network
                .local_candidates
                .contains(&Candidate::host("[fd00::7]:7777".parse().unwrap()))
        );
        for path in &network.paths {
            assert_eq!(path.endpoint.local_addr().unwrap(), path.local_addr);
            assert_eq!(path.punch_socket.local_addr().unwrap(), path.local_addr);
            assert!(path.local_candidates.contains(&Candidate::host(
                path.family.loopback(path.local_addr.port())
            )));
            assert!(
                path.local_candidates
                    .iter()
                    .all(|c| path.family.accepts(c.addr))
            );
        }
        network.close();
        network.wait_idle().await;
    }
    #[test]
    fn candidate_budget_keeps_both_families_and_fills_unused_quota() {
        let mut candidates = (1..=40)
            .map(|port| Candidate::host(AddressFamily::Ipv4.loopback(port)))
            .collect::<Vec<_>>();
        bound_candidates(&mut candidates);
        assert_eq!(candidates.len(), 32);
        for port in 1..=40 {
            candidates.push(Candidate::host(AddressFamily::Ipv6.loopback(port)));
        }
        sort_candidates(&mut candidates);
        bound_candidates(&mut candidates);
        assert_eq!(candidates.len(), 32);
        assert_eq!(candidates.iter().filter(|c| c.addr.is_ipv6()).count(), 16);
    }

    #[test]
    fn missing_family_and_unsupported_candidates_never_cross_path() {
        let candidates = [
            Candidate::host("[fd00::7]:9000".parse().unwrap()),
            Candidate::host("127.0.0.1:9000".parse().unwrap()),
            Candidate::host("[fe80::1]:9000".parse().unwrap()),
            Candidate::host("[::ffff:127.0.0.1]:9000".parse().unwrap()),
        ];
        assert_eq!(
            filter_reachable(&candidates, AddressFamily::Ipv4.wildcard(0)),
            vec!["127.0.0.1:9000".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            filter_reachable(&candidates, AddressFamily::Ipv6.wildcard(0)),
            vec!["[fd00::7]:9000".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn 默认参数合理() {
        let peer = Identity::generate().node_id();
        let config = DirectConfig::new("127.0.0.1:7000", peer);
        assert_eq!(config.local_port, 9000);
        assert_eq!(config.peer, peer);
        assert!(!config.stun_servers.is_empty());
        assert!(!config.include_loopback);
    }

    #[tokio::test]
    async fn desktop网络探测与quinn端点保持同一udp地址() {
        let config = DesktopNetworkConfig {
            relay_server: None,
            advertise_only: false,
            local_port: 0,
            families: NetworkFamilies::Ipv4Only,
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_millis(20),
            advertise: Vec::new(),
            include_loopback: true,
        };
        let network = prepare_desktop_network(&config).await.unwrap();
        let endpoint_addr = network.paths[0].endpoint.local_addr().unwrap();
        assert_eq!(network.paths[0].local_addr, endpoint_addr);
        assert!(network.local_candidates.iter().any(|candidate| {
            candidate.addr
                == SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, endpoint_addr.port()))
        }));
        network.paths[0]
            .endpoint
            .close(0u32.into(), b"test complete");
        network.paths[0].endpoint.wait_idle().await;
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
        let candidates = build_candidates(
            9123,
            Some("203.0.113.7:41234".parse().unwrap()),
            &config.advertise,
            config.include_loopback,
        );
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
