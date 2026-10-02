//! A dedicated socket per peer attempt: admission first, then the same socket to Quinn.
use super::{
    RELAY_ATTEMPT_TIMEOUT, RELAY_BIND_TIMEOUT,
    wire::{self, Challenge, Hello, Packet},
};
use crate::identity::{Identity, NodeId};
use crate::nat::punch::PunchToken;
use crate::net::{
    AddressFamily, NetworkFamilies,
    race::{ConnectionGuard, PreparedTransport},
};
use crate::{Error, Result};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Owned by the Desktop network or CLI link. Only winning endpoints are retained;
/// pending/losing endpoints stay inside cancellation guards. No detached keepalive task.
#[derive(Clone, Default)]
pub struct EndpointPool(Arc<Mutex<PoolState>>);
#[derive(Default)]
struct PoolState {
    closed: bool,
    endpoints: Vec<(usize, quinn::Endpoint)>,
}
type Progress = Arc<dyn Fn(&str) + Send + Sync>;
#[derive(Clone)]
pub struct Fallback {
    pub server: String,
    pub families: NetworkFamilies,
    pub endpoints: EndpointPool,
    pub(crate) progress: Option<Progress>,
}
impl Fallback {
    pub fn new(server: String, families: NetworkFamilies) -> Self {
        Self {
            server,
            families,
            endpoints: EndpointPool::default(),
            progress: None,
        }
    }
    pub async fn prepare(
        &self,
        identity: Identity,
        peer: NodeId,
        token: PunchToken,
    ) -> Result<PreparedTransport> {
        tokio::time::sleep(super::RELAY_FALLBACK_DELAY).await;
        tracing::info!(relay = %self.server, "直连尚无 authenticated winner，正在尝试 Relay");
        if let Some(progress) = &self.progress {
            progress("IPv6 / IPv4 直连未完成，正在尝试 Relay");
        }
        prepare_any_with_progress(
            identity,
            peer,
            token,
            self.server.clone(),
            self.families,
            self.progress.clone(),
        )
        .await
    }
    pub async fn wait(
        &self,
        identity: Identity,
        peer: NodeId,
        token: PunchToken,
    ) -> Result<ConnectionGuard> {
        tokio::time::sleep(super::RELAY_FALLBACK_DELAY).await;
        tracing::info!(relay = %self.server, "直连尚无 authenticated winner，正在尝试 Relay");
        if let Some(progress) = &self.progress {
            progress("IPv6 / IPv4 直连未完成，正在尝试 Relay");
        }
        await_peer_selection_with_progress(
            identity,
            peer,
            token,
            self.server.clone(),
            self.families,
            self.progress.clone(),
        )
        .await
    }
}
impl EndpointPool {
    pub(crate) fn retain(
        &self,
        connection: &quinn::Connection,
        endpoint: quinn::Endpoint,
    ) -> Result<()> {
        let mut endpoints = self
            .0
            .lock()
            .map_err(|_| Error::Transport("Relay endpoint ownership unavailable".into()))?;
        if endpoints.closed {
            return Err(Error::Transport("Relay network already closed".into()));
        }
        endpoints
            .endpoints
            .retain(|(_, endpoint)| endpoint.open_connections() > 0);
        if endpoints.endpoints.len() >= 64 {
            return Err(Error::Transport("Relay endpoint resource limit".into()));
        }
        endpoints.endpoints.push((connection.stable_id(), endpoint));
        Ok(())
    }
    pub fn is_relay(&self, connection: &quinn::Connection) -> bool {
        self.0.lock().is_ok_and(|items| {
            items
                .endpoints
                .iter()
                .any(|(id, _)| *id == connection.stable_id())
        })
    }
    pub fn endpoints(&self) -> Vec<quinn::Endpoint> {
        self.0
            .lock()
            .map(|items| {
                items
                    .endpoints
                    .iter()
                    .map(|(_, endpoint)| endpoint.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.closed = true;
            for (_, endpoint) in &state.endpoints {
                endpoint.close(0_u32.into(), b"Relay network shutdown");
            }
        }
    }
}

/// Resolving is deliberately called only inside the delayed fallback task.
pub async fn resolve(spec: &str, families: NetworkFamilies) -> Result<Vec<SocketAddr>> {
    let addresses = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(spec))
        .await
        .map_err(|_| Error::Discovery("Relay DNS timeout".into()))??;
    let addresses: Vec<_> = addresses.take(32).collect();
    let mut result = Vec::new();
    for family in [AddressFamily::Ipv6, AddressFamily::Ipv4] {
        for address in addresses
            .iter()
            .copied()
            .filter(|address| family.accepts(*address) && families.enabled(family))
            .take(2)
        {
            if !result.contains(&address) {
                result.push(address);
            }
        }
    }
    if result.is_empty() {
        return Err(Error::Discovery(
            "Relay has no usable native address family".into(),
        ));
    }
    Ok(result)
}

/// No socket is shared with direct paths or another peer/family attempt.
pub async fn bind(
    identity: &Identity,
    peer: NodeId,
    token: PunchToken,
    server: SocketAddr,
) -> Result<quinn::Endpoint> {
    bind_with_progress(identity, peer, token, server, None).await
}
async fn bind_with_progress(
    identity: &Identity,
    peer: NodeId,
    token: PunchToken,
    server: SocketAddr,
    progress: Option<&Progress>,
) -> Result<quinn::Endpoint> {
    let family = AddressFamily::of(server);
    if !family.accepts(server) {
        return Err(Error::Transport("invalid Relay UDP address".into()));
    }
    let socket = UdpSocket::from_std(crate::net::family::bind_udp(family.wildcard(0))?)?;
    let local = socket.local_addr()?;
    let hello = Hello::new(identity, peer, token);
    let hello_bytes = wire::encode(Packet::Hello(hello))?;
    let mut retry = tokio::time::interval(Duration::from_millis(200));
    // Windows reports WSAEMSGSIZE for oversized receives into a short buffer.
    // Receive the full bounded UDP datagram and then apply the control limit.
    let mut buffer = [0_u8; 65_536];
    let deadline = tokio::time::sleep(RELAY_BIND_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(Error::Transport(format!("Relay {family} UDP admission timeout: {server}"))),
            _ = retry.tick() => { socket.send_to(&hello_bytes, server).await?; },
            received = socket.recv_from(&mut buffer) => {
                let (n, from) = received?;
                if from != server || n > wire::MAX_CONTROL { continue; }
                match wire::decode(&buffer[..n]) {
                    Ok(Packet::Challenge {client_nonce, nonce, source}) if client_nonce == hello.client_nonce && family.accepts(source) => {
                        let challenge = Challenge { hello, nonce, source };
                        socket.send_to(&wire::encode(wire::register(identity, challenge)?)?, server).await?;
                    },
                    Ok(Packet::Ready {token: ready_token, node, client_nonce}) if ready_token == token && node == identity.node_id() && client_nonce == hello.client_nonce => break,
                    _ => {},
                }
            }
        }
    }
    // RelayReady is UDP readiness only, never peer authentication.
    tracing::info!(%server, %family, %local, "Relay UDP 已就绪；等待端到端 QUIC 身份认证");
    if let Some(progress) = progress {
        progress(&format!(
            "Relay UDP {family} 已就绪；等待端到端 QUIC 身份认证"
        ));
    }
    let endpoint = crate::transport::quic::endpoint_from_socket(socket.into_std()?)?;
    if endpoint.local_addr()? != local {
        return Err(Error::Transport(
            "Relay socket changed at Quinn handoff".into(),
        ));
    }
    Ok(endpoint)
}

pub async fn prepare(
    identity: &Identity,
    peer: NodeId,
    token: PunchToken,
    server: SocketAddr,
) -> Result<PreparedTransport> {
    prepare_with_progress(identity, peer, token, server, None).await
}
async fn prepare_with_progress(
    identity: &Identity,
    peer: NodeId,
    token: PunchToken,
    server: SocketAddr,
    progress: Option<Progress>,
) -> Result<PreparedTransport> {
    tokio::time::timeout(RELAY_ATTEMPT_TIMEOUT, async {
        let endpoint = bind_with_progress(identity, peer, token, server, progress.as_ref()).await?;
        // Same deterministic NodeId rule as Desktop direct paths. Application
        // client/server roles are independent of who initiates the QUIC handshake.
        let mut prepared = if identity.node_id() < peer {
            PreparedTransport::dial(&endpoint, server, identity, peer).await?
        } else {
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| Error::Transport("Relay endpoint closed".into()))?;
            if incoming.remote_address() != server {
                incoming.refuse();
                return Err(Error::Transport("Relay source changed".into()));
            }
            PreparedTransport::accept(incoming, identity, peer).await?
        };
        prepared.own_relay_endpoint(endpoint);
        Ok(prepared)
    })
    .await
    .map_err(|_| Error::Transport(format!("Relay {server} authenticated attempt timeout")))?
}

/// Each family/target is bounded and independently owns a UDP socket.
pub async fn prepare_any(
    identity: Identity,
    peer: NodeId,
    token: PunchToken,
    spec: String,
    families: NetworkFamilies,
) -> Result<PreparedTransport> {
    prepare_any_with_progress(identity, peer, token, spec, families, None).await
}
async fn prepare_any_with_progress(
    identity: Identity,
    peer: NodeId,
    token: PunchToken,
    spec: String,
    families: NetworkFamilies,
    progress: Option<Progress>,
) -> Result<PreparedTransport> {
    let addresses = resolve(&spec, families).await?;
    let mut tasks = tokio::task::JoinSet::new();
    let has_v6 = addresses.iter().any(SocketAddr::is_ipv6);
    for (index, server) in addresses.into_iter().enumerate() {
        let identity = identity.clone();
        let progress = progress.clone();
        tasks.spawn(async move {
            let delay = if has_v6 && server.is_ipv4() {
                crate::net::race::FAMILY_STAGGER
            } else {
                Duration::ZERO
            } + crate::net::race::CANDIDATE_STAGGER * index as u32;
            tokio::time::sleep(delay).await;
            prepare_with_progress(&identity, peer, token, server, progress).await
        });
    }
    crate::net::race::select_prepared(tasks).await
}

pub async fn await_peer_selection(
    identity: Identity,
    peer: NodeId,
    token: PunchToken,
    spec: String,
    families: NetworkFamilies,
) -> Result<ConnectionGuard> {
    await_peer_selection_with_progress(identity, peer, token, spec, families, None).await
}
async fn await_peer_selection_with_progress(
    identity: Identity,
    peer: NodeId,
    token: PunchToken,
    spec: String,
    families: NetworkFamilies,
    progress: Option<Progress>,
) -> Result<ConnectionGuard> {
    // Keep all prepared candidates participating until the peer's FIN selects
    // one; choosing the first RelayReady or local handshake would split winners.
    let addresses = resolve(&spec, families).await?;
    let mut tasks = tokio::task::JoinSet::new();
    let has_v6 = addresses.iter().any(SocketAddr::is_ipv6);
    for (index, server) in addresses.into_iter().enumerate() {
        let identity = identity.clone();
        let progress = progress.clone();
        tasks.spawn(async move {
            let delay = if has_v6 && server.is_ipv4() {
                crate::net::race::FAMILY_STAGGER
            } else {
                Duration::ZERO
            } + crate::net::race::CANDIDATE_STAGGER * index as u32;
            tokio::time::sleep(delay).await;
            prepare_with_progress(&identity, peer, token, server, progress)
                .await?
                .wait_for_selection()
                .await
        });
    }
    let mut failures = Vec::new();
    let result = loop {
        match tasks.join_next().await {
            Some(Ok(Ok(winner))) => break Ok(winner),
            Some(Ok(Err(error))) => failures.push(error.to_string()),
            Some(Err(error)) => failures.push(error.to_string()),
            None => {
                break Err(Error::Transport(format!(
                    "no selected Relay transport: {}",
                    failures.join("; ")
                )));
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

/// Validate local configuration without DNS or network traffic.
pub fn validate_server_spec(spec: &str) -> Result<()> {
    if spec.len() > 300 || spec.trim() != spec || spec.chars().any(char::is_whitespace) {
        return Err(Error::Discovery(
            "Relay must be HOST:PORT or [IPv6]:PORT".into(),
        ));
    }
    if let Ok(address) = spec.parse::<SocketAddr>() {
        if crate::net::family::usable_address(address) {
            return Ok(());
        }
        return Err(Error::Discovery(
            "Relay address must be native, usable and have a nonzero port".into(),
        ));
    }
    let (host, port) = spec
        .rsplit_once(':')
        .ok_or_else(|| Error::Discovery("Relay requires HOST:PORT".into()))?;
    if port.parse::<u16>().ok().is_none_or(|port| port == 0)
        || host.is_empty()
        || host.len() > 253
        || host.contains(':')
    {
        return Err(Error::Discovery("invalid Relay host or port".into()));
    }
    for label in host.strip_suffix('.').unwrap_or(host).split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(Error::Discovery("invalid Relay hostname".into()));
        }
    }
    if host.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return Err(Error::Discovery("invalid Relay IPv4 address".into()));
    }
    Ok(())
}
