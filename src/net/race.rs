//! Race through Ready; commit only the winner by finishing its dedicated handshake stream.
use super::AddressFamily;
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::transport::handshake::prepare_handshake_initiator;
use crate::transport::quic::{ChannelBinding, connect};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinSet;

pub const FAMILY_STAGGER: Duration = Duration::from_millis(200);
pub const CANDIDATE_STAGGER: Duration = Duration::from_millis(50);
pub const PATH_TIMEOUT: Duration = Duration::from_secs(10);

/// Close on errors, task cancellation and losers, even if Quinn has other handles.
pub struct ConnectionGuard(Option<quinn::Connection>);
impl ConnectionGuard {
    pub fn new(connection: quinn::Connection) -> Self {
        Self(Some(connection))
    }
    pub fn connection(&self) -> &quinn::Connection {
        self.0.as_ref().unwrap()
    }
    pub fn release(mut self) -> quinn::Connection {
        self.0.take().unwrap()
    }
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(0u32.into(), b"unselected or cancelled transport");
        }
    }
}

/// QUIC, expected NodeId, both Ed25519 signatures, TLS binding and Ready are verified.
/// The dedicated stream is kept open until this candidate wins selection.
pub struct PreparedTransport {
    guard: ConnectionGuard,
    send: quinn::SendStream,
    _recv: quinn::RecvStream,
}
impl PreparedTransport {
    pub async fn dial(
        endpoint: &quinn::Endpoint,
        remote: SocketAddr,
        identity: &Identity,
        expected: NodeId,
    ) -> Result<Self> {
        if !AddressFamily::of(endpoint.local_addr()?).accepts(remote) {
            return Err(Error::Transport(
                "QUIC candidate/path family mismatch".into(),
            ));
        }
        let connection = connect(endpoint, remote, "p2pfile").await?;
        let guard = ConnectionGuard::new(connection);
        let binding = ChannelBinding::from_connection(guard.connection())?;
        let (mut send, mut recv) = guard
            .connection()
            .open_bi()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let handshake =
            prepare_handshake_initiator(&mut send, &mut recv, identity, &binding).await?;
        if handshake.outcome.peer_node_id != expected {
            return Err(Error::Identity(format!(
                "unexpected peer: expected {expected}, got {}",
                handshake.outcome.peer_node_id
            )));
        }
        // Ready proves that the responder verified our Auth on this binding.
        handshake.finish(&mut send, &mut recv).await?;
        Ok(Self {
            guard,
            send,
            _recv: recv,
        })
    }
    pub async fn finish(self) -> Result<ConnectionGuard> {
        let Self {
            guard,
            mut send,
            _recv,
        } = self;
        // Only the selected, fully authenticated path sends FIN. Responders wait
        // for it before capabilities, Remote Auth, or business dispatch.
        send.finish().map_err(|e| Error::Transport(e.to_string()))?;
        Ok(guard)
    }
}

/// The same runner is used by Desktop and CLI. The race is bounded by candidate
/// count and per-path deadlines, and every loser is drained before returning.
pub async fn authenticated_race(
    candidates: Vec<(quinn::Endpoint, SocketAddr)>,
    identity: &Identity,
    expected: NodeId,
) -> Result<quinn::Connection> {
    authenticated_race_with_probes(candidates, Vec::new(), identity, expected).await
}

pub type ProbeObservation = (
    quinn::Endpoint,
    tokio::sync::watch::Receiver<Option<SocketAddr>>,
);
pub async fn authenticated_race_with_probes(
    candidates: Vec<(quinn::Endpoint, SocketAddr)>,
    observations: Vec<ProbeObservation>,
    identity: &Identity,
    expected: NodeId,
) -> Result<quinn::Connection> {
    let has_v6 = candidates.iter().any(|(_, addr)| addr.is_ipv6());
    let mut counts = [0_u32; 2];
    let mut tasks = JoinSet::new();
    for (endpoint, remote) in candidates
        .into_iter()
        .take(crate::discovery::signal::MAX_CANDIDATES)
    {
        let slot = usize::from(remote.is_ipv4());
        let delay = CANDIDATE_STAGGER * counts[slot]
            + if remote.is_ipv4() && has_v6 {
                FAMILY_STAGGER
            } else {
                Duration::ZERO
            };
        counts[slot] += 1;
        let identity = identity.clone();
        tasks.spawn(async move {
            tokio::time::sleep(delay).await;
            tokio::time::timeout(
                PATH_TIMEOUT,
                PreparedTransport::dial(&endpoint, remote, &identity, expected),
            )
            .await
            .map_err(|_| Error::Transport(format!("{remote} authenticated path timeout")))?
        });
    }
    for (endpoint, mut observation) in observations.into_iter().take(2) {
        let identity = identity.clone();
        tasks.spawn(async move {
            tokio::time::timeout(PATH_TIMEOUT, async {
                let remote = loop {
                    let value = *observation.borrow_and_update();
                    if let Some(remote) = value {
                        break remote;
                    }
                    observation
                        .changed()
                        .await
                        .map_err(|_| Error::Transport("probe observation closed".into()))?;
                };
                PreparedTransport::dial(&endpoint, remote, &identity, expected).await
            })
            .await
            .map_err(|_| Error::Transport("probe observation timeout".into()))?
        });
    }
    finish_prepared_race(tasks).await
}

pub async fn select_prepared(
    mut tasks: JoinSet<Result<PreparedTransport>>,
) -> Result<PreparedTransport> {
    let mut failures = Vec::new();
    let selected = loop {
        match tasks.join_next().await {
            Some(Ok(Ok(prepared))) => break Some(prepared),
            Some(Ok(Err(error))) => failures.push(error.to_string()),
            Some(Err(error)) => failures.push(error.to_string()),
            None => break None,
        }
    };
    tasks.abort_all();
    // Successful unselected results own guards, and are closed here as well.
    while tasks.join_next().await.is_some() {}
    let selected = selected.ok_or_else(|| {
        Error::Transport(format!("no authenticated path: {}", failures.join("; ")))
    })?;
    Ok(selected)
}

pub async fn finish_prepared_race(
    tasks: JoinSet<Result<PreparedTransport>>,
) -> Result<quinn::Connection> {
    let selected = select_prepared(tasks).await?;
    let guard = tokio::time::timeout(PATH_TIMEOUT, selected.finish())
        .await
        .map_err(|_| Error::Transport("selected identity handshake timed out".into()))??;
    let connection = guard.release();
    tracing::info!(family = %AddressFamily::of(connection.remote_address()), remote = %connection.remote_address(), "authenticated winner transport");
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::family::ipv6_test_available;
    use crate::transport::handshake::{handshake_responder, prepare_handshake_responder};
    use crate::transport::quic::{await_identity_commit, client_endpoint, server_endpoint};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    async fn responder(
        endpoint: quinn::Endpoint,
        identity: Identity,
        delay: Duration,
        accepted: Arc<AtomicUsize>,
        authenticated: Arc<AtomicUsize>,
    ) {
        let mut tasks = JoinSet::new();
        while let Some(incoming) = endpoint.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let identity = identity.clone();
            let authenticated = authenticated.clone();
            tasks.spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let guard = ConnectionGuard::new(connection);
                let Ok((mut send, mut recv)) = guard.connection().accept_bi().await else {
                    return;
                };
                if delay != Duration::MAX {
                    tokio::time::sleep(delay).await;
                }
                let binding = ChannelBinding::from_connection(guard.connection()).unwrap();
                if delay == Duration::MAX {
                    // Verify Auth on a real TLS-bound connection, but withhold Ready.
                    let _verified =
                        prepare_handshake_responder(&mut send, &mut recv, &identity, &binding)
                            .await;
                    let _ = guard.connection().closed().await;
                    return;
                }
                if handshake_responder(&mut send, &mut recv, &identity, &binding)
                    .await
                    .is_ok()
                    && await_identity_commit(&mut recv).await.is_ok()
                {
                    authenticated.fetch_add(1, Ordering::SeqCst);
                    let _ = send.finish();
                    let _ = guard.connection().closed().await;
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    }
    async fn race_case(
        v6_works: bool,
        v4_works: bool,
        wrong_v6: bool,
        delay_v6: Duration,
    ) -> (AddressFamily, usize, usize) {
        let identity = Identity::generate();
        let local = Identity::generate();
        let count = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let mut servers = Vec::new();
        let mut workers = JoinSet::new();
        let mut clients = Vec::new();
        let mut candidates = Vec::new();
        for (family, works) in [
            (AddressFamily::Ipv6, v6_works),
            (AddressFamily::Ipv4, v4_works),
        ] {
            let client = client_endpoint(family.loopback(0)).unwrap();
            let remote = if works {
                let server = server_endpoint(family.loopback(0)).unwrap();
                let address = server.local_addr().unwrap();
                workers.spawn(responder(
                    server.clone(),
                    if family == AddressFamily::Ipv6 && wrong_v6 {
                        Identity::generate()
                    } else {
                        identity.clone()
                    },
                    if family == AddressFamily::Ipv6 {
                        delay_v6
                    } else {
                        Duration::ZERO
                    },
                    accepted.clone(),
                    count.clone(),
                ));
                servers.push(server);
                address
            } else {
                // A held UDP socket that silently drops every QUIC datagram is a real black hole.
                let socket = crate::net::family::bind_udp(family.loopback(0)).unwrap();
                let addr = socket.local_addr().unwrap();
                workers.spawn(async move {
                    std::future::pending::<()>().await;
                    drop(socket);
                });
                addr
            };
            candidates.push((client.clone(), remote));
            clients.push(client);
        }
        let started = tokio::time::Instant::now();
        let connection = tokio::time::timeout(
            Duration::from_secs(3),
            authenticated_race(candidates, &local, identity.node_id()),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "a dead family blocked a working path"
        );
        let family = AddressFamily::of(connection.remote_address());
        tokio::time::timeout(Duration::from_secs(3), async {
            while servers
                .iter()
                .map(quinn::Endpoint::open_connections)
                .sum::<usize>()
                != 1
                || count.load(Ordering::SeqCst) != 1
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("loser must close before business winner is exposed");
        connection.close(0u32.into(), b"test complete");
        for endpoint in servers.iter().chain(&clients) {
            endpoint.close(0u32.into(), b"test complete");
        }
        for endpoint in servers.iter().chain(&clients) {
            endpoint.wait_idle().await;
        }
        // Endpoint shutdown wakes the accepted handler, including losing partial handshakes.
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        (
            family,
            count.load(Ordering::SeqCst),
            accepted.load(Ordering::SeqCst),
        )
    }
    #[tokio::test]
    async fn ipv6_fast_winner_does_not_wait_for_ipv4_blackhole() {
        if !ipv6_test_available() {
            return;
        }
        let (family, count, _) = race_case(true, false, false, Duration::ZERO).await;
        assert_eq!(family, AddressFamily::Ipv6);
        assert_eq!(count, 1);
    }
    #[tokio::test]
    async fn ipv6_blackhole_falls_back_to_ipv4_within_stagger_bound() {
        if !ipv6_test_available() {
            return;
        }
        let (family, count, _) = race_case(false, true, false, Duration::ZERO).await;
        assert_eq!(family, AddressFamily::Ipv4);
        assert_eq!(count, 1);
    }
    #[tokio::test]
    async fn fast_wrong_ipv6_identity_cannot_win_over_authenticated_ipv4() {
        if !ipv6_test_available() {
            return;
        }
        let (family, count, _) = race_case(true, true, true, Duration::ZERO).await;
        assert_eq!(family, AddressFamily::Ipv4);
        assert_eq!(count, 1);
    }
    #[tokio::test]
    async fn ipv6_ready_blackhole_cannot_block_fully_authenticated_ipv4() {
        if !ipv6_test_available() {
            return;
        }
        let (family, count, accepted) = race_case(true, true, false, Duration::MAX).await;
        assert_eq!(family, AddressFamily::Ipv4);
        assert_eq!(count, 1);
        assert_eq!(accepted, 2);
    }
    #[tokio::test]
    async fn both_live_families_commit_exactly_one_business_transport_and_close_loser() {
        if !ipv6_test_available() {
            return;
        }
        let (_, count, accepted) = race_case(true, true, false, Duration::from_millis(350)).await;
        assert_eq!(count, 1);
        assert_eq!(accepted, 2, "both real QUIC transports must have raced");
    }
}
