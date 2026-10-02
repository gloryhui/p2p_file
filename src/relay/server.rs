//! Pairing admission and raw datagram forwarding; no QUIC or ControlMessage decoding.
use super::wire::{self, Challenge, Hello, Packet};
use crate::identity::{NodeId, public_key_from_bytes};
use crate::nat::punch::PunchToken;
use crate::net::AddressFamily;
use crate::{Error, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

pub const DEFAULT_TICKET_TTL: u64 = 60;
pub const DEFAULT_IDLE_TIMEOUT: u64 = 90;
pub const DEFAULT_MAX_SESSIONS: usize = 512;
pub const DEFAULT_PENDING_PER_IP: usize = 8;
pub const MAX_TICKETS_PER_PAIR: usize = 16;
pub const MAX_TICKETS_PER_NODE: usize = 64;
pub const MAX_SESSIONS_PER_PAIR: usize = 16;
pub const MAX_SESSIONS_PER_NODE: usize = 64;
pub const MAX_DATAGRAM: usize = 2048;
const CHALLENGE_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct RelayServerConfig {
    pub listen: Vec<SocketAddr>,
    pub ticket_ttl: Duration,
    pub idle_timeout: Duration,
    pub max_sessions: usize,
    pub max_pending_per_ip: usize,
}
impl Default for RelayServerConfig {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            ticket_ttl: Duration::from_secs(DEFAULT_TICKET_TTL),
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT),
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_pending_per_ip: DEFAULT_PENDING_PER_IP,
        }
    }
}
impl RelayServerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.listen.iter().any(|address| {
            address.ip().is_multicast()
                || match address {
                    SocketAddr::V4(a) => a.ip().is_broadcast(),
                    SocketAddr::V6(a) => {
                        a.scope_id() != 0
                            || a.flowinfo() != 0
                            || a.ip().is_unicast_link_local()
                            || a.ip().to_ipv4_mapped().is_some()
                    }
                }
        }) || self.listen.len() > 2
            || (self.listen.len() == 2
                && AddressFamily::of(self.listen[0]) == AddressFamily::of(self.listen[1]))
            || self.ticket_ttl.is_zero()
            || self.idle_timeout.is_zero()
            || self.ticket_ttl > Duration::from_secs(300)
            || self.idle_timeout > Duration::from_secs(3600)
            || !(1..=4096).contains(&self.max_sessions)
            || !(1..=128).contains(&self.max_pending_per_ip)
        {
            return Err(Error::Discovery(
                "invalid relay limits/listeners (one native listener per family)".into(),
            ));
        }
        Ok(())
    }
}
type Token = [u8; 16];
// Stable arms pair authenticated sockets once; they never switch destinations.
// This also permits IPv4-only and IPv6-only peers through two native listeners.
type SessionKey = (Token, u8);
const MAX_ARMS_PER_TICKET: u8 = 4;
#[derive(Clone)]
struct Ticket {
    nodes: [NodeId; 2],
    expires: Instant,
}
#[derive(Clone, Copy)]
struct Pending {
    challenge: Challenge,
    issued: Instant,
    session: SessionKey,
    side: usize,
}
#[derive(Clone, Copy)]
struct Bound {
    hello: Hello,
    source: SocketAddr,
}
struct Session {
    sides: [Option<Bound>; 2],
    last_activity: Instant,
}
impl Session {
    fn ready(&self) -> bool {
        self.sides.iter().all(Option::is_some)
    }
    fn contains_node(&self, node: NodeId) -> bool {
        self.sides
            .iter()
            .flatten()
            .any(|bound| bound.hello.node == node || bound.hello.peer == node)
    }
    fn contains_pair(&self, a: NodeId, b: NodeId) -> bool {
        self.sides.iter().flatten().any(|bound| {
            (bound.hello.node == a && bound.hello.peer == b)
                || (bound.hello.node == b && bound.hello.peer == a)
        })
    }
}

/// Shared with signaling solely for successful pairing ticket issuance.
#[derive(Clone)]
pub struct Admission(Arc<Mutex<State>>);
struct State {
    config: RelayServerConfig,
    tickets: HashMap<Token, Ticket>,
    pending: HashMap<SocketAddr, Pending>,
    sessions: HashMap<SessionKey, Session>,
    sources: HashMap<SocketAddr, (SessionKey, usize)>,
}
impl Admission {
    pub fn new(config: RelayServerConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self(Arc::new(Mutex::new(State {
            config,
            tickets: HashMap::new(),
            pending: HashMap::new(),
            sessions: HashMap::new(),
            sources: HashMap::new(),
        }))))
    }
    /// Called only after both signaling outboxes have reserved the same real pair.
    pub(crate) fn issue(&self, token: PunchToken, a: NodeId, b: NodeId) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        state.cleanup(Instant::now());
        // The bounded ticket map is the sole quota authority: no counters can
        // drift on expiry/rejection. Either order of a pair consumes one budget;
        // both nodes consume a budget even when one rotates its counterpart.
        // Clamp to half the global pool for small server configurations too.
        let pair_limit = MAX_TICKETS_PER_PAIR.min(state.config.max_sessions);
        let node_limit = MAX_TICKETS_PER_NODE.min(state.config.max_sessions);
        if a == b
            || state.tickets.contains_key(token.as_bytes())
            || state
                .sessions
                .keys()
                .any(|(active, _)| active == token.as_bytes())
            || state.tickets.len() >= state.config.max_sessions * 2
            || state
                .tickets
                .values()
                .filter(|t| t.nodes.contains(&a) && t.nodes.contains(&b))
                .count()
                >= pair_limit
            || [a, b].into_iter().any(|node| {
                state
                    .tickets
                    .values()
                    .filter(|t| t.nodes.contains(&node))
                    .count()
                    >= node_limit
            })
        {
            return false;
        }
        let expires = Instant::now() + state.config.ticket_ttl;
        state.tickets.insert(
            *token.as_bytes(),
            Ticket {
                nodes: [a, b],
                expires,
            },
        );
        true
    }
    #[cfg(test)]
    pub(crate) fn ticket_count(&self) -> usize {
        self.0.lock().unwrap().tickets.len()
    }
    fn control(
        &self,
        packet: Packet,
        source: SocketAddr,
        family: AddressFamily,
    ) -> Vec<(SocketAddr, Packet)> {
        let Ok(mut state) = self.0.lock() else {
            return Vec::new();
        };
        let now = Instant::now();
        state.cleanup(now);
        match packet {
            Packet::Hello(hello) => state.hello(hello, source, family, now),
            Packet::Register {
                challenge,
                signature_a,
                signature_b,
            } => state.register(challenge, signature_a, signature_b, source, family, now),
            _ => Vec::new(),
        }
    }
    fn forward(
        &self,
        source: SocketAddr,
        family: AddressFamily,
        now: Instant,
    ) -> Option<SocketAddr> {
        let mut state = self.0.lock().ok()?;
        let (key, side) = *state.sources.get(&source)?;
        if AddressFamily::of(source) != family {
            return None;
        }
        let idle = state.config.idle_timeout;
        let session = state.sessions.get_mut(&key)?;
        if !session.ready() || now.duration_since(session.last_activity) >= idle {
            return None;
        }
        session.last_activity = now;
        Some(session.sides[1 - side]?.source)
    }
    fn cleanup(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.cleanup(Instant::now());
        }
    }
}
impl State {
    fn cleanup(&mut self, now: Instant) {
        self.pending.retain(|_, p| {
            now.duration_since(p.issued) < CHALLENGE_TTL
                && self
                    .tickets
                    .get(&p.session.0)
                    .is_some_and(|t| now < t.expires)
        });
        self.sessions.retain(|(token, _), s| {
            now.duration_since(s.last_activity) < self.config.idle_timeout
                && (s.ready() || self.tickets.get(token).is_some_and(|t| now < t.expires))
        });
        self.sources
            .retain(|_, (key, _)| self.sessions.contains_key(key));
        // Tickets authorize new binds only. Expiry releases their quota even if
        // an already Ready session remains alive under its existing idle rule.
        self.tickets.retain(|_, t| now < t.expires);
    }
    fn validate_hello(&self, hello: Hello, now: Instant) -> Option<usize> {
        let ticket = self.tickets.get(hello.token.as_bytes())?;
        if now >= ticket.expires || hello.node == hello.peer {
            return None;
        }
        let key = public_key_from_bytes(&hello.public_key).ok()?;
        if key.is_weak() || NodeId::from_public_key(&key) != hello.node {
            return None;
        }
        ticket
            .nodes
            .iter()
            .position(|n| *n == hello.node)
            .filter(|side| ticket.nodes[1 - side] == hello.peer)
    }
    fn hello(
        &mut self,
        hello: Hello,
        source: SocketAddr,
        family: AddressFamily,
        now: Instant,
    ) -> Vec<(SocketAddr, Packet)> {
        if !family.accepts(source) {
            return Vec::new();
        }
        let Some(side) = self.validate_hello(hello, now) else {
            return Vec::new();
        };
        let token = *hello.token.as_bytes();
        if let Some((bound_key, bound_side)) = self.sources.get(&source) {
            let bound = self
                .sessions
                .get(bound_key)
                .and_then(|s| s.sides[*bound_side]);
            if bound_key.0 == token
                && *bound_side == side
                && bound.is_some_and(|b| b.hello == hello)
            {
                return self
                    .ready_packets(*bound_key)
                    .into_iter()
                    .filter(|(target, _)| *target == source)
                    .collect();
            }
            return Vec::new();
        }
        if let Some(pending) = self.pending.get(&source) {
            if pending.session.0 == token && pending.challenge.hello == hello {
                return vec![(source, challenge_packet(pending.challenge))];
            }
            return Vec::new();
        }
        if self.pending.len() >= self.config.max_sessions * 2
            || self
                .pending
                .keys()
                .filter(|addr| addr.ip() == source.ip())
                .count()
                >= self.config.max_pending_per_ip
            || self.available_arm(hello, side).is_none()
        {
            return Vec::new();
        }
        let challenge = Challenge {
            hello,
            nonce: rand::random(),
            source,
        };
        self.pending.insert(
            source,
            Pending {
                challenge,
                issued: now,
                session: (token, 0), // Allocate an arm only after the signature is verified.
                side,
            },
        );
        vec![(source, challenge_packet(challenge))]
    }
    fn register(
        &mut self,
        challenge: Challenge,
        signature_a: [u8; 32],
        signature_b: [u8; 32],
        source: SocketAddr,
        family: AddressFamily,
        now: Instant,
    ) -> Vec<(SocketAddr, Packet)> {
        let Some(pending) = self.pending.get(&source).copied() else {
            return Vec::new();
        };
        if AddressFamily::of(source) != family
            || pending.challenge != challenge
            || challenge.source != source
            || now.duration_since(pending.issued) >= CHALLENGE_TTL
            || self.validate_hello(challenge.hello, now) != Some(pending.side)
        {
            return Vec::new();
        }
        let Ok(key) = public_key_from_bytes(&challenge.hello.public_key) else {
            return Vec::new();
        };
        let Ok(payload) = wire::bind_payload(&challenge) else {
            return Vec::new();
        };
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&signature_a);
        bytes[32..].copy_from_slice(&signature_b);
        if key
            .verify_strict(&payload, &ed25519_dalek::Signature::from_bytes(&bytes))
            .is_err()
        {
            return Vec::new();
        }
        // A valid response is consumed exactly once. Neither replay nor a new
        // source with the same IP may change a ready session's binding.
        self.pending.remove(&source);
        if self.sources.contains_key(&source) {
            return Vec::new();
        }
        let Some(arm) = self.available_arm(challenge.hello, pending.side) else {
            return Vec::new();
        };
        let session = self.sessions.entry(arm).or_insert(Session {
            sides: [None, None],
            last_activity: now,
        });
        if session.sides[pending.side].is_some() {
            return Vec::new();
        }
        session.sides[pending.side] = Some(Bound {
            hello: challenge.hello,
            source,
        });
        session.last_activity = now;
        self.sources.insert(source, (arm, pending.side));
        self.ready_packets(arm)
    }
    fn available_arm(&self, hello: Hello, side: usize) -> Option<SessionKey> {
        let token = *hello.token.as_bytes();
        // Prefer a waiting opposite socket. Once paired, its destination is immutable.
        if let Some(key) = self
            .sessions
            .iter()
            .filter(|((t, _), s)| {
                *t == token
                    && s.sides[side].is_none()
                    && s.sides[1 - side].is_some_and(|bound| {
                        bound.hello.node == hello.peer && bound.hello.peer == hello.node
                    })
            })
            .map(|(key, _)| *key)
            .min()
        {
            return Some(key);
        }
        // Count real arms, including half-bound ones, from their signed Bound
        // identities. Tickets may already have expired while Ready arms live.
        // No separate counters can drift on idle cleanup. Reserve half the
        // global pool for unrelated identities even with small configurations.
        let fair_limit = (self.config.max_sessions / 2).max(1);
        let pair_limit = MAX_SESSIONS_PER_PAIR.min(fair_limit);
        let node_limit = MAX_SESSIONS_PER_NODE.min(fair_limit);
        if self.sessions.len() >= self.config.max_sessions
            || self
                .sessions
                .values()
                .filter(|session| session.contains_pair(hello.node, hello.peer))
                .count()
                >= pair_limit
            || [hello.node, hello.peer].into_iter().any(|node| {
                self.sessions
                    .values()
                    .filter(|session| session.contains_node(node))
                    .count()
                    >= node_limit
            })
        {
            return None;
        }
        (0..MAX_ARMS_PER_TICKET)
            .map(|slot| (token, slot))
            .find(|key| !self.sessions.contains_key(key))
    }
    fn ready_packets(&self, key: SessionKey) -> Vec<(SocketAddr, Packet)> {
        let Some(session) = self.sessions.get(&key).filter(|s| s.ready()) else {
            return Vec::new();
        };
        session
            .sides
            .iter()
            .flatten()
            .map(|b| {
                (
                    b.source,
                    Packet::Ready {
                        token: b.hello.token,
                        node: b.hello.node,
                        client_nonce: b.hello.client_nonce,
                    },
                )
            })
            .collect()
    }
}

fn challenge_packet(challenge: Challenge) -> Packet {
    Packet::Challenge {
        client_nonce: challenge.hello.client_nonce,
        nonce: challenge.nonce,
        source: challenge.source,
    }
}

/// One UDP task per native listener, fixed buffer, direct forwarding and no queues.
pub async fn run(socket: UdpSocket, admission: Admission) -> Result<()> {
    run_listeners(vec![socket], admission).await
}

pub async fn run_listeners(sockets: Vec<UdpSocket>, admission: Admission) -> Result<()> {
    let mut senders = HashMap::new();
    for socket in sockets {
        let family = AddressFamily::of(socket.local_addr()?);
        if senders.insert(family, Arc::new(socket)).is_some() {
            return Err(Error::Discovery("duplicate Relay listener family".into()));
        }
    }
    let senders = Arc::new(senders);
    let mut tasks = tokio::task::JoinSet::new();
    for socket in senders.values() {
        tasks.spawn(run_listener(
            socket.clone(),
            senders.clone(),
            admission.clone(),
        ));
    }
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        result => Err(Error::Discovery(format!(
            "Relay listeners stopped: {result:?}"
        ))),
    }
}

async fn run_listener(
    socket: Arc<UdpSocket>,
    senders: Arc<HashMap<AddressFamily, Arc<UdpSocket>>>,
    admission: Admission,
) -> Result<()> {
    let local = socket.local_addr()?;
    let family = AddressFamily::of(local);
    tracing::info!(%local, "Relay UDP enabled (opaque datagrams, pairing admission)");
    // Avoid Windows WSAEMSGSIZE killing the task on an oversized datagram.
    let mut buffer = [0_u8; 65_536];
    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buffer) => match received {
                Ok(received) => received,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::Interrupted) => continue,
                Err(error) => return Err(error.into()),
            },
            _ = maintenance.tick() => { admission.cleanup(); continue; }
        };
        let (length, source) = received;
        if length == 0 || length > MAX_DATAGRAM || !family.accepts(source) {
            continue;
        }
        let bytes = &buffer[..length];
        if bytes.starts_with(wire::MAGIC) {
            let Ok(packet) = wire::decode(bytes) else {
                continue;
            };
            for (target, reply) in admission.control(packet, source, family) {
                let reply = wire::encode(reply)?;
                // Every unready response fits inside its triggering request.
                // Ready notices to the other authenticated side are bounded.
                if reply.len() <= length
                    && let Some(sender) = senders.get(&AddressFamily::of(target))
                {
                    let _ = sender.send_to(&reply, target).await;
                }
            }
        } else if let Some(target) = admission.forward(source, family, Instant::now())
            && let Some(sender) = senders.get(&AddressFamily::of(target))
        {
            let _ = sender.send_to(bytes, target).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }
    fn fixture(max_sessions: usize, per_ip: usize) -> (Admission, Identity, Identity, PunchToken) {
        let admission = Admission::new(RelayServerConfig {
            max_sessions,
            max_pending_per_ip: per_ip,
            ..Default::default()
        })
        .unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let token = PunchToken::random();
        assert!(admission.issue(token, a.node_id(), b.node_id()));
        (admission, a, b, token)
    }
    fn challenge(admission: &Admission, hello: Hello, addr: SocketAddr) -> Option<Challenge> {
        let replies = admission.control(Packet::Hello(hello), addr, AddressFamily::Ipv4);
        let (
            _,
            Packet::Challenge {
                client_nonce,
                nonce,
                source,
            },
        ) = replies.first()?
        else {
            return None;
        };
        assert_eq!(*client_nonce, hello.client_nonce);
        let response = Challenge {
            hello,
            nonce: *nonce,
            source: *source,
        };
        assert!(
            wire::encode(replies[0].1).unwrap().len()
                <= wire::encode(Packet::Hello(hello)).unwrap().len()
        );
        Some(response)
    }
    fn bind_side(
        admission: &Admission,
        identity: &Identity,
        peer: NodeId,
        token: PunchToken,
        source: SocketAddr,
    ) -> (Hello, Packet, Vec<(SocketAddr, Packet)>) {
        let hello = Hello::new(identity, peer, token);
        let challenge = challenge(admission, hello, source).unwrap();
        let register = wire::register(identity, challenge).unwrap();
        let replies = admission.control(register, source, AddressFamily::Ipv4);
        assert!(
            replies
                .iter()
                .map(|(_, packet)| wire::encode(*packet).unwrap().len())
                .sum::<usize>()
                <= wire::encode(register).unwrap().len()
        );
        (hello, register, replies)
    }
    #[test]
    fn relay_session_pair_quota_counts_half_bound_arms_in_both_directions() {
        let (admission, a, b, first) = fixture(128, 8);
        let mut bindings = Vec::new();
        for ticket_index in 0..MAX_SESSIONS_PER_PAIR / MAX_ARMS_PER_TICKET as usize {
            let token = if ticket_index == 0 {
                first
            } else {
                let token = PunchToken::random();
                assert!(admission.issue(token, b.node_id(), a.node_id()));
                token
            };
            let (owner, peer) = if ticket_index % 2 == 0 {
                (&a, &b)
            } else {
                (&b, &a)
            };
            for _ in 0..MAX_ARMS_PER_TICKET {
                let port = 10000 + bindings.len() as u16 * 2;
                assert!(
                    bind_side(&admission, owner, peer.node_id(), token, source(port))
                        .2
                        .is_empty()
                );
                bindings.push((token, owner, peer, port));
            }
        }
        assert_eq!(
            admission.0.lock().unwrap().sessions.len(),
            MAX_SESSIONS_PER_PAIR
        );
        let token = PunchToken::random();
        assert!(admission.issue(token, a.node_id(), b.node_id()));
        for (owner, peer) in [(&a, &b), (&b, &a)] {
            assert!(
                challenge(
                    &admission,
                    Hello::new(owner, peer.node_id(), token),
                    source(11000)
                )
                .is_none()
            );
        }
        // Completing an existing arm consumes no new quota. Ready still counts
        // once, rather than once per bound socket.
        for (token, owner, peer, port) in bindings {
            assert_eq!(
                bind_side(&admission, peer, owner.node_id(), token, source(port + 1))
                    .2
                    .len(),
                2
            );
        }
        assert_eq!(
            admission.0.lock().unwrap().sessions.len(),
            MAX_SESSIONS_PER_PAIR
        );
        assert!(
            challenge(
                &admission,
                Hello::new(&a, b.node_id(), token),
                source(11000)
            )
            .is_none()
        );
        let c = Identity::generate();
        let d = Identity::generate();
        let cd = PunchToken::random();
        assert!(admission.issue(cd, c.node_id(), d.node_id()));
        bind_side(&admission, &c, d.node_id(), cd, source(11001));
        assert_eq!(
            bind_side(&admission, &d, c.node_id(), cd, source(11002))
                .2
                .len(),
            2
        );
    }
    #[test]
    fn relay_session_node_quota_counts_peer_identity_across_rotating_pairs() {
        let (admission, a, b, token) = fixture(256, 8);
        // Only counterparts sign these half-bound arms. The unbound A identity
        // still owns every session, irrespective of ticket order or signer.
        for i in 0..MAX_SESSIONS_PER_NODE / 2 {
            let peer = if i == 0 {
                b.clone()
            } else {
                Identity::generate()
            };
            let token = if i == 0 {
                token
            } else {
                let token = PunchToken::random();
                let (left, right) = if i % 2 == 0 {
                    (a.node_id(), peer.node_id())
                } else {
                    (peer.node_id(), a.node_id())
                };
                assert!(admission.issue(token, left, right));
                token
            };
            for arm in 0..2 {
                bind_side(
                    &admission,
                    &peer,
                    a.node_id(),
                    token,
                    source(12000 + i as u16 * 2 + arm),
                );
            }
        }
        assert_eq!(
            admission.0.lock().unwrap().sessions.len(),
            MAX_SESSIONS_PER_NODE
        );
        let peer = Identity::generate();
        let token = PunchToken::random();
        assert!(admission.issue(token, peer.node_id(), a.node_id()));
        for (owner, counterpart) in [(&a, &peer), (&peer, &a)] {
            assert!(
                challenge(
                    &admission,
                    Hello::new(owner, counterpart.node_id(), token),
                    source(13000)
                )
                .is_none()
            );
        }
        let c = Identity::generate();
        let d = Identity::generate();
        let cd = PunchToken::random();
        assert!(admission.issue(cd, c.node_id(), d.node_id()));
        bind_side(&admission, &c, d.node_id(), cd, source(13001));
        assert_eq!(
            bind_side(&admission, &d, c.node_id(), cd, source(13002))
                .2
                .len(),
            2
        );
    }
    #[test]
    fn relay_session_quota_rechecks_concurrent_signed_pending_challenges() {
        let (admission, a, b, first) = fixture(8, 8);
        let mut responses = Vec::new();
        for i in 0..6 {
            let token = if i == 0 {
                first
            } else {
                let token = PunchToken::random();
                assert!(admission.issue(token, a.node_id(), b.node_id()));
                token
            };
            let addr = source(14000 + i);
            let proof = challenge(&admission, Hello::new(&a, b.node_id(), token), addr).unwrap();
            responses.push((addr, wire::register(&a, proof).unwrap()));
        }
        assert!(admission.0.lock().unwrap().sessions.is_empty());
        let barrier = Arc::new(std::sync::Barrier::new(responses.len()));
        std::thread::scope(|scope| {
            for (addr, register) in responses {
                let admission = admission.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    assert!(
                        admission
                            .control(register, addr, AddressFamily::Ipv4)
                            .is_empty()
                    );
                });
            }
        });
        let state = admission.0.lock().unwrap();
        assert_eq!(state.sessions.len(), 4);
        assert_eq!(state.sources.len(), 4);
        assert!(state.pending.is_empty());
    }
    #[test]
    fn relay_session_limits_scale_to_small_pools_and_keep_global_cap() {
        for max_sessions in [1, 2, 4, 8, 32] {
            let (admission, a, b, first) = fixture(max_sessions, 8);
            let limit = MAX_SESSIONS_PER_PAIR.min((max_sessions / 2).max(1));
            for i in 0..limit {
                let token = if i == 0 {
                    first
                } else {
                    let token = PunchToken::random();
                    assert!(admission.issue(token, a.node_id(), b.node_id()));
                    token
                };
                bind_side(
                    &admission,
                    &a,
                    b.node_id(),
                    token,
                    source(15000 + i as u16 * 2),
                );
                assert_eq!(
                    bind_side(
                        &admission,
                        &b,
                        a.node_id(),
                        token,
                        source(15001 + i as u16 * 2)
                    )
                    .2
                    .len(),
                    2
                );
            }
            assert!(
                challenge(
                    &admission,
                    Hello::new(&a, b.node_id(), first),
                    source(15100)
                )
                .is_none()
            );
            for i in limit..max_sessions {
                let c = Identity::generate();
                let d = Identity::generate();
                let token = PunchToken::random();
                // Retire tickets only, leaving live arms independent of them.
                {
                    let mut state = admission.0.lock().unwrap();
                    state.tickets.clear();
                }
                assert!(admission.issue(token, c.node_id(), d.node_id()));
                bind_side(
                    &admission,
                    &c,
                    d.node_id(),
                    token,
                    source(15200 + i as u16 * 2),
                );
                assert_eq!(
                    bind_side(
                        &admission,
                        &d,
                        c.node_id(),
                        token,
                        source(15201 + i as u16 * 2)
                    )
                    .2
                    .len(),
                    2
                );
            }
            let c = Identity::generate();
            let d = Identity::generate();
            let token = PunchToken::random();
            admission.0.lock().unwrap().tickets.clear();
            assert!(admission.issue(token, c.node_id(), d.node_id()));
            assert!(
                challenge(
                    &admission,
                    Hello::new(&c, d.node_id(), token),
                    source(15300)
                )
                .is_none()
            );
            assert_eq!(admission.0.lock().unwrap().sessions.len(), max_sessions);
        }
    }
    #[test]
    fn relay_half_bound_session_idle_cleanup_releases_pair_and_node_quotas() {
        let (admission, a, b, token) = fixture(2, 8);
        bind_side(&admission, &a, b.node_id(), token, source(16000));
        assert!(
            challenge(
                &admission,
                Hello::new(&a, b.node_id(), token),
                source(16001)
            )
            .is_none()
        );
        let peer = Identity::generate();
        let next = PunchToken::random();
        assert!(admission.issue(next, a.node_id(), peer.node_id()));
        assert!(
            challenge(
                &admission,
                Hello::new(&peer, a.node_id(), next),
                source(16002)
            )
            .is_none()
        );
        {
            let mut state = admission.0.lock().unwrap();
            let idle = state.config.idle_timeout;
            state.sessions.values_mut().next().unwrap().last_activity = Instant::now() - idle;
            state.cleanup(Instant::now());
            assert!(state.sessions.is_empty());
            assert!(state.sources.is_empty());
            assert_eq!(state.tickets.len(), 2);
        }
        bind_side(&admission, &peer, a.node_id(), next, source(16002));
        assert_eq!(
            bind_side(&admission, &a, peer.node_id(), next, source(16003))
                .2
                .len(),
            2
        );
    }
    #[tokio::test]
    async fn relay_live_udp_after_ticket_expiry_cannot_bypass_session_quotas() {
        let (admission, a, b, token) = fixture(2, 8);
        let listener = UdpSocket::bind(source(0)).await.unwrap();
        let server = listener.local_addr().unwrap();
        let sa = UdpSocket::bind(source(0)).await.unwrap();
        let sb = UdpSocket::bind(source(0)).await.unwrap();
        bind_side(&admission, &a, b.node_id(), token, sa.local_addr().unwrap());
        bind_side(&admission, &b, a.node_id(), token, sb.local_addr().unwrap());
        let task = tokio::spawn(run(listener, admission.clone()));
        {
            let mut state = admission.0.lock().unwrap();
            state.tickets.get_mut(token.as_bytes()).unwrap().expires = Instant::now();
            state.cleanup(Instant::now());
            assert!(state.tickets.is_empty());
            assert_eq!(state.sessions.len(), 1);
        }
        let peer = Identity::generate();
        let mut buffer = [0; 256];
        for i in 0..8 {
            // Explicit expiry/aging avoids wall-clock TTL sleeps. Receipt of a
            // real opaque datagram is the barrier proving last_activity refreshed.
            let aged = Instant::now() - Duration::from_secs(30);
            admission
                .0
                .lock()
                .unwrap()
                .sessions
                .values_mut()
                .next()
                .unwrap()
                .last_activity = aged;
            let payload = [i; 128];
            let (sender, receiver) = if i % 2 == 0 { (&sa, &sb) } else { (&sb, &sa) };
            sender.send_to(&payload, server).await.unwrap();
            let (length, from) =
                tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(from, server);
            assert_eq!(&buffer[..length], payload);
            assert!(
                admission
                    .0
                    .lock()
                    .unwrap()
                    .sessions
                    .values()
                    .next()
                    .unwrap()
                    .last_activity
                    > aged
            );
            let next = PunchToken::random();
            assert!(admission.issue(next, a.node_id(), b.node_id()));
            assert!(
                challenge(&admission, Hello::new(&a, b.node_id(), next), source(17000)).is_none()
            );
            // Ticket quota is genuinely available, but rotating the peer also
            // cannot bypass the live session's per-node ownership.
            let rotated = PunchToken::random();
            assert!(admission.issue(rotated, peer.node_id(), a.node_id()));
            assert!(
                challenge(
                    &admission,
                    Hello::new(&peer, a.node_id(), rotated),
                    source(17001)
                )
                .is_none()
            );
            let mut state = admission.0.lock().unwrap();
            let now = Instant::now();
            for ticket in state.tickets.values_mut() {
                ticket.expires = now;
            }
            state.cleanup(now);
            assert_eq!(state.sessions.len(), 1);
            assert_eq!(state.sources.len(), 2);
            assert!(state.tickets.is_empty());
        }
        let c = Identity::generate();
        let d = Identity::generate();
        let cd = PunchToken::random();
        assert!(admission.issue(cd, c.node_id(), d.node_id()));
        bind_side(&admission, &c, d.node_id(), cd, source(17002));
        assert_eq!(
            bind_side(&admission, &d, c.node_id(), cd, source(17003))
                .2
                .len(),
            2
        );
        {
            let mut state = admission.0.lock().unwrap();
            let idle = state.config.idle_timeout;
            for session in state.sessions.values_mut() {
                session.last_activity = Instant::now() - idle;
            }
            state.cleanup(Instant::now());
            assert!(state.sessions.is_empty());
            assert!(state.sources.is_empty());
        }
        let next = PunchToken::random();
        assert!(admission.issue(next, a.node_id(), b.node_id()));
        bind_side(&admission, &a, b.node_id(), next, sa.local_addr().unwrap());
        assert_eq!(
            bind_side(&admission, &b, a.node_id(), next, sb.local_addr().unwrap())
                .2
                .len(),
            2
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    #[tokio::test]
    async fn relay_requires_real_pair_both_signatures_and_unique_source_before_forwarding() {
        let (admission, a, b, token) = fixture(4, 8);
        let aa = source(9001);
        let bb = source(9002);
        let invalid = [
            Hello::new(&a, b.node_id(), PunchToken::random()),
            Hello::new(&a, Identity::generate().node_id(), token),
            Hello {
                node: b.node_id(),
                ..Hello::new(&a, b.node_id(), token)
            },
            Hello {
                public_key: b.public_key_bytes(),
                ..Hello::new(&a, b.node_id(), token)
            },
        ];
        for hello in invalid {
            assert!(challenge(&admission, hello, aa).is_none());
        }
        let (hello_a, replay, ready) = bind_side(&admission, &a, b.node_id(), token, aa);
        assert!(ready.is_empty());
        assert_eq!(
            admission.forward(aa, AddressFamily::Ipv4, Instant::now()),
            None
        );
        assert!(
            admission
                .control(replay, aa, AddressFamily::Ipv4)
                .is_empty()
        );
        assert!(
            admission
                .control(replay, source(9003), AddressFamily::Ipv4)
                .is_empty()
        );
        let (_, _, ready) = bind_side(&admission, &b, a.node_id(), token, bb);
        assert_eq!(ready.len(), 2);
        assert_eq!(
            admission.forward(aa, AddressFamily::Ipv4, Instant::now()),
            Some(bb)
        );
        assert_eq!(
            admission.forward(bb, AddressFamily::Ipv4, Instant::now()),
            Some(aa)
        );
        assert_eq!(
            admission.forward(source(9003), AddressFamily::Ipv4, Instant::now()),
            None
        );
        assert_eq!(
            admission.forward(aa, AddressFamily::Ipv6, Instant::now()),
            None
        );
        let retry = admission.control(Packet::Hello(hello_a), aa, AddressFamily::Ipv4);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].0, aa);
        let new_token = PunchToken::random();
        assert!(admission.issue(new_token, a.node_id(), b.node_id()));
        assert!(challenge(&admission, Hello::new(&a, b.node_id(), new_token), aa).is_none());
        // Another source cannot inject data or reuse the old response. A fresh,
        // signed socket may participate in another bounded race arm.
        assert!(challenge(&admission, Hello::new(&a, b.node_id(), token), source(9003)).is_some());
        assert_eq!(
            admission.forward(source(9003), AddressFamily::Ipv4, Instant::now()),
            None
        );
    }
    #[tokio::test]
    async fn relay_wrong_signature_nonce_source_and_cross_domain_proof_are_rejected() {
        let (admission, a, b, token) = fixture(4, 8);
        let hello = Hello::new(&a, b.node_id(), token);
        let proof = challenge(&admission, hello, source(9001)).unwrap();
        for identity in [&b, &Identity::generate()] {
            assert!(
                admission
                    .control(
                        wire::register(identity, proof).unwrap(),
                        source(9001),
                        AddressFamily::Ipv4
                    )
                    .is_empty()
            );
        }
        let mut modified = proof;
        modified.nonce[0] ^= 1;
        assert!(
            admission
                .control(
                    wire::register(&a, modified).unwrap(),
                    source(9001),
                    AddressFamily::Ipv4
                )
                .is_empty()
        );
        assert!(
            admission
                .control(
                    wire::register(&a, proof).unwrap(),
                    source(9002),
                    AddressFamily::Ipv4
                )
                .is_empty()
        );
        let signature = a.sign(b"p2p_file/signal-register/v2").to_bytes();
        let foreign = Packet::Register {
            challenge: proof,
            signature_a: signature[..32].try_into().unwrap(),
            signature_b: signature[32..].try_into().unwrap(),
        };
        assert!(
            admission
                .control(foreign, source(9001), AddressFamily::Ipv4)
                .is_empty()
        );
        assert!(admission.0.lock().unwrap().sources.is_empty());
        // An expired challenge cannot consume admission even with a correct signature.
        admission
            .0
            .lock()
            .unwrap()
            .pending
            .get_mut(&source(9001))
            .unwrap()
            .issued = Instant::now() - CHALLENGE_TTL;
        assert!(
            admission
                .control(
                    wire::register(&a, proof).unwrap(),
                    source(9001),
                    AddressFamily::Ipv4
                )
                .is_empty()
        );
        assert!(admission.0.lock().unwrap().pending.is_empty());
    }
    #[tokio::test]
    async fn relay_ticket_challenge_session_caps_and_idle_cleanup_release_every_index() {
        let (admission, a, b, token) = fixture(1, 1);
        let hello = Hello::new(&a, b.node_id(), token);
        assert!(challenge(&admission, hello, source(9001)).is_some());
        assert!(challenge(&admission, Hello::new(&b, a.node_id(), token), source(9002)).is_none());
        let mut state = admission.0.lock().unwrap();
        state.cleanup(Instant::now() + CHALLENGE_TTL);
        assert!(state.pending.is_empty());
        drop(state);
        let (_, _, _) = bind_side(&admission, &a, b.node_id(), token, source(9001));
        let (_, _, _) = bind_side(&admission, &b, a.node_id(), token, source(9002));
        let next = PunchToken::random();
        let c = Identity::generate();
        let d = Identity::generate();
        assert!(admission.issue(next, c.node_id(), d.node_id()));
        assert!(!admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
        assert!(!admission.issue(
            PunchToken::random(),
            Identity::generate().node_id(),
            Identity::generate().node_id()
        ));
        assert!(challenge(&admission, Hello::new(&c, d.node_id(), next), source(9003)).is_none());
        let mut state = admission.0.lock().unwrap();
        let expired = Instant::now() + state.config.idle_timeout + state.config.ticket_ttl;
        state.cleanup(expired);
        assert!(state.sessions.is_empty());
        assert!(state.sources.is_empty());
        assert!(state.pending.is_empty());
        assert!(state.tickets.is_empty());
        drop(state);
        assert!(admission.issue(next, a.node_id(), b.node_id()));
        admission
            .0
            .lock()
            .unwrap()
            .tickets
            .get_mut(next.as_bytes())
            .unwrap()
            .expires = Instant::now();
        assert!(challenge(&admission, Hello::new(&a, b.node_id(), next), source(9001)).is_none());
    }
    #[test]
    fn relay_unordered_pair_ticket_quota_reserves_capacity_for_unrelated_peers() {
        let (admission, a, b, _) = fixture(128, 8);
        for i in 1..MAX_TICKETS_PER_PAIR {
            let (a, b) = if i % 2 == 0 {
                (a.node_id(), b.node_id())
            } else {
                (b.node_id(), a.node_id())
            };
            assert!(admission.issue(PunchToken::random(), a, b));
        }
        assert_eq!(admission.ticket_count(), MAX_TICKETS_PER_PAIR);
        for _ in 0..32 {
            assert!(!admission.issue(PunchToken::random(), b.node_id(), a.node_id()));
        }
        assert_eq!(admission.ticket_count(), MAX_TICKETS_PER_PAIR);
        assert!(admission.issue(
            PunchToken::random(),
            Identity::generate().node_id(),
            Identity::generate().node_id()
        ));
        assert_eq!(admission.ticket_count(), MAX_TICKETS_PER_PAIR + 1);
    }
    #[test]
    fn relay_node_ticket_quota_covers_rotating_peers_and_both_pair_positions() {
        let (admission, a, _, _) = fixture(128, 8);
        for i in 1..MAX_TICKETS_PER_NODE {
            let peer = Identity::generate().node_id();
            let (a, b) = if i % 2 == 0 {
                (a.node_id(), peer)
            } else {
                (peer, a.node_id())
            };
            assert!(admission.issue(PunchToken::random(), a, b));
        }
        assert_eq!(admission.ticket_count(), MAX_TICKETS_PER_NODE);
        for (a, b) in [
            (a.node_id(), Identity::generate().node_id()),
            (Identity::generate().node_id(), a.node_id()),
        ] {
            assert!(!admission.issue(PunchToken::random(), a, b));
        }
        assert!(admission.issue(
            PunchToken::random(),
            Identity::generate().node_id(),
            Identity::generate().node_id()
        ));
        assert_eq!(admission.ticket_count(), MAX_TICKETS_PER_NODE + 1);
    }
    #[test]
    fn relay_ticket_quotas_scale_to_small_global_pools_without_starving_other_pairs() {
        for max_sessions in [1, 4, 16] {
            let (admission, a, b, _) = fixture(max_sessions, 8);
            for _ in 1..MAX_TICKETS_PER_PAIR.min(max_sessions) {
                assert!(admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
            }
            assert!(!admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
            assert!(admission.issue(
                PunchToken::random(),
                Identity::generate().node_id(),
                Identity::generate().node_id()
            ));
            let (admission, a, _, _) = fixture(max_sessions, 8);
            for _ in 1..MAX_TICKETS_PER_NODE.min(max_sessions) {
                assert!(admission.issue(
                    PunchToken::random(),
                    a.node_id(),
                    Identity::generate().node_id()
                ));
            }
            assert!(!admission.issue(
                PunchToken::random(),
                Identity::generate().node_id(),
                a.node_id()
            ));
            assert!(admission.issue(
                PunchToken::random(),
                Identity::generate().node_id(),
                Identity::generate().node_id()
            ));
        }
    }
    #[test]
    fn relay_ticket_expiry_releases_pair_node_quotas_without_retiring_ready_session() {
        let (admission, a, b, token) = fixture(MAX_TICKETS_PER_PAIR, 8);
        bind_side(&admission, &a, b.node_id(), token, source(9001));
        bind_side(&admission, &b, a.node_id(), token, source(9002));
        for _ in 1..MAX_TICKETS_PER_PAIR {
            assert!(admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
        }
        assert!(!admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
        {
            let mut state = admission.0.lock().unwrap();
            let now = Instant::now();
            for ticket in state.tickets.values_mut() {
                ticket.expires = now;
            }
            state.cleanup(now);
            assert!(state.tickets.is_empty());
            assert!(state.pending.is_empty());
            assert_eq!(state.sessions.len(), 1);
            assert_eq!(state.sources.len(), 2);
        }
        assert_eq!(
            admission.forward(source(9001), AddressFamily::Ipv4, Instant::now()),
            Some(source(9002))
        );
        assert_eq!(
            admission.forward(source(9002), AddressFamily::Ipv4, Instant::now()),
            Some(source(9001))
        );
        assert!(challenge(&admission, Hello::new(&a, b.node_id(), token), source(9003)).is_none());
        assert!(!admission.issue(token, a.node_id(), b.node_id())); // An active token cannot be reassigned.
        let fresh = PunchToken::random();
        assert!(admission.issue(fresh, a.node_id(), b.node_id()));
        assert!(challenge(&admission, Hello::new(&a, b.node_id(), fresh), source(9001)).is_none());
        for _ in 1..MAX_TICKETS_PER_PAIR {
            assert!(admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
        }
        assert!(!admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
        let mut state = admission.0.lock().unwrap();
        let after_idle = Instant::now() + state.config.idle_timeout;
        state.cleanup(after_idle);
        assert!(state.sessions.is_empty());
        assert!(state.sources.is_empty());
    }
    #[test]
    fn relay_concurrent_ticket_issuance_cannot_exceed_pair_or_node_quota() {
        for rotating in [false, true] {
            let admission = Admission::new(RelayServerConfig::default()).unwrap();
            let a = Identity::generate().node_id();
            let b = Identity::generate().node_id();
            let barrier = std::sync::Barrier::new(4);
            let accepted = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|scope| {
                for _ in 0..4 {
                    let (admission, barrier, accepted) = (&admission, &barrier, &accepted);
                    scope.spawn(move || {
                        barrier.wait();
                        for i in 0..32 {
                            let peer = if rotating {
                                Identity::generate().node_id()
                            } else {
                                b
                            };
                            let pair = if i % 2 == 0 { (a, peer) } else { (peer, a) };
                            if admission.issue(PunchToken::random(), pair.0, pair.1) {
                                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    });
                }
            });
            let quota = if rotating {
                MAX_TICKETS_PER_NODE
            } else {
                MAX_TICKETS_PER_PAIR
            };
            assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), quota);
            assert_eq!(admission.ticket_count(), quota);
        }
    }
    #[test]
    fn relay_weak_ed25519_keys_and_unbounded_config_are_rejected() {
        let (admission, _, b, _) = fixture(4, 8);
        let mut compressed_identity = [0; 32];
        compressed_identity[0] = 1;
        let weak = public_key_from_bytes(&compressed_identity).unwrap();
        assert!(weak.is_weak());
        let node = NodeId::from_public_key(&weak);
        let token = PunchToken::random();
        assert!(admission.issue(token, node, b.node_id()));
        let hello = Hello {
            token,
            node,
            peer: b.node_id(),
            public_key: compressed_identity,
            client_nonce: [8; 32],
        };
        assert!(
            admission
                .control(Packet::Hello(hello), source(7001), AddressFamily::Ipv4)
                .is_empty()
        );
        for ttl in [Duration::ZERO, Duration::from_secs(301), Duration::MAX] {
            assert!(
                RelayServerConfig {
                    ticket_ttl: ttl,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        for listen in [
            vec!["[::ffff:127.0.0.1]:7001".parse().unwrap()],
            vec![source(7001), source(7002)],
        ] {
            assert!(
                RelayServerConfig {
                    listen,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn relay_control_has_fixed_fields_strict_version_length_and_no_trailing_data() {
        let hello = Hello::new(
            &Identity::generate(),
            Identity::generate().node_id(),
            PunchToken::random(),
        );
        let encoded = wire::encode(Packet::Hello(hello)).unwrap();
        assert_eq!(wire::decode(&encoded).unwrap(), Packet::Hello(hello));
        let mut version = encoded.clone();
        version[wire::MAGIC.len()] = 2;
        assert!(wire::decode(&version).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(wire::decode(&trailing).is_err());
        assert!(wire::decode(&vec![0; wire::MAX_CONTROL + 1]).is_err());
        for n in 0..encoded.len() {
            assert!(wire::decode(&encoded[..n]).is_err());
        }
    }
}
