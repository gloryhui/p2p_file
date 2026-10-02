//! Pairing admission and raw datagram forwarding; no QUIC or ControlMessage decoding.
use super::wire::{self, Challenge, Hello, Packet};
use crate::identity::{NodeId, public_key_from_bytes};
use crate::nat::punch::PunchToken;
use crate::net::AddressFamily;
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

pub const DEFAULT_TICKET_TTL: u64 = 60;
pub const DEFAULT_IDLE_TIMEOUT: u64 = 90;
pub const DEFAULT_MAX_SESSIONS: usize = 512;
pub const DEFAULT_PENDING_PER_IP: usize = 8;
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
        if a == b
            || state.tickets.contains_key(token.as_bytes())
            || state.tickets.len() >= state.config.max_sessions * 2
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
        let active_tokens: HashSet<_> = self.sessions.keys().map(|(token, _)| *token).collect();
        self.tickets
            .retain(|token, t| now < t.expires || active_tokens.contains(token));
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
            || self.available_arm(token, side).is_none()
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
        let Some(arm) = self.available_arm(pending.session.0, pending.side) else {
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
    fn available_arm(&self, token: Token, side: usize) -> Option<SessionKey> {
        // Prefer a waiting opposite socket. Once paired, its destination is immutable.
        if let Some(key) = self
            .sessions
            .iter()
            .filter(|((t, _), s)| {
                *t == token && s.sides[side].is_none() && s.sides[1 - side].is_some()
            })
            .map(|(key, _)| *key)
            .min()
        {
            return Some(key);
        }
        if self.sessions.len() >= self.config.max_sessions {
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
        assert!(admission.issue(next, a.node_id(), b.node_id()));
        assert!(!admission.issue(PunchToken::random(), a.node_id(), b.node_id()));
        assert!(challenge(&admission, Hello::new(&a, b.node_id(), next), source(9003)).is_none());
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
