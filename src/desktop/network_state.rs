//! Bounded, generation-fenced network state used by the long-lived desktop session.

use std::collections::HashMap;
use std::time::Duration;

use crate::identity::NodeId;

pub const MAX_PEERS: usize = 16;
pub const MAX_PENDING_PEERS: usize = 8;
pub const PEER_LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkLifecycle {
    Unconfigured,
    ConnectingSignal,
    SignalOnline,
    ReconnectingSignal {
        attempt: u32,
        delay: Duration,
    },
    PeerPending {
        peer: NodeId,
    },
    Punching {
        peer: NodeId,
    },
    Authenticating {
        peer: NodeId,
    },
    Connected {
        peer: NodeId,
    },
    Disconnected {
        peer: Option<NodeId>,
        detail: String,
    },
    Failed {
        detail: String,
    },
}

impl NetworkLifecycle {
    pub fn label(&self) -> String {
        match self {
            Self::Unconfigured => "未配置网络".into(),
            Self::ConnectingSignal => "正在连接信令".into(),
            Self::SignalOnline => "信令在线；等待对端".into(),
            Self::ReconnectingSignal { attempt, .. } => {
                format!("信令断开；正在第 {attempt} 次重连")
            }
            Self::PeerPending { peer } => format!("等待对端 {} 上线", peer.short()),
            Self::Punching { peer } => format!("正在连接对端 {}", peer.short()),
            Self::Authenticating { peer } => format!("正在认证对端 {}", peer.short()),
            Self::Connected { peer } => format!("桌面协议已就绪 {}", peer.short()),
            Self::Disconnected { peer, detail } => match peer {
                Some(peer) => format!("对端 {} 已断开：{detail}", peer.short()),
                None => format!("网络已断开：{detail}"),
            },
            Self::Failed { detail } => format!("网络启动失败：{detail}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerLifecycle {
    PeerPending,
    Punching,
    Authenticating,
    Negotiating,
    Connected,
    Disconnected,
    Failed(String),
}

impl PeerLifecycle {
    fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::PeerPending | Self::Punching | Self::Authenticating | Self::Negotiating
        )
    }

    pub(super) fn is_active(&self) -> bool {
        self.is_pending() || matches!(self, Self::Connected)
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Disconnected | Self::Failed(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginPeerAttempt {
    Started(u64),
    AlreadyActive(u64),
    AtCapacity,
}

#[derive(Clone, Debug)]
struct PeerRecord {
    generation: u64,
    state: PeerLifecycle,
    started: tokio::time::Instant,
}

/// A small registry that prevents duplicate work and rejects stale callbacks.
#[derive(Debug, Default)]
pub struct PeerRegistry {
    peers: HashMap<NodeId, PeerRecord>,
    next_generation: u64,
}

impl PeerRegistry {
    pub fn begin_attempt(&mut self, peer: NodeId) -> BeginPeerAttempt {
        if let Some(record) = self.peers.get(&peer)
            && record.state.is_active()
        {
            return BeginPeerAttempt::AlreadyActive(record.generation);
        }

        let pending = self
            .peers
            .values()
            .filter(|record| record.state.is_pending())
            .count();
        if pending >= MAX_PENDING_PEERS {
            return BeginPeerAttempt::AtCapacity;
        }

        if self.peers.len() >= MAX_PEERS {
            let oldest_terminal = self
                .peers
                .iter()
                .filter(|(_, record)| record.state.is_terminal())
                .min_by_key(|(_, record)| record.generation)
                .map(|(peer, _)| *peer);
            if let Some(oldest_terminal) = oldest_terminal {
                self.peers.remove(&oldest_terminal);
            }
        }
        if self.peers.len() >= MAX_PEERS {
            return BeginPeerAttempt::AtCapacity;
        }

        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let generation = self.next_generation;
        self.peers.insert(
            peer,
            PeerRecord {
                generation,
                state: PeerLifecycle::PeerPending,
                started: tokio::time::Instant::now(),
            },
        );
        BeginPeerAttempt::Started(generation)
    }

    pub fn transition(&mut self, peer: NodeId, generation: u64, state: PeerLifecycle) -> bool {
        let Some(record) = self.peers.get_mut(&peer) else {
            return false;
        };
        if record.generation != generation || record.state.is_terminal() {
            return false;
        }
        record.state = state;
        true
    }

    pub fn active_peers(&self) -> Vec<(NodeId, u64)> {
        self.peers
            .iter()
            .filter(|(_, record)| record.state.is_active())
            .map(|(peer, record)| (*peer, record.generation))
            .collect()
    }

    pub fn expired_lookups(&self, now: tokio::time::Instant) -> Vec<(NodeId, u64)> {
        self.peers
            .iter()
            .filter(|(_, record)| {
                record.state == PeerLifecycle::PeerPending
                    && now.saturating_duration_since(record.started) >= PEER_LOOKUP_TIMEOUT
            })
            .map(|(peer, record)| (*peer, record.generation))
            .collect()
    }

    pub fn generation(&self, peer: NodeId) -> Option<u64> {
        self.peers.get(&peer).map(|record| record.generation)
    }

    pub fn state(&self, peer: NodeId) -> Option<&PeerLifecycle> {
        self.peers.get(&peer).map(|record| &record.state)
    }

    pub fn is_current(&self, peer: NodeId, generation: u64) -> bool {
        self.generation(peer) == Some(generation)
    }

    #[cfg(test)]
    pub fn connected_count(&self) -> usize {
        self.peers
            .values()
            .filter(|record| record.state == PeerLifecycle::Connected)
            .count()
    }

    pub fn pending_peers(&self) -> Vec<(NodeId, u64)> {
        self.peers
            .iter()
            .filter(|(_, record)| record.state == PeerLifecycle::PeerPending)
            .map(|(peer, record)| (*peer, record.generation))
            .collect()
    }
}

/// Deterministically choose the lower NodeId as the QUIC dialer.
pub fn should_initiate_quic(local: NodeId, peer: NodeId) -> bool {
    local < peer
}

/// Capped exponential delay with caller-provided jitter in per-mille units.
pub fn reconnect_delay(attempt: u32, jitter_per_mille: i32) -> Duration {
    let base_seconds: u64 = match attempt.min(5) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        _ => 30,
    };
    let jitter = jitter_per_mille.clamp(-200, 200);
    let base_millis = base_seconds * 1_000;
    let adjusted = (i128::from(base_millis)
        + (i128::from(base_millis) * i128::from(jitter) / 1_000))
        .clamp(250, MAX_RECONNECT_DELAY.as_millis() as i128) as u64;
    Duration::from_millis(adjusted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId::from_hex(&format!("{byte:02x}{}", "00".repeat(15))).unwrap()
    }

    #[test]
    fn duplicate_attempts_are_bounded_and_third_peer_can_progress() {
        let mut peers = PeerRegistry::default();
        let peer_b = node(2);
        let peer_c = node(3);
        let BeginPeerAttempt::Started(generation_b) = peers.begin_attempt(peer_b) else {
            panic!("first peer should start")
        };
        assert_eq!(
            peers.begin_attempt(peer_b),
            BeginPeerAttempt::AlreadyActive(generation_b)
        );
        assert!(peers.transition(peer_b, generation_b, PeerLifecycle::Connected));
        assert_eq!(peers.connected_count(), 1);

        let BeginPeerAttempt::Started(generation_c) = peers.begin_attempt(peer_c) else {
            panic!("third peer attempt should proceed while peer B is connected")
        };
        assert!(peers.is_current(peer_c, generation_c));
        assert_eq!(peers.connected_count(), 1);
    }

    #[test]
    fn stale_generation_cannot_overwrite_a_newer_peer_attempt() {
        let mut peers = PeerRegistry::default();
        let peer = node(4);
        let BeginPeerAttempt::Started(old_generation) = peers.begin_attempt(peer) else {
            panic!("first attempt should start")
        };
        assert!(peers.transition(peer, old_generation, PeerLifecycle::Failed("test".into())));
        let BeginPeerAttempt::Started(new_generation) = peers.begin_attempt(peer) else {
            panic!("failed peer should be retryable")
        };
        assert_ne!(old_generation, new_generation);
        assert!(!peers.transition(peer, old_generation, PeerLifecycle::Disconnected));
        assert_eq!(peers.state(peer), Some(&PeerLifecycle::PeerPending));
    }

    #[test]
    fn lower_node_id_is_the_only_designated_quic_dialer() {
        let lower = node(1);
        let higher = node(2);
        assert!(should_initiate_quic(lower, higher));
        assert!(!should_initiate_quic(higher, lower));
        assert!(!should_initiate_quic(lower, lower));
    }

    #[tokio::test(start_paused = true)]
    async fn offline_lookup_expires_and_late_same_generation_cannot_resurrect_it() {
        let mut peers = PeerRegistry::default();
        let peer = node(9);
        let BeginPeerAttempt::Started(generation) = peers.begin_attempt(peer) else {
            panic!()
        };
        assert!(
            peers
                .expired_lookups(tokio::time::Instant::now())
                .is_empty()
        );
        tokio::time::advance(PEER_LOOKUP_TIMEOUT).await;
        assert_eq!(
            peers.expired_lookups(tokio::time::Instant::now()),
            vec![(peer, generation)]
        );
        assert!(peers.transition(peer, generation, PeerLifecycle::Failed("offline".into())));
        assert!(!peers.transition(peer, generation, PeerLifecycle::Connected));
        let BeginPeerAttempt::Started(new_generation) = peers.begin_attempt(peer) else {
            panic!()
        };
        assert_ne!(generation, new_generation);
    }

    #[test]
    fn reconnect_backoff_doubles_then_caps_with_jitter() {
        let seconds = (0..5)
            .map(|attempt| reconnect_delay(attempt, 0).as_secs())
            .collect::<Vec<_>>();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16]);
        assert!(reconnect_delay(5, 200).as_secs() <= MAX_RECONNECT_DELAY.as_secs());
        assert!(reconnect_delay(0, -200) >= Duration::from_millis(250));
    }
}
