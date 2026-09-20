//! 节点发现：局域网组播、公网信令。

pub mod mdns;
pub mod signal;

pub use mdns::{
    LanDiscovery, PeerAnnouncement, SERVICE_TYPE, local_ip_addresses, parse_announcement,
};
pub use signal::{
    Candidate, CandidateKind, DEFAULT_SIGNAL_PORT, LookupOutcome, PeerOffer, SignalMessage,
    SignalingClient, dedup_candidates, run_signal_server, run_signal_server_on, sort_candidates,
};
