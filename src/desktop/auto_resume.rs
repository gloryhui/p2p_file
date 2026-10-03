//! Current-process recovery intentions. Nothing in this module is serialized.
use super::task_model::{TaskDirection, TaskId};
use crate::identity::NodeId;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const MAX_TASKS: usize = 256;
const MAX_ATTEMPTS: u8 = 5;
const LIFETIME: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub(super) struct Ticket {
    pub id: TaskId,
    pub peer: NodeId,
    pub direction: TaskDirection,
    nonce: u64,
    revision: u64,
    pub deadline: Option<Instant>,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Ticket {
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }
}
struct Intent {
    ticket: Ticket,
    waiting: bool,
    inflight: bool,
    network: bool,
    attempts: u8,
    expires: Option<Instant>,
    due: Instant,
}
#[derive(Default)]
pub(super) struct Recovery {
    enabled: bool,
    nonce: u64,
    tasks: HashMap<TaskId, Intent>,
}
impl Recovery {
    pub fn enable(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            for i in self.tasks.values_mut() {
                i.ticket.cancel();
                i.waiting = false;
                i.inflight = false;
            }
        }
    }
    pub fn clear(&mut self) {
        for i in self.tasks.values() {
            i.ticket.cancel();
        }
        self.tasks.clear();
    }
    pub fn cancel(&mut self, id: &TaskId) -> bool {
        self.tasks.remove(id).is_some_and(|i| {
            i.ticket.cancel();
            i.waiting
        })
    }
    pub fn forget(&mut self, id: &TaskId) {
        self.tasks.remove(id);
    }
    pub fn enroll(&mut self, id: TaskId, peer: NodeId, direction: TaskDirection) {
        self.nonce = self.nonce.wrapping_add(1);
        if let Some(intent) = self.tasks.get_mut(&id) {
            intent.ticket.revision = intent.ticket.revision.wrapping_add(1);
            // A received Offer or an admitted sender supersedes a pending RPC.
            intent.waiting = false;
            intent.inflight = false;
            return;
        }
        if self.tasks.len() >= MAX_TASKS {
            return;
        }
        self.nonce = self.nonce.wrapping_add(1);
        self.tasks.insert(
            id.clone(),
            Intent {
                ticket: Ticket {
                    id,
                    peer,
                    direction,
                    nonce: self.nonce,
                    revision: 0,
                    deadline: None,
                    cancelled: Default::default(),
                },
                waiting: false,
                inflight: false,
                network: false,
                attempts: 0,
                expires: None,
                due: Instant::now(),
            },
        );
    }
    pub fn lost(&mut self, peer: NodeId, now: Instant) {
        self.nonce = self.nonce.wrapping_add(1);
        for intent in self.tasks.values_mut().filter(|i| i.ticket.peer == peer) {
            if intent.waiting {
                continue;
            }
            intent.ticket.cancel();
            intent.ticket.nonce = self.nonce;
            intent.ticket.revision = intent.ticket.revision.wrapping_add(1);
            intent.ticket.cancelled = Default::default();
            intent.network = true;
            intent.waiting = self.enabled;
            intent.inflight = false;
            intent.ticket.deadline = Some(*intent.expires.get_or_insert(now + LIFETIME));
            // Sender goes first. A receiver requests continuation only if no
            // new Offer arrives, allowing either device alone to opt in.
            intent.due = now
                + Duration::from_secs(if intent.ticket.direction == TaskDirection::Send {
                    1
                } else {
                    4
                });
        }
    }
    pub fn valid(&self, ticket: &Ticket) -> bool {
        self.tasks.get(&ticket.id).is_some_and(|i| {
            i.ticket.nonce == ticket.nonce
                && i.waiting
                && i.expires.is_some_and(|t| t > Instant::now())
        })
    }
    pub fn pending(&self, id: &TaskId) -> bool {
        self.tasks
            .get(id)
            .is_some_and(|i| i.waiting && i.expires.is_some_and(|t| t > Instant::now()))
    }
    pub fn network_tasks(&self, peer: NodeId) -> Vec<Ticket> {
        self.tasks
            .values()
            .filter(|i| i.ticket.peer == peer && i.network)
            .map(|i| i.ticket.clone())
            .collect()
    }
    pub fn same_attempt(&self, ticket: &Ticket) -> bool {
        self.tasks
            .get(&ticket.id)
            .is_some_and(|i| i.ticket.nonce == ticket.nonce && i.ticket.revision == ticket.revision)
    }
    pub fn started(&self, ticket: &Ticket) -> bool {
        self.tasks
            .get(&ticket.id)
            .is_some_and(|i| i.ticket.nonce == ticket.nonce && i.ticket.revision != ticket.revision)
    }
    pub fn stop_ticket(&mut self, ticket: &Ticket) {
        if self.same_attempt(ticket)
            && let Some(i) = self.tasks.get_mut(&ticket.id)
        {
            i.ticket.cancel();
            i.waiting = false;
            i.inflight = false;
        }
    }
    pub fn automatic_allowed(&self, id: &TaskId) -> bool {
        self.tasks
            .get(id)
            .is_some_and(|i| i.network && i.expires.is_some_and(|t| t > Instant::now()))
    }
    pub fn cancel_peer(&mut self, peer: NodeId) -> bool {
        let pending = self
            .tasks
            .values()
            .any(|i| i.ticket.peer == peer && i.waiting);
        self.tasks.retain(|_, i| {
            if i.ticket.peer == peer {
                i.ticket.cancel();
                false
            } else {
                true
            }
        });
        pending
    }
    pub fn cancel_denied(&mut self, peer: NodeId, rights: super::remote_auth::RemoteAuthorization) {
        self.tasks.retain(|_, i| {
            let keep = i.ticket.peer != peer
                || match i.ticket.direction {
                    TaskDirection::Send => rights.outbound_authorized(),
                    TaskDirection::Receive => rights.inbound_authorized(),
                };
            if !keep {
                i.ticket.cancel();
            }
            keep
        });
    }
    /// Advance once per maintenance tick. `ready` means a freshly authenticated
    /// connection with the required direction(s), `busy` means an attempt is
    /// already owned by Session. At most one lookup per peer is returned.
    pub fn due(
        &mut self,
        now: Instant,
        mut ready: impl FnMut(NodeId, TaskDirection) -> bool,
        mut busy: impl FnMut(NodeId) -> bool,
    ) -> (Vec<NodeId>, Vec<Ticket>) {
        self.tasks.retain(|_, i| {
            i.expires.is_none_or(|t| t > now)
                && (!i.waiting || i.attempts < MAX_ATTEMPTS || i.inflight)
        });
        let mut peers = Vec::new();
        let mut jobs = Vec::new();
        for i in self.tasks.values_mut() {
            if !i.waiting || i.inflight || i.due > now {
                continue;
            }
            if ready(i.ticket.peer, i.ticket.direction) {
                i.inflight = true;
                i.attempts += 1;
                jobs.push(i.ticket.clone());
            } else if !busy(i.ticket.peer) {
                i.attempts += 1;
                i.due = now + Duration::from_secs(1 << i.attempts.min(5));
                if !peers.contains(&i.ticket.peer) {
                    peers.push(i.ticket.peer);
                }
            }
        }
        (peers, jobs)
    }
    pub fn admitted(&mut self, id: &TaskId) {
        if let Some(i) = self.tasks.get_mut(id) {
            i.waiting = false;
            i.inflight = false;
        }
    }
    pub fn finished(&mut self, ticket: &Ticket) {
        if let Some(i) = self.tasks.get_mut(&ticket.id)
            && i.ticket.nonce == ticket.nonce
        {
            i.inflight = false;
            i.due = Instant::now() + Duration::from_secs(1 << i.attempts.min(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(enabled: bool) -> (Recovery, TaskId, NodeId, Instant) {
        let mut r = Recovery::default();
        r.enable(enabled);
        let peer = crate::identity::Identity::generate().node_id();
        let id = TaskId::generate();
        r.enroll(id.clone(), peer, TaskDirection::Send);
        let now = Instant::now();
        r.lost(peer, now);
        (r, id, peer, now)
    }
    #[test]
    fn enrollment_is_bounded_and_completion_releases_capacity() {
        let mut r = Recovery::default();
        let peer = crate::identity::Identity::generate().node_id();
        let ids: Vec<_> = (0..MAX_TASKS + 4).map(|_| TaskId::generate()).collect();
        for id in &ids {
            r.enroll(id.clone(), peer, TaskDirection::Send);
        }
        assert_eq!(r.tasks.len(), MAX_TASKS);
        r.forget(&ids[0]);
        r.enroll(ids[MAX_TASKS].clone(), peer, TaskDirection::Send);
        assert_eq!(r.tasks.len(), MAX_TASKS);
        assert!(r.tasks.contains_key(&ids[MAX_TASKS]));
    }
    #[test]
    fn opt_in_and_restart_never_replay_old_intentions() {
        let (mut r, id, _, now) = setup(false);
        assert!(!r.pending(&id));
        assert!(r.automatic_allowed(&id));
        assert!(
            r.due(now + Duration::from_secs(10), |_, _| true, |_| false)
                .1
                .is_empty()
        );
        r.enable(true);
        assert!(!r.pending(&id));
        assert!(!Recovery::default().automatic_allowed(&id));
    }
    #[test]
    fn pause_setting_off_revocation_and_shutdown_cancel_running_tickets() {
        for kind in 0..4 {
            let (mut r, id, peer, now) = setup(true);
            let (_, mut jobs) = r.due(now + Duration::from_secs(1), |_, _| true, |_| false);
            let ticket = jobs.pop().unwrap();
            match kind {
                0 => {
                    r.cancel(&id);
                }
                1 => r.enable(false),
                2 => r.cancel_denied(
                    peer,
                    super::super::remote_auth::RemoteAuthorization::default(),
                ),
                _ => r.clear(),
            }
            assert!(ticket.cancelled());
            assert!(!r.pending(&id));
            assert!(!r.valid(&ticket));
        }
    }
    #[test]
    fn backoff_attempts_deadline_and_pending_lookup_are_bounded() {
        let (mut r, id, peer, now) = setup(true);
        assert!(
            r.due(now + Duration::from_secs(1), |_, _| false, |_| true)
                .0
                .is_empty()
        );
        for seconds in [1, 3, 7, 15, 31] {
            assert_eq!(
                r.due(now + Duration::from_secs(seconds), |_, _| false, |_| false)
                    .0,
                [peer]
            );
            assert!(
                r.due(now + Duration::from_secs(seconds), |_, _| false, |_| false)
                    .0
                    .is_empty()
            );
        }
        assert!(!r.pending(&id));
        let (mut r, id, _, now) = setup(true);
        assert!(r.due(now + LIFETIME, |_, _| true, |_| false).1.is_empty());
        assert!(!r.pending(&id));
    }
    #[test]
    fn incoming_offer_supersedes_waiting_rpc_without_cancelling_its_ack() {
        let (mut r, id, peer, now) = setup(true);
        let ticket = r
            .due(now + Duration::from_secs(1), |_, _| true, |_| false)
            .1
            .pop()
            .unwrap();
        r.enroll(id.clone(), peer, TaskDirection::Send);
        assert!(!r.pending(&id));
        assert!(!r.same_attempt(&ticket));
        assert!(!ticket.cancelled());
        r.forget(&id);
        assert!(!ticket.cancelled());
    }
    #[test]
    fn receiver_yields_to_sender_and_duplicate_jobs_cannot_start() {
        let (mut r, _, peer, now) = setup(true);
        let rx = TaskId::generate();
        r.enroll(rx.clone(), peer, TaskDirection::Receive);
        r.lost(peer, now);
        let (lookups, jobs) = r.due(now + Duration::from_secs(1), |_, _| true, |_| false);
        assert!(lookups.is_empty());
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].direction, TaskDirection::Send);
        assert!(
            r.due(now + Duration::from_secs(2), |_, _| true, |_| false)
                .1
                .is_empty()
        );
        let jobs = r
            .due(now + Duration::from_secs(4), |_, _| true, |_| false)
            .1;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, rx);
    }
    #[test]
    fn one_lookup_per_peer_and_directional_revocation_preserves_other_work() {
        let (mut r, _, peer, now) = setup(true);
        let receiver = TaskId::generate();
        r.enroll(receiver.clone(), peer, TaskDirection::Receive);
        r.lost(peer, now);
        assert_eq!(
            r.due(now + Duration::from_secs(4), |_, _| false, |_| false)
                .0,
            [peer]
        );
        r.cancel_denied(
            peer,
            super::super::remote_auth::RemoteAuthorization {
                inbound: super::super::remote_auth::AuthorizationGrant::password(true),
                outbound: Default::default(),
            },
        );
        assert!(r.pending(&receiver));
        assert_eq!(r.tasks.len(), 1);
    }
}
