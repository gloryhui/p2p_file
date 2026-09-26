//! FIFO admission, byte-level write scheduling and monotonic presentation samples.
//! Network futures never run while an admission/scheduling mutex is held.
use super::task_model::{TaskId, TaskRecord, TaskState};
use crate::identity::NodeId;
use std::collections::{HashMap, VecDeque};

pub const MAX_QUEUED: usize = 4096;
pub const MAX_METADATA_ACTIVE: usize = 8;
pub const BYTE_QUANTUM: usize = 64 * 1024;
pub const MAX_DATA_WRITERS: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueEntry {
    pub id: TaskId,
    pub peer: NodeId,
    pub metadata: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueMetrics {
    pub pending: usize,
    pub active_files: usize,
    pub active_metadata: usize,
    pub limit: u8,
    pub converging: bool,
}
pub struct TaskQueue {
    pending: VecDeque<QueueEntry>,
    active: HashMap<TaskId, QueueEntry>,
    limit: u8,
    generations: HashMap<TaskId, u64>,
    next_generation: u64,
}
impl Default for TaskQueue {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            active: HashMap::new(),
            limit: 1,
            generations: HashMap::new(),
            next_generation: 0,
        }
    }
}
impl TaskQueue {
    pub fn set_limit(&mut self, value: u8) -> Result<(), &'static str> {
        if !(1..=3).contains(&value) {
            return Err("发送并发数仅支持 1、2 或 3");
        }
        self.limit = value;
        Ok(())
    }
    pub fn enqueue(&mut self, entries: Vec<QueueEntry>) -> Result<(), &'static str> {
        // Validate the complete batch before admitting any child of a selection.
        let mut candidate = self.pending.clone();
        for entry in entries {
            if let Some(existing) = self
                .active
                .get(&entry.id)
                .or_else(|| candidate.iter().find(|e| e.id == entry.id))
            {
                if existing != &entry {
                    return Err("队列任务绑定不能改变");
                }
                continue;
            }
            if candidate.len() == MAX_QUEUED {
                return Err("发送队列已达上限");
            }
            candidate.push_back(entry);
        }
        self.pending = candidate;
        Ok(())
    }
    pub fn dispatch(&mut self, connected: impl Fn(NodeId) -> bool) -> Option<QueueEntry> {
        let metrics = self.metrics();
        let position = self.pending.iter().position(|entry| {
            if !connected(entry.peer) {
                return false;
            }
            if entry.metadata {
                metrics.active_metadata < MAX_METADATA_ACTIVE
                    && self
                        .active
                        .values()
                        .filter(|a| a.metadata && a.peer == entry.peer)
                        .count()
                        < 2
            } else {
                metrics.active_files < self.limit as usize
            }
        })?;
        let generation = self.next_generation.checked_add(1)?;
        let entry = self.pending.remove(position).unwrap();
        self.next_generation = generation;
        self.generations.insert(entry.id.clone(), generation);
        self.active.insert(entry.id.clone(), entry.clone());
        Some(entry)
    }
    pub fn slot_generation(&self, id: &TaskId) -> Option<u64> {
        self.generations.get(id).copied()
    }
    pub fn finish_if(&mut self, id: &TaskId, generation: u64) {
        if self.slot_generation(id) == Some(generation) {
            self.active.remove(id);
            self.generations.remove(id);
        }
    }
    #[cfg(test)]
    fn finish(&mut self, id: &TaskId) {
        if let Some(generation) = self.slot_generation(id) {
            self.finish_if(id, generation);
        }
    }
    pub fn reserve_direct(&mut self, entry: QueueEntry) -> Result<u64, &'static str> {
        if self.active.contains_key(&entry.id) {
            return Err("任务已有发送槽");
        }
        let metrics = self.metrics();
        if (!entry.metadata && metrics.active_files >= self.limit as usize)
            || (entry.metadata
                && (metrics.active_metadata >= MAX_METADATA_ACTIVE
                    || self
                        .active
                        .values()
                        .filter(|e| e.metadata && e.peer == entry.peer)
                        .count()
                        >= 2))
        {
            return Err("发送活动已达上限");
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or("发送槽代数已耗尽")?;
        if let Some(existing) = self.pending.iter().find(|e| e.id == entry.id)
            && existing != &entry
        {
            return Err("队列任务绑定不能改变");
        }
        self.remove_queued(&entry.id);
        self.next_generation = generation;
        self.generations.insert(entry.id.clone(), generation);
        self.active.insert(entry.id.clone(), entry);
        Ok(generation)
    }
    pub fn clear(&mut self) {
        self.pending.clear();
        self.active.clear();
        self.generations.clear();
        // Retain the monotonic token so a late old guard cannot release a new slot.
    }
    pub fn remove_queued(&mut self, id: &TaskId) -> Option<QueueEntry> {
        let position = self.pending.iter().position(|entry| &entry.id == id)?;
        self.pending.remove(position)
    }
    pub fn is_queued(&self, id: &TaskId) -> bool {
        self.pending.iter().any(|e| &e.id == id)
    }
    pub fn metrics(&self) -> QueueMetrics {
        let active_files = self.active.values().filter(|e| !e.metadata).count();
        QueueMetrics {
            pending: self.pending.len(),
            active_files,
            active_metadata: self.active.len() - active_files,
            limit: self.limit,
            converging: active_files > self.limit as usize,
        }
    }
}

/// A short moving window of confirmed bytes. `now_ms` is supplied by the owner,
/// so tests need no sleeping and resumed durable bytes are a baseline, not traffic.
#[derive(Clone, Debug, Default)]
pub struct RateSampler {
    points: VecDeque<(u64, u64)>,
    latest: u64,
    last_ms: u64,
}
impl RateSampler {
    pub fn reset(&mut self, now_ms: u64, confirmed: u64) {
        self.points.clear();
        self.points.push_back((now_ms, confirmed));
        self.latest = confirmed;
        self.last_ms = now_ms;
    }
    pub fn observe(&mut self, now_ms: u64, confirmed: u64) {
        if self.points.is_empty() || now_ms < self.last_ms || confirmed < self.latest {
            self.reset(now_ms, confirmed);
            return;
        }
        self.latest = confirmed;
        self.last_ms = now_ms;
        if self.points.back().is_some_and(|(t, _)| *t == now_ms) {
            self.points.pop_back();
        }
        self.points.push_back((now_ms, confirmed));
        // Retain the point just before the two-second window when available.
        while self.points.len() > 2 && self.points[1].0 <= now_ms.saturating_sub(2000) {
            self.points.pop_front();
        }
        // Observation is at most once per 250ms in production. Still bound callers.
        while self.points.len() > 32 {
            self.points.pop_front();
        }
    }
    pub fn bytes_per_second(&self, now_ms: u64, transferring: bool) -> f64 {
        if !transferring || now_ms < self.last_ms || now_ms.saturating_sub(self.last_ms) >= 2000 {
            return 0.0;
        }
        let Some((started, bytes)) = self.points.front() else {
            return 0.0;
        };
        let elapsed = now_ms.saturating_sub(*started);
        if elapsed == 0 {
            return 0.0;
        }
        self.latest.saturating_sub(*bytes) as f64 * 1000.0 / elapsed as f64
    }
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GroupProgress {
    pub children: usize,
    pub completed: usize,
    pub failed: usize,
    pub total_bytes: u64,
    pub confirmed_bytes: u64,
    pub complete: bool,
}
pub fn group_progress(records: &[TaskRecord]) -> GroupProgress {
    let mut group = GroupProgress::default();
    for record in records {
        group.children += 1;
        group.completed += usize::from(record.state() == TaskState::Completed);
        group.failed += usize::from(matches!(
            record.state(),
            TaskState::Failed | TaskState::Interrupted
        ));
        let total = record.manifest_identity().total_bytes();
        group.total_bytes = group.total_bytes.saturating_add(total);
        let confirmed = if record.state() == TaskState::Completed {
            total
        } else {
            record
                .progress_hint()
                .map_or(0, |h| h.verified_bytes())
                .min(total)
        };
        group.confirmed_bytes = group.confirmed_bytes.saturating_add(confirmed);
    }
    group.complete = group.children > 0 && group.completed == group.children;
    group
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    fn entry(peer: NodeId, metadata: bool) -> QueueEntry {
        QueueEntry {
            id: TaskId::generate(),
            peer,
            metadata,
        }
    }
    #[test]
    fn fifo_skips_offline_peer_and_preserves_order_for_ready_tasks() {
        let offline = Identity::generate().node_id();
        let ready = Identity::generate().node_id();
        let entries = vec![
            entry(offline, false),
            entry(ready, false),
            entry(ready, false),
        ];
        let mut q = TaskQueue::default();
        q.enqueue(entries.clone()).unwrap();
        let first = q.dispatch(|p| p == ready).unwrap();
        assert_eq!(first, entries[1]);
        assert!(q.dispatch(|_| true).is_none());
        q.finish(&first.id);
        assert_eq!(q.dispatch(|p| p == ready).unwrap(), entries[2]);
        q.finish(&entries[2].id);
        assert_eq!(q.dispatch(|_| true).unwrap(), entries[0]);
    }
    #[test]
    fn lowering_three_to_one_does_not_kill_or_refill_excess_activity() {
        let peer = Identity::generate().node_id();
        let entries = (0..5).map(|_| entry(peer, false)).collect::<Vec<_>>();
        let mut q = TaskQueue::default();
        q.set_limit(3).unwrap();
        q.enqueue(entries.clone()).unwrap();
        for expected in &entries[..3] {
            assert_eq!(&q.dispatch(|_| true).unwrap(), expected);
        }
        q.set_limit(1).unwrap();
        assert!(q.metrics().converging);
        assert_eq!(q.metrics().active_files, 3);
        for expected in &entries[..2] {
            q.finish(&expected.id);
            assert!(q.dispatch(|_| true).is_none());
        }
        q.finish(&entries[2].id);
        assert_eq!(q.dispatch(|_| true).unwrap(), entries[3]);
        for invalid in [0, 4, 255] {
            assert!(q.set_limit(invalid).is_err());
            assert_eq!(q.metrics().limit, 1);
        }
    }
    #[test]
    fn directory_metadata_does_not_consume_a_file_slot_and_pause_removes_pending() {
        let peer = Identity::generate().node_id();
        let entries = vec![entry(peer, false), entry(peer, true), entry(peer, false)];
        let mut q = TaskQueue::default();
        q.enqueue(entries.clone()).unwrap();
        q.dispatch(|_| true).unwrap();
        assert_eq!(q.dispatch(|_| true).unwrap(), entries[1]);
        assert_eq!(q.metrics().active_files, 1);
        assert_eq!(q.metrics().active_metadata, 1);
        assert_eq!(q.remove_queued(&entries[2].id), Some(entries[2].clone()));
        assert!(!q.is_queued(&entries[2].id));
        assert_eq!(q.metrics().pending, 0);
    }
    #[test]
    fn bounded_batch_admission_is_atomic_and_cannot_rebind_an_id() {
        let peer = Identity::generate().node_id();
        let entries = (0..MAX_QUEUED - 1)
            .map(|_| entry(peer, false))
            .collect::<Vec<_>>();
        let mut q = TaskQueue::default();
        q.enqueue(entries.clone()).unwrap();
        assert!(
            q.enqueue(vec![entry(peer, false), entry(peer, false)])
                .is_err()
        );
        assert_eq!(q.metrics().pending, MAX_QUEUED - 1);
        let mut changed = entries[0].clone();
        changed.peer = Identity::generate().node_id();
        assert!(q.enqueue(vec![changed]).is_err());
        q.enqueue(vec![entries[0].clone()]).unwrap();
        assert_eq!(q.metrics().pending, MAX_QUEUED - 1);
    }
    #[test]
    fn stale_completion_cannot_release_a_retried_task_slot() {
        let mut q = TaskQueue::default();
        let entry = entry(Identity::generate().node_id(), false);
        let first = q.reserve_direct(entry.clone()).unwrap();
        q.finish_if(&entry.id, first);
        let second = q.reserve_direct(entry.clone()).unwrap();
        assert_ne!(first, second);
        q.finish_if(&entry.id, first);
        assert_eq!(q.metrics().active_files, 1);
        q.clear();
        let third = q.reserve_direct(entry.clone()).unwrap();
        assert_ne!(second, third);
        q.finish_if(&entry.id, second);
        assert_eq!(q.metrics().active_files, 1);
        q.finish_if(&entry.id, third);
        assert_eq!(q.metrics().active_files, 0);
    }
    #[test]
    fn rate_uses_confirmed_delta_not_resume_baseline_and_paused_or_idle_is_zero() {
        let mut sample = RateSampler::default();
        sample.reset(100, 64 * 1024 * 1024);
        assert_eq!(sample.bytes_per_second(100, true), 0.0);
        sample.observe(1100, 64 * 1024 * 1024 + 1000);
        assert_eq!(sample.bytes_per_second(1100, true), 1000.0);
        assert_eq!(sample.bytes_per_second(1100, false), 0.0);
        assert_eq!(sample.bytes_per_second(3100, true), 0.0);
        sample.reset(4000, u64::MAX - 1000);
        sample.observe(5000, u64::MAX);
        assert_eq!(sample.bytes_per_second(5000, true), 1000.0);
        sample.observe(4900, 7);
        assert_eq!(sample.bytes_per_second(4900, true), 0.0);
    }
}

/// Equal byte quantum over writers which are currently able to write. A Pending
/// stream leaves the ready ring until its own I/O waker polls it again. Credits
/// never exceed one quantum, so slow streams cannot bank an unlimited catch-up.
#[derive(Clone, Default)]
pub struct FairWrites(std::sync::Arc<std::sync::Mutex<FairState>>);
#[derive(Default)]
struct FairState {
    tasks: HashMap<TaskId, WriteCredit>,
    ready: VecDeque<TaskId>,
    polling: Option<TaskId>,
    has_written: bool,
}
struct WriteCredit {
    credit: usize,
    ready: bool,
    has_written: bool,
    startup_share: bool,
    waker: Option<std::task::Waker>,
}
pub struct WriteTicket {
    scheduler: FairWrites,
    id: TaskId,
}
impl FairState {
    fn ready_wakers(&self) -> Vec<std::task::Waker> {
        self.tasks
            .values()
            .filter(|t| t.ready)
            .filter_map(|t| t.waker.clone())
            .collect()
    }
}
impl Drop for WriteTicket {
    fn drop(&mut self) {
        let wake = {
            let mut state = self.scheduler.0.lock().unwrap();
            state.tasks.remove(&self.id);
            if state.polling.as_ref() == Some(&self.id) {
                state.polling = None;
            }
            state.ready.retain(|id| id != &self.id);
            if state.tasks.is_empty() {
                state.has_written = false;
            }
            state.ready_wakers()
        };
        for waker in wake {
            waker.wake();
        }
    }
}
impl FairWrites {
    pub fn ticket(&self, id: TaskId) -> std::io::Result<WriteTicket> {
        let mut state = self.0.lock().unwrap();
        if state.tasks.contains_key(&id) {
            return Err(std::io::Error::other("同一任务已有数据写入"));
        }
        if state.tasks.len() >= MAX_DATA_WRITERS {
            return Err(std::io::Error::other("数据写入资源已达上限"));
        }
        let startup_share = !state.has_written;
        state.tasks.insert(
            id.clone(),
            WriteCredit {
                credit: BYTE_QUANTUM,
                ready: false,
                has_written: false,
                startup_share,
                waker: None,
            },
        );
        Ok(WriteTicket {
            scheduler: self.clone(),
            id,
        })
    }
}
impl WriteTicket {
    /// Call only when the owner has no prepared bytes (disk/ACK/input wait).
    /// Keep its remaining credit, but make the unused share available immediately.
    pub fn park(&self) {
        let wake = {
            let mut state = self.scheduler.0.lock().unwrap();
            state.tasks.get_mut(&self.id).unwrap().ready = false;
            state.ready.retain(|id| id != &self.id);
            state.ready_wakers()
        };
        for waker in wake {
            waker.wake();
        }
    }
    pub async fn write_all<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let n = std::future::poll_fn(|cx| {
                self.poll_write(std::pin::Pin::new(&mut *writer), cx, &bytes[offset..])
            })
            .await?;
            offset += n;
            // A permanently ready QUIC writer must let other task futures
            // register readiness even when every poll completes synchronously.
            tokio::task::yield_now().await;
        }
        Ok(())
    }
    pub fn poll_write<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        mut writer: std::pin::Pin<&mut W>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let allowance = {
            let mut state = self.scheduler.0.lock().unwrap();
            let credit = state.tasks.get_mut(&self.id).unwrap();
            credit.waker = Some(cx.waker().clone());
            if !credit.ready {
                credit.ready = true;
                let first_write = credit.startup_share && !credit.has_written;
                if first_write {
                    // Initial participants get a first share before another
                    // startup quantum. Later arrivals append normally so a
                    // sequence of tiny new tasks cannot starve existing ones.
                    state.ready.push_front(self.id.clone());
                } else {
                    state.ready.push_back(self.id.clone());
                }
            }
            if state.polling.is_some() || state.ready.front() != Some(&self.id) {
                return Poll::Pending;
            }
            state.polling = Some(self.id.clone());
            state.tasks[&self.id].credit.min(bytes.len())
        };
        // The global lock is released before even polling a stream. A blocked
        // peer can only block its own future; it never holds the scheduler turn.
        let result = writer.as_mut().poll_write(cx, &bytes[..allowance]);
        let wake = {
            let mut state = self.scheduler.0.lock().unwrap();
            state.polling = None;
            if matches!(&result, Poll::Ready(Ok(n)) if *n > 0) {
                state.has_written = true;
            }
            let credit = state.tasks.get_mut(&self.id).unwrap();
            match &result {
                Poll::Ready(Ok(n)) if *n > 0 => {
                    credit.has_written = true;
                    credit.credit -= *n;
                    if credit.credit == 0 {
                        credit.credit = BYTE_QUANTUM;
                        state.ready.pop_front();
                        state.ready.push_back(self.id.clone());
                        state.ready_wakers()
                    } else {
                        Vec::new()
                    }
                }
                _ => {
                    credit.ready = false;
                    state.ready.pop_front();
                    state.ready_wakers()
                }
            }
        };
        for waker in wake {
            waker.wake();
        }
        match result {
            Poll::Ready(Ok(0)) => Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
            other => other,
        }
    }
}

#[cfg(test)]
mod fairness_tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    use tokio::io::AsyncWrite;
    struct ReadyWriter {
        limit: usize,
        bytes: usize,
        ready: bool,
    }
    impl AsyncWrite for ReadyWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if !self.ready {
                return Poll::Pending;
            }
            let n = bytes.len().min(self.limit);
            self.bytes += n;
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[test]
    fn continuously_ready_writers_have_a_byte_bound_even_with_different_short_writes() {
        for limits in [
            [137, 4093, BYTE_QUANTUM],
            [BYTE_QUANTUM; 3],
            [BYTE_QUANTUM, 137, 4093],
        ] {
            for n in 1..=3 {
                let scheduler = FairWrites::default();
                let tickets = (0..n)
                    .map(|_| scheduler.ticket(TaskId::generate()).unwrap())
                    .collect::<Vec<_>>();
                let mut writers = limits
                    .into_iter()
                    .take(n)
                    .map(|limit| ReadyWriter {
                        limit,
                        bytes: 0,
                        ready: true,
                    })
                    .collect::<Vec<_>>();
                let bytes = vec![0; BYTE_QUANTUM];
                let waker = Waker::noop().clone();
                let mut cx = Context::from_waker(&waker);
                for _ in 0..20_000 {
                    for (index, ticket) in tickets.iter().enumerate() {
                        let _ = ticket.poll_write(Pin::new(&mut writers[index]), &mut cx, &bytes);
                        let min = writers.iter().map(|w| w.bytes).min().unwrap();
                        let max = writers.iter().map(|w| w.bytes).max().unwrap();
                        assert!(
                            max - min <= BYTE_QUANTUM,
                            "unfair acceptedbytes: {min}..{max}"
                        );
                    }
                }
                assert!(writers.iter().all(|w| w.bytes >= 10 * BYTE_QUANTUM));
            }
        }
    }
    #[test]
    fn writer_panic_drops_only_its_ticket_and_other_peer_can_continue() {
        struct PanicWriter;
        impl AsyncWrite for PanicWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                panic!("injected writer panic");
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let scheduler = FairWrites::default();
        let waker = Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ticket = scheduler.ticket(TaskId::generate()).unwrap();
            let _ = ticket.poll_write(Pin::new(&mut PanicWriter), &mut cx, b"payload");
        }));
        assert!(outcome.is_err());
        let next = scheduler.ticket(TaskId::generate()).unwrap();
        let mut writer = ReadyWriter {
            limit: BYTE_QUANTUM,
            bytes: 0,
            ready: true,
        };
        assert!(matches!(
            next.poll_write(Pin::new(&mut writer), &mut cx, b"next"),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(writer.bytes, 4);
    }
    #[test]
    fn blocked_writer_releases_turn_and_unused_share_is_borrowed_without_credit_growth() {
        let scheduler = FairWrites::default();
        let a = scheduler.ticket(TaskId::generate()).unwrap();
        let b = scheduler.ticket(TaskId::generate()).unwrap();
        let mut slow = ReadyWriter {
            limit: BYTE_QUANTUM,
            bytes: 0,
            ready: false,
        };
        let mut fast = ReadyWriter {
            limit: BYTE_QUANTUM,
            bytes: 0,
            ready: true,
        };
        let data = vec![0; BYTE_QUANTUM];
        let waker = Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        assert!(
            a.poll_write(Pin::new(&mut slow), &mut cx, &data)
                .is_pending()
        );
        for _ in 0..100 {
            assert!(matches!(
                b.poll_write(Pin::new(&mut fast), &mut cx, &data),
                Poll::Ready(Ok(BYTE_QUANTUM))
            ));
        }
        assert_eq!(fast.bytes, 100 * BYTE_QUANTUM);
        assert_eq!(slow.bytes, 0);
        slow.ready = true;
        for _ in 0..100 {
            let _ = a.poll_write(Pin::new(&mut slow), &mut cx, &data);
            let _ = b.poll_write(Pin::new(&mut fast), &mut cx, &data);
        }
        assert!(slow.bytes >= 99 * BYTE_QUANTUM);
        assert!(fast.bytes <= 201 * BYTE_QUANTUM);
        drop(a);
        drop(b);
        assert!(scheduler.0.lock().unwrap().tasks.is_empty());
    }
    #[tokio::test]
    async fn synchronously_ready_async_loops_yield_and_remain_byte_fair() {
        struct ObservedWriter {
            index: usize,
            counts: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
            scheduler: FairWrites,
        }
        impl AsyncWrite for ObservedWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                assert!(
                    self.scheduler.0.try_lock().is_ok(),
                    "scheduler held across stream poll"
                );
                let n = bytes.len();
                let mut counts = self.counts.lock().unwrap();
                counts[self.index] += n;
                let min = *counts.iter().min().unwrap();
                let max = *counts.iter().max().unwrap();
                assert!(max - min <= BYTE_QUANTUM, "async starvation: {counts:?}");
                Poll::Ready(Ok(n))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        for n in 1..=3 {
            let fair = FairWrites::default();
            let counts = std::sync::Arc::new(std::sync::Mutex::new(vec![0; n]));
            let mut jobs = tokio::task::JoinSet::new();
            for index in 0..n {
                let ticket = fair.ticket(TaskId::generate()).unwrap();
                let mut writer = ObservedWriter {
                    index,
                    counts: counts.clone(),
                    scheduler: fair.clone(),
                };
                jobs.spawn(async move {
                    ticket
                        .write_all(&mut writer, &vec![0; 12 * BYTE_QUANTUM])
                        .await
                        .unwrap();
                });
            }
            while let Some(result) = jobs.join_next().await {
                result.unwrap();
            }
            assert_eq!(*counts.lock().unwrap(), vec![12 * BYTE_QUANTUM; n]);
        }
    }
    #[test]
    fn a_stream_of_new_tiny_tasks_cannot_jump_ahead_of_ready_existing_tasks() {
        let fair = FairWrites::default();
        let tickets = [
            fair.ticket(TaskId::generate()).unwrap(),
            fair.ticket(TaskId::generate()).unwrap(),
        ];
        let mut writers = [
            ReadyWriter {
                limit: BYTE_QUANTUM,
                bytes: 0,
                ready: true,
            },
            ReadyWriter {
                limit: BYTE_QUANTUM,
                bytes: 0,
                ready: true,
            },
        ];
        let waker = Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let bytes = vec![0; BYTE_QUANTUM];
        for index in 0..2 {
            let _ = tickets[index].poll_write(Pin::new(&mut writers[index]), &mut cx, &bytes);
        }
        for _ in 0..100 {
            let fresh = fair.ticket(TaskId::generate()).unwrap();
            let mut tiny = ReadyWriter {
                limit: 1,
                bytes: 0,
                ready: true,
            };
            assert!(
                fresh
                    .poll_write(Pin::new(&mut tiny), &mut cx, &[0])
                    .is_pending()
            );
            for index in 0..2 {
                let _ = tickets[index].poll_write(Pin::new(&mut writers[index]), &mut cx, &bytes);
            }
            assert!(matches!(
                fresh.poll_write(Pin::new(&mut tiny), &mut cx, &[0]),
                Poll::Ready(Ok(1))
            ));
        }
        assert!(
            writers
                .iter()
                .all(|writer| writer.bytes >= 100 * BYTE_QUANTUM)
        );
    }
    #[test]
    fn writer_registration_is_bounded_and_a_dropped_slot_is_reusable() {
        let fair = FairWrites::default();
        let mut held = (0..MAX_DATA_WRITERS)
            .map(|_| fair.ticket(TaskId::generate()).unwrap())
            .collect::<Vec<_>>();
        assert!(fair.ticket(TaskId::generate()).is_err());
        held.pop();
        assert!(fair.ticket(TaskId::generate()).is_ok());
        assert!(fair.ticket(held[0].id.clone()).is_err());
    }
}
