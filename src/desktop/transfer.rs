//! Authenticated single-file streams. Disk work stays off the network/UI executors.
use super::{
    protocol::{self, Actor, Entry, ErrorCode, Frame, Message, TaskProtocol, WireTaskState},
    task_model::{
        ProgressHint, TaskDiagnostic, TaskDirection, TaskErrorCode, TaskId, TaskRecord, TaskState,
        system_time_unix_ms,
    },
    task_store::TaskStore,
    transfer_files as disk,
};
use crate::{
    error::{Error, Result},
    identity::NodeId,
    protocol::manifest::FileManifest,
    transfer::resume::ChunkBitmap,
};
use quinn::{Connection, RecvStream, SendStream};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const PAUSE_TIMEOUT: Duration = Duration::from_secs(5);
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
const WINDOW: usize = 4;
const MAX_RECEIVE_FILES: usize = 3;

#[cfg(test)]
type TestGate = Arc<
    Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
>;

#[derive(Clone)]
pub(crate) struct TransferService {
    store: Arc<Mutex<TaskStore>>,
    receive_root: Arc<Mutex<PathBuf>>,
    active: Arc<Mutex<HashMap<TaskId, Active>>>,
    changed: watch::Sender<u64>,
    epoch: Arc<std::sync::atomic::AtomicU64>,
    fair_writes: super::queue::FairWrites,
    frame_budget: super::frame_budget::FrameBudget,
    rate_origin: Instant,
    rates: Arc<Mutex<HashMap<TaskId, super::queue::RateSampler>>>,
    sender_queue: Arc<Mutex<super::queue::TaskQueue>>,
    pub(super) activity: super::activity::Activity,
    speed_peers: Arc<Mutex<HashMap<NodeId, super::speed::SpeedPeer>>>,
    #[cfg(test)]
    drop_completion: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    first_chunk_gate: TestGate,
    #[cfg(test)]
    checkpoint_gate: TestGate,
    #[cfg(test)]
    admission_gate: TestGate,
    #[cfg(test)]
    source_cleanup_gate: TestGate,
}
#[allow(dead_code)] // T010 consumes these safe domain fields in its task list.
pub(crate) struct TransferPresentation {
    pub tasks: Vec<TaskRecord>,
    pub events: Vec<super::task_events::TaskEvent>,
    pub resync_required: bool,
    pub bytes_per_second: HashMap<TaskId, f64>,
    pub groups: HashMap<TaskId, super::queue::GroupProgress>,
    pub queue: super::queue::QueueMetrics,
}
struct Active {
    peer: NodeId,
    direction: TaskDirection,
    metadata: bool,
    pause: watch::Sender<bool>,
}
pub(crate) struct ScheduledSend {
    pub entry: super::queue::QueueEntry,
    generation: u64,
    _slot: SendSlot,
}
struct SendSlot {
    _activity: super::activity::FilePermit,
    service: TransferService,
    id: TaskId,
    generation: u64,
}
impl Drop for SendSlot {
    fn drop(&mut self) {
        self.service
            .sender_queue
            .lock()
            .unwrap()
            .finish_if(&self.id, self.generation);
        self.service.changed.send_modify(|v| *v = v.wrapping_add(1));
    }
}
struct ActiveGuard {
    _activity: Option<super::activity::FilePermit>,
    service: TransferService,
    id: TaskId,
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.service.active.lock().unwrap().remove(&self.id);
        self.service.rates.lock().unwrap().remove(&self.id);
        self.service
            .changed
            .send_modify(|version| *version = version.wrapping_add(1));
    }
}
impl std::fmt::Debug for TransferService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferService").finish_non_exhaustive()
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| disk::failure("文件后台任务中断"))?
}

impl TransferService {
    pub fn new(store: TaskStore, receive_root: PathBuf) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            store: Arc::new(Mutex::new(store)),
            receive_root: Arc::new(Mutex::new(receive_root)),
            active: Arc::new(Mutex::new(HashMap::new())),
            activity: super::activity::Activity::new(changed.clone()),
            speed_peers: Arc::new(Mutex::new(HashMap::new())),
            changed,
            epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fair_writes: super::queue::FairWrites::default(),
            frame_budget: super::frame_budget::FrameBudget::default(),
            rate_origin: Instant::now(),
            rates: Arc::new(Mutex::new(HashMap::new())),
            sender_queue: Arc::new(Mutex::new(super::queue::TaskQueue::default())),
            #[cfg(test)]
            drop_completion: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            first_chunk_gate: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            checkpoint_gate: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            admission_gate: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            source_cleanup_gate: Arc::new(Mutex::new(None)),
        }
    }
    async fn store<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut TaskStore) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let store = self.store.clone();
        let epoch = self.epoch.clone();
        let generation = epoch.load(std::sync::atomic::Ordering::Acquire);
        let result = blocking(move || {
            let mut store = store.lock().map_err(|_| disk::failure("任务库锁不可用"))?;
            if generation != epoch.load(std::sync::atomic::Ordering::Acquire) {
                return Err(disk::failure("旧传输会话已取消"));
            }
            work(&mut store)
        })
        .await;
        if result.is_ok() {
            self.changed
                .send_modify(|version| *version = version.wrapping_add(1));
        }
        result
    }
    async fn read_store<T: Send + 'static>(
        &self,
        work: impl FnOnce(&TaskStore) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let store = self.store.clone();
        blocking(move || work(&*store.lock().map_err(|_| disk::failure("任务库锁不可用"))?)).await
    }
    pub fn set_send_limit(&self, value: u8) -> Result<()> {
        self.sender_queue
            .lock()
            .unwrap()
            .set_limit(value)
            .map_err(disk::failure)?;
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
        Ok(())
    }
    pub fn queue_metrics(&self) -> super::queue::QueueMetrics {
        self.sender_queue.lock().unwrap().metrics()
    }
    pub fn dispatch_ready(&self, connections: &HashMap<NodeId, Connection>) -> Vec<ScheduledSend> {
        let mut activity = self.activity.lock();
        let mut queue = self.sender_queue.lock().unwrap();
        let mut selected = Vec::new();
        while let Some(entry) = queue.dispatch(|peer| {
            !activity.speed_active(peer)
                && connections
                    .get(&peer)
                    .is_some_and(|c| c.close_reason().is_none())
        }) {
            let generation = queue.slot_generation(&entry.id).unwrap();
            activity
                .add_file(entry.peer)
                .expect("dispatch admission lock");
            let slot = SendSlot {
                _activity: self.activity.file_permit(entry.peer),
                service: self.clone(),
                id: entry.id.clone(),
                generation,
            };
            selected.push(ScheduledSend {
                entry,
                generation,
                _slot: slot,
            });
        }
        selected
    }
    /// Only explicitly queued tasks enter the current-run executor. Restored
    /// Interrupted/Paused records require a new user continuation command.
    pub async fn enqueue_tasks(&self, peer: NodeId, ids: Vec<TaskId>) -> Result<()> {
        let generation = self.epoch.load(std::sync::atomic::Ordering::Acquire);
        let lookup = ids.clone();
        let previous = self
            .read_store(move |store| {
                let mut previous = Vec::new();
                for id in lookup {
                    let record = disk::bound_task(store, peer, &id)?;
                    if record.direction() != TaskDirection::Send {
                        return Err(disk::failure("接收任务不能加入发送队列"));
                    }
                    if can_continue(&record) {
                        previous.push(id);
                    }
                }
                Ok(previous)
            })
            .await?;
        // Paused/Interrupted is visible before the old executor's RAII cleanup
        // finishes. A deliberate Continue must await it rather than be mistaken
        // for an idempotent duplicate of an activity that is already ending.
        for id in previous {
            self.wait_previous_attempt(&id).await?;
        }
        let epoch = self.epoch.clone();
        let queue = self.sender_queue.clone();
        self.store(move |store| Self::admit_locked(store, &queue, peer, ids, &epoch, generation))
            .await?;
        #[cfg(test)]
        self.admission_committed().await;
        Ok(())
    }
    /// Caller owns the store writer until admission is complete. Pause/readers
    /// cannot observe Queued before its entry exists. Queue locks stay short;
    /// disk snapshot commits do not hold the scheduler admission mutex.
    fn admit_locked(
        store: &mut TaskStore,
        queue: &Mutex<super::queue::TaskQueue>,
        peer: NodeId,
        ids: Vec<TaskId>,
        epoch: &std::sync::atomic::AtomicU64,
        generation: u64,
    ) -> Result<()> {
        let mut entries = Vec::new();
        for id in ids {
            let record = disk::bound_task(store, peer, &id)?;
            if record.direction() != TaskDirection::Send {
                return Err(disk::failure("接收任务不能加入发送队列"));
            }
            if record.state() == TaskState::Completed
                || queue.lock().unwrap().slot_generation(&id).is_some()
            {
                continue;
            }
            if record.state() != TaskState::Queued && !can_continue(&record) {
                return Err(disk::failure("任务当前不能继续"));
            }
            entries.push(super::queue::QueueEntry {
                id,
                peer,
                metadata: record.directory_details().is_some(),
            });
        }
        // Validate the complete batch before changing any lifecycle state.
        for entry in &entries {
            if store.task(&entry.id).map_err(disk::local_error)?.state() != TaskState::Queued {
                disk::transition(store, &entry.id, TaskState::Queued)?;
            }
        }
        let admission = {
            let mut queue = queue.lock().unwrap();
            if generation != epoch.load(std::sync::atomic::Ordering::Acquire) {
                Err("旧传输会话已取消")
            } else {
                queue.enqueue(entries.clone())
            }
        };
        if let Err(message) = admission {
            for entry in entries {
                let retained = {
                    let queue = queue.lock().unwrap();
                    queue.is_queued(&entry.id) || queue.slot_generation(&entry.id).is_some()
                };
                if !retained
                    && store.task(&entry.id).map_err(disk::local_error)?.state()
                        == TaskState::Queued
                {
                    disk::transition(store, &entry.id, TaskState::Interrupted)?;
                }
            }
            return Err(disk::failure(message));
        }
        Ok(())
    }
    #[cfg(test)]
    async fn admission_committed(&self) {
        let gate = self.admission_gate.lock().unwrap().take();
        if let Some((reached, release)) = gate {
            let _ = reached.send(());
            let _ = release.await;
        }
    }
    pub async fn execute_queued(
        &self,
        scheduled: ScheduledSend,
        connection: Connection,
    ) -> Result<()> {
        let ScheduledSend {
            entry,
            generation,
            _slot,
        } = scheduled;
        let _owned_slot = _slot;
        self.execute_send(&connection, entry.peer, entry.id, generation)
            .await
    }
    async fn reserve_send(&self, peer: NodeId, id: TaskId) -> Result<SendSlot> {
        let lookup = id.clone();
        let record = self
            .read_store(move |store| disk::bound_task(store, peer, &lookup))
            .await?;
        if record.direction() != TaskDirection::Send {
            return Err(disk::failure("只能发送本机已选择任务"));
        }
        let _activity = self.activity.file(peer)?;
        let generation = self
            .sender_queue
            .lock()
            .unwrap()
            .reserve_direct(super::queue::QueueEntry {
                id: id.clone(),
                peer,
                metadata: record.directory_details().is_some(),
            })
            .map_err(disk::failure)?;
        Ok(SendSlot {
            _activity,
            service: self.clone(),
            id,
            generation,
        })
    }
    pub async fn pause_task(&self, id: TaskId) -> Result<()> {
        let active = self.active.clone();
        let queue = self.sender_queue.clone();
        self.store(move |store| {
            // Serialize the durable state with admission. A reserved executor
            // has not necessarily claimed its stream yet; cancel its nonce too.
            let active = active.lock().unwrap();
            if let Some(task) = active.get(&id) {
                task.pause.send_if_modified(|paused| {
                    if *paused {
                        false
                    } else {
                        *paused = true;
                        true
                    }
                });
                return Ok(());
            }
            let mut queue = queue.lock().unwrap();
            let queued = queue.is_queued(&id);
            let generation = queue.slot_generation(&id);
            if !queued && generation.is_none() {
                return Err(disk::failure("任务当前未传输或排队"));
            }
            if store.task(&id).map_err(disk::local_error)?.state() != TaskState::Queued {
                return Err(disk::failure("任务当前不能暂停"));
            }
            disk::transition(store, &id, TaskState::Pausing)?;
            disk::transition(store, &id, TaskState::Paused)?;
            queue.remove_queued(&id);
            if let Some(generation) = generation {
                queue.finish_if(&id, generation);
            }
            Ok(())
        })
        .await
    }
    pub async fn interrupt_all(&self) -> Result<()> {
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.sender_queue.lock().unwrap().clear();
        self.store(|store| {
            let ids = store
                .list()
                .iter()
                .filter(|task| task.state().needs_startup_recovery())
                .map(|task| task.task_id().clone())
                .collect::<Vec<_>>();
            for id in ids {
                disk::transition(store, &id, TaskState::Interrupted)?;
            }
            Ok(())
        })
        .await
    }
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
    #[allow(dead_code)] // T010 task list consumes this snapshot API.
    pub async fn snapshot(&self) -> Result<Vec<TaskRecord>> {
        self.read_store(|store| Ok(store.list().to_vec())).await
    }
    pub fn set_receive_root(&self, root: PathBuf) {
        *self.receive_root.lock().unwrap() = root;
    }
    pub async fn select_file(&self, peer: NodeId, source: PathBuf) -> Result<TaskId> {
        let _selection_activity = self.activity.file(peer)?;
        struct CancelScan(super::files::ScanCancellation);
        impl Drop for CancelScan {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        let generation = self.epoch.load(std::sync::atomic::Ordering::Acquire);
        let epoch = self.epoch.clone();
        let queue = self.sender_queue.clone();
        let cancellation = super::files::ScanCancellation::default();
        let _guard = CancelScan(cancellation.clone());
        let commit_cancellation = cancellation.clone();
        // Hashing may take minutes. It never holds the task-store writer lock.
        let record =
            blocking(move || disk::scan_selected_file(peer, source, &cancellation)).await?;
        let id = self
            .store(move |store| {
                if generation != epoch.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(disk::failure("旧传输会话已取消"));
                }
                commit_cancellation.check()?;
                let id = record.task_id().clone();
                store.create(record).map_err(disk::local_error)?;
                disk::transition(store, &id, TaskState::Queued)?;
                Self::admit_locked(store, &queue, peer, vec![id.clone()], &epoch, generation)?;
                Ok(id)
            })
            .await?;
        #[cfg(test)]
        self.admission_committed().await;
        Ok(id)
    }
    pub async fn select_directory(&self, peer: NodeId, source: PathBuf) -> Result<Vec<TaskId>> {
        let _selection_activity = self.activity.file(peer)?;
        struct CancelScan(super::files::ScanCancellation);
        impl Drop for CancelScan {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        let generation = self.epoch.load(std::sync::atomic::Ordering::Acquire);
        let epoch = self.epoch.clone();
        let queue = self.sender_queue.clone();
        let cancellation = super::files::ScanCancellation::default();
        let _guard = CancelScan(cancellation.clone());
        let commit_cancellation = cancellation.clone();
        let records =
            blocking(move || super::files::scan_directory(peer, &source, &cancellation)).await?;
        let ids = self
            .store(move |store| {
                if generation != epoch.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(disk::failure("旧传输会话已取消"));
                }
                commit_cancellation.check()?;
                let ids = store.create_selection(records).map_err(disk::local_error)?;
                for id in &ids {
                    disk::transition(store, id, TaskState::Queued)?;
                }
                Self::admit_locked(store, &queue, peer, ids.clone(), &epoch, generation)?;
                Ok(ids)
            })
            .await?;
        #[cfg(test)]
        self.admission_committed().await;
        Ok(ids)
    }
    /// Test convenience for existing directory protocol regressions.
    #[cfg(test)]
    pub async fn send_selection(
        &self,
        connection: &Connection,
        peer: NodeId,
        ids: Vec<TaskId>,
    ) -> Result<()> {
        let mut failure = None;
        for id in ids {
            if connection.close_reason().is_some() {
                return Err(disk::failure("目录传输连接中断，其余任务可手动继续"));
            }
            if let Err(error) = self.send_file(connection, peer, id).await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
    pub async fn task(&self, id: TaskId) -> Result<TaskRecord> {
        self.read_store(move |store| store.task(&id).map_err(disk::local_error))
            .await
    }
    async fn wait_previous_attempt(&self, id: &TaskId) -> Result<()> {
        let mut changed = self.subscribe();
        tokio::time::timeout(PAUSE_TIMEOUT, async {
            loop {
                if !self.active.lock().unwrap().contains_key(id)
                    && self
                        .sender_queue
                        .lock()
                        .unwrap()
                        .slot_generation(id)
                        .is_none()
                {
                    return Ok(());
                }
                changed
                    .changed()
                    .await
                    .map_err(|_| disk::failure("任务状态通知已关闭"))?;
            }
        })
        .await
        .map_err(|_| disk::failure("上次传输清理超时"))?
    }
    fn claim(
        &self,
        peer: NodeId,
        id: &TaskId,
        direction: TaskDirection,
        metadata: bool,
        send_generation: Option<u64>,
    ) -> Result<(ActiveGuard, watch::Receiver<bool>)> {
        let mut activity = self.activity.lock();
        let mut active = self.active.lock().unwrap();
        if active.contains_key(id) {
            return Err(disk::failure("同一任务已有传输活动"));
        }
        if direction == TaskDirection::Send {
            if self.sender_queue.lock().unwrap().slot_generation(id) != send_generation
                || send_generation.is_none()
            {
                return Err(disk::failure("发送槽已失效"));
            }
        } else {
            let global = active
                .values()
                .filter(|a| a.direction == TaskDirection::Receive && a.metadata == metadata)
                .count();
            let per_peer = active
                .values()
                .filter(|a| {
                    a.direction == TaskDirection::Receive
                        && a.metadata == metadata
                        && a.peer == peer
                })
                .count();
            let (global_limit, peer_limit) = if metadata {
                (super::queue::MAX_METADATA_ACTIVE, 2)
            } else {
                (MAX_RECEIVE_FILES, 3)
            };
            if global >= global_limit || per_peer >= peer_limit {
                return Err(disk::failure("接收资源忙，请稍后继续"));
            }
        }
        let file_permit = if direction == TaskDirection::Receive {
            activity.add_file(peer)?;
            Some(self.activity.file_permit(peer))
        } else {
            None
        };
        let (pause, rx) = watch::channel(false);
        active.insert(
            id.clone(),
            Active {
                peer,
                direction,
                metadata,
                pause,
            },
        );
        Ok((
            ActiveGuard {
                _activity: file_permit,
                service: self.clone(),
                id: id.clone(),
            },
            rx,
        ))
    }
    async fn claim_receive(
        &self,
        send: &mut SendStream,
        peer: NodeId,
        id: &TaskId,
        metadata: bool,
    ) -> Result<(ActiveGuard, watch::Receiver<bool>)> {
        match self.claim(peer, id, TaskDirection::Receive, metadata, None) {
            Ok(claim) => Ok(claim),
            Err(error) => {
                tokio::time::timeout(
                    IDLE_TIMEOUT,
                    protocol::write(
                        send,
                        &Frame {
                            request_id: 1,
                            message: Message::Error {
                                task_id: id.clone(),
                                code: ErrorCode::Busy,
                            },
                        },
                    ),
                )
                .await
                .map_err(|_| disk::failure("接收资源忙回执超时"))??;
                let _ = send.finish();
                Err(error)
            }
        }
    }
    #[cfg(test)]
    pub fn pause(&self, id: &TaskId) -> Result<()> {
        let active = self.active.lock().unwrap();
        let pause = &active
            .get(id)
            .ok_or_else(|| disk::failure("任务当前未传输"))?
            .pause;
        if *pause.borrow() {
            return Ok(());
        }
        pause.send(true).map_err(|_| disk::failure("任务已结束"))
    }
    async fn state(&self, id: &TaskId, state: TaskState) -> Result<()> {
        let id = id.clone();
        self.store(move |store| disk::transition(store, &id, state))
            .await
    }
    async fn finish_error(&self, id: &TaskId, error: &Error) {
        let id = id.clone();
        let text = error.to_string();
        let (state, code, retryable) = if text.contains("源文件内容已变化") {
            (TaskState::Failed, TaskErrorCode::SourceChanged, false)
        } else if text.contains("源文件不可用") {
            (TaskState::Failed, TaskErrorCode::SourceUnavailable, true)
        } else if text.contains("资源忙") {
            (TaskState::Failed, TaskErrorCode::PeerBusy, true)
        } else if is_storage_error(error) {
            (TaskState::Failed, TaskErrorCode::StorageUnavailable, true)
        } else {
            (
                TaskState::Interrupted,
                TaskErrorCode::NetworkInterrupted,
                false,
            )
        };
        let _ = self
            .store(move |store| {
                let record = store.task(&id).map_err(disk::local_error)?;
                if record.state().is_terminal() || record.state() == TaskState::Interrupted {
                    return Ok(());
                }
                store
                    .transition(
                        &id,
                        state,
                        Some(TaskDiagnostic::new(code, retryable)),
                        system_time_unix_ms().map_err(disk::local_error)?,
                    )
                    .map_err(disk::local_error)
            })
            .await;
    }
    fn monotonic_ms(&self) -> u64 {
        self.rate_origin
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }
    fn reset_rate(&self, id: &TaskId, bytes: u64) {
        self.rates
            .lock()
            .unwrap()
            .entry(id.clone())
            .or_default()
            .reset(self.monotonic_ms(), bytes);
    }
    async fn progress(&self, id: &TaskId, bytes: u64) -> Result<()> {
        let lookup = id.clone();
        self.store(move |store| {
            store
                .set_progress_hint(
                    &lookup,
                    ProgressHint::new(bytes, system_time_unix_ms().map_err(disk::local_error)?),
                )
                .map_err(disk::local_error)
        })
        .await?;
        self.rates
            .lock()
            .unwrap()
            .entry(id.clone())
            .or_default()
            .observe(self.monotonic_ms(), bytes);
        Ok(())
    }
    /// An authoritative snapshot accompanies bounded/coalesced events. A UI
    /// rebuilds from tasks when resync_required, rather than trusting a lost delta.
    #[allow(dead_code)] // T010 consumes the T008 presentation contract.
    pub async fn presentation(&self) -> Result<TransferPresentation> {
        let store = self.store.clone();
        let (tasks, events, resync_required) = blocking(move || {
            let mut store = store.lock().map_err(|_| disk::failure("任务库锁不可用"))?;
            let tasks = store.list().to_vec();
            let events = store.drain_events();
            let resync = store.take_event_resync_required();
            Ok((tasks, events, resync))
        })
        .await?;
        let now = self.monotonic_ms();
        let rates = self.rates.lock().unwrap();
        let bytes_per_second = tasks
            .iter()
            .map(|record| {
                let value = rates.get(record.task_id()).map_or(0.0, |rate| {
                    rate.bytes_per_second(now, record.state() == TaskState::Transferring)
                });
                (record.task_id().clone(), value)
            })
            .collect();
        let mut children: HashMap<TaskId, Vec<TaskRecord>> = HashMap::new();
        for record in &tasks {
            if let Some(group) = record.group_id() {
                children
                    .entry(group.clone())
                    .or_default()
                    .push(record.clone());
            }
        }
        let groups = children
            .into_iter()
            .map(|(id, children)| (id, super::queue::group_progress(&children)))
            .collect();
        Ok(TransferPresentation {
            tasks,
            events,
            resync_required,
            bytes_per_second,
            groups,
            queue: self.queue_metrics(),
        })
    }
    async fn receipt(&self, id: &TaskId) -> Result<()> {
        self.state(id, TaskState::Finalizing).await?;
        let id = id.clone();
        self.store(move |store| {
            store
                .commit_receipt(&id, system_time_unix_ms().map_err(disk::local_error)?)
                .map_err(disk::local_error)
        })
        .await
    }
    #[cfg(test)]
    pub async fn send_file(&self, connection: &Connection, peer: NodeId, id: TaskId) -> Result<()> {
        self.wait_previous_attempt(&id).await?;
        let slot = self.reserve_send(peer, id.clone()).await?;
        self.execute_send(connection, peer, id, slot.generation)
            .await
    }
    async fn execute_send(
        &self,
        connection: &Connection,
        peer: NodeId,
        id: TaskId,
        generation: u64,
    ) -> Result<()> {
        let lookup = id.clone();
        self.read_store(move |store| {
            let record = disk::bound_task(store, peer, &lookup)?;
            if record.direction() != TaskDirection::Send {
                return Err(disk::failure("只能发送本机已选择任务"));
            }
            Ok(())
        })
        .await?;
        let current = self.task(id.clone()).await?;
        // This executor already owns the new reserved nonce. Callers waited
        // for old cleanup before reserving/admitting; never wait on our own slot.
        let (_guard, pause) = self.claim(
            peer,
            &id,
            TaskDirection::Send,
            current.directory_details().is_some(),
            Some(generation),
        )?;
        let result = self.send_inner(connection, peer, &id, pause, None).await;
        if let Err(error) = &result {
            self.finish_error(&id, error).await;
        }
        #[cfg(test)]
        {
            let gate = self.source_cleanup_gate.lock().unwrap().take();
            if let Some((reached, release)) = gate {
                let _ = reached.send(());
                let _ = release.await;
            }
        }
        result
    }
    async fn send_inner(
        &self,
        connection: &Connection,
        peer: NodeId,
        id: &TaskId,
        pause: watch::Receiver<bool>,
        continue_reply: Option<&mut SendStream>,
    ) -> Result<()> {
        let lookup = id.clone();
        let record = self
            .store(move |store| {
                disk::bound_task(store, peer, &lookup)?;
                disk::begin_attempt(store, &lookup)
            })
            .await?;
        if record.direction() != TaskDirection::Send {
            return Err(disk::failure("只能发送本机已选择任务"));
        }
        if record.state() == TaskState::Completed {
            return Ok(());
        }
        if record.directory_details().is_some() {
            return self
                .send_directory_entry(connection, peer, &record, continue_reply)
                .await;
        }
        let source = record.clone();
        let file = blocking(move || disk::verify_source(&source)).await?;
        let details = record.file_details().unwrap();
        let (send, recv) = tokio::time::timeout(IDLE_TIMEOUT, connection.open_bi())
            .await
            .map_err(|_| disk::failure("文件流打开超时"))?
            .map_err(disk::local_error)?;
        let mut io = TaskIo::new(send, recv, peer, id.clone(), self.frame_budget.clone());
        io.send(Message::Offer {
            task_id: id.clone(),
            group_id: record.group_id().cloned(),
            relative_path: details.relative_path.clone(),
            entry: Entry::File(Box::new(details.manifest.clone())),
        })
        .await?;
        if let Some(reply) = continue_reply {
            protocol::write(
                reply,
                &Frame {
                    request_id: 1,
                    message: Message::ResumeTask {
                        task_id: id.clone(),
                    },
                },
            )
            .await?;
            let _ = reply.finish();
        }
        self.state(id, TaskState::Transferring).await?;
        let result = self
            .sender_loop(&mut io, id, &details.manifest, file, pause)
            .await;
        if let Err(error) = &result {
            io.report_error(error).await;
        }
        result
    }
    async fn send_directory_entry(
        &self,
        connection: &Connection,
        peer: NodeId,
        record: &TaskRecord,
        continue_reply: Option<&mut SendStream>,
    ) -> Result<()> {
        let path = record.local_path().to_path_buf();
        blocking(move || {
            super::secure_fs::root(&path)?;
            Ok(())
        })
        .await
        .map_err(|_| disk::failure("源文件不可用"))?;
        let (send, recv) = tokio::time::timeout(IDLE_TIMEOUT, connection.open_bi())
            .await
            .map_err(|_| disk::failure("目录流打开超时"))?
            .map_err(disk::local_error)?;
        let id = record.task_id();
        let mut io = TaskIo::new(send, recv, peer, id.clone(), self.frame_budget.clone());
        io.send(Message::Offer {
            task_id: id.clone(),
            group_id: record.group_id().cloned(),
            relative_path: record.relative_path().unwrap().to_owned(),
            entry: Entry::Directory,
        })
        .await?;
        if let Some(reply) = continue_reply {
            protocol::write(
                reply,
                &Frame {
                    request_id: 1,
                    message: Message::ResumeTask {
                        task_id: id.clone(),
                    },
                },
            )
            .await?;
            let _ = reply.finish();
        }
        self.state(id, TaskState::Transferring).await?;
        let response = tokio::time::timeout(IDLE_TIMEOUT, io.incoming.recv())
            .await
            .map_err(|_| disk::failure("目录回执超时"))?
            .ok_or_else(|| disk::failure("目录流中断"))??;
        let super::frame_budget::BufferedFrame {
            frame: response,
            _lease,
        } = response;
        io.observe(&response)?;
        match response.message {
            Message::Completed { .. } => {
                self.receipt(id).await?;
                io.finish();
                Ok(())
            }
            Message::Error { code, .. } => Err(remote_error(code)),
            _ => Err(disk::failure("目录回执非法")),
        }
    }
    async fn sender_loop(
        &self,
        io: &mut TaskIo,
        id: &TaskId,
        manifest: &FileManifest,
        file: disk::VerifiedSource,
        mut pause: watch::Receiver<bool>,
    ) -> Result<()> {
        let file = Arc::new(Mutex::new(file));
        let writer_ticket = self.fair_writes.ticket(id.clone())?;
        let mut resumed = false;
        let mut pending_pause = false;
        let mut acknowledged = HashSet::new();
        let mut sent = HashSet::new();
        let mut bytes = 0;
        let mut sampled = Instant::now();
        let mut pausing: Option<Instant> = None;
        loop {
            if io.gate.state(id) == Some(WireTaskState::Paused) {
                self.state(id, TaskState::Paused).await?;
                io.finish();
                return Ok(());
            }
            // No prepared payload while waiting for a request/ACK or reading disk.
            // Keep remaining byte credit, release the unused share immediately.
            writer_ticket.park();
            let incoming = next_input(io, &mut pause, pausing).await?;
            let frame = match incoming {
                Input::Pause => {
                    if pausing.is_none() {
                        self.state(id, TaskState::Pausing).await?;
                        pausing = Some(Instant::now());
                    }
                    if resumed {
                        io.send(Message::Pause {
                            task_id: id.clone(),
                        })
                        .await?;
                    } else {
                        pending_pause = true;
                    }
                    continue;
                }
                Input::Frame(frame) => frame,
            };
            let super::frame_budget::BufferedFrame { frame, _lease } = frame;
            match frame.message {
                Message::Resume { have, .. } => {
                    let bitmap = ChunkBitmap::from_bytes(manifest.chunk_count(), &have)?;
                    acknowledged.extend(bitmap.present());
                    bytes = bytes_for(manifest, &acknowledged);
                    self.reset_rate(id, bytes);
                    resumed = true;
                    self.progress(id, bytes).await?;
                    if pending_pause {
                        io.send(Message::Pause {
                            task_id: id.clone(),
                        })
                        .await?;
                        pending_pause = false;
                    }
                }
                Message::RequestChunk { index, .. } => {
                    if !resumed
                        || sent.len() >= WINDOW
                        || acknowledged.contains(&index)
                        || !sent.insert(index)
                    {
                        return Err(disk::failure("重复或未授权分片请求"));
                    }
                    let source = file.clone();
                    let manifest = manifest.clone();
                    let data = blocking(move || {
                        disk::source_chunk(
                            &mut *source.lock().map_err(|_| disk::failure("源文件锁不可用"))?,
                            &manifest,
                            index,
                        )
                    })
                    .await?;
                    io.send_chunk(
                        &writer_ticket,
                        Message::Chunk {
                            task_id: id.clone(),
                            index,
                            data,
                        },
                    )
                    .await?;
                }
                Message::ChunkAck { index, .. } => {
                    if !sent.remove(&index) || !acknowledged.insert(index) {
                        return Err(disk::failure("重复或未知分片确认"));
                    }
                    bytes += manifest.chunk_range(index).unwrap().1 as u64;
                    if sampled.elapsed() >= PROGRESS_INTERVAL {
                        self.progress(id, bytes).await?;
                        sampled = Instant::now();
                    }
                }
                Message::Pause { .. } => {
                    if pausing.is_none() {
                        self.state(id, TaskState::Pausing).await?;
                        pausing = Some(Instant::now());
                        // Require the receiver's checkpoint acknowledgement before closing.
                        // Otherwise its outstanding ChunkAck frames can hit a reset stream.
                        io.send(Message::Pause {
                            task_id: id.clone(),
                        })
                        .await?;
                    }
                    io.send(Message::Paused {
                        task_id: id.clone(),
                        pause_request_id: frame.request_id,
                    })
                    .await?;
                }
                Message::Paused { .. } => {}
                Message::Completed { .. } => {
                    self.progress(id, manifest.total_len).await?;
                    self.receipt(id).await?;
                    io.finish();
                    return Ok(());
                }
                Message::Error { code, .. } => return Err(remote_error(code)),
                _ => return Err(disk::failure("发送任务收到非法消息")),
            }
        }
    }
    #[allow(dead_code)] // T010 commands.
    pub async fn start_speed(
        &self,
        peer: NodeId,
        direction: super::protocol::SpeedDirection,
        seconds: u16,
    ) -> Result<super::speed::SpeedSnapshot> {
        let speed = self
            .speed_peers
            .lock()
            .unwrap()
            .get(&peer)
            .cloned()
            .ok_or_else(|| disk::failure("请先连接测速对端"))?;
        speed.start(direction, seconds).await
    }
    #[allow(dead_code)] // T010 commands.
    pub fn cancel_speed(&self, peer: NodeId, id: &TaskId) -> Result<()> {
        self.speed_peers
            .lock()
            .unwrap()
            .get(&peer)
            .ok_or_else(|| disk::failure("测速连接已断开"))?
            .cancel(id)
    }
    #[allow(dead_code)] // T010 presentation.
    pub fn speed_snapshots(&self) -> HashMap<NodeId, super::speed::SpeedSnapshot> {
        self.speed_peers
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(peer, speed)| speed.snapshot().map(|s| (*peer, s)))
            .collect()
    }
    pub async fn serve_peer_with_speed(
        &self,
        connection: Connection,
        peer: NodeId,
        local: NodeId,
    ) -> Result<()> {
        let speed = super::speed::SpeedPeer::new(
            connection.clone(),
            local,
            peer,
            self.activity.clone(),
            self.changed.clone(),
        );
        self.speed_peers.lock().unwrap().insert(peer, speed.clone());
        struct RemovePeer {
            map: Arc<Mutex<HashMap<NodeId, super::speed::SpeedPeer>>>,
            peer: NodeId,
            speed: super::speed::SpeedPeer,
        }
        impl Drop for RemovePeer {
            fn drop(&mut self) {
                self.speed.cancel_all();
                let mut map = self.map.lock().unwrap();
                if map
                    .get(&self.peer)
                    .is_some_and(|s| s.same_connection(&self.speed))
                {
                    map.remove(&self.peer);
                }
            }
        }
        let _guard = RemovePeer {
            map: self.speed_peers.clone(),
            peer,
            speed: speed.clone(),
        };
        self.serve_peer_inner(connection, peer, Some(speed)).await
    }
    /// Test convenience; production always enables negotiated speed business.
    #[cfg(test)]
    pub async fn serve_peer(&self, connection: Connection, peer: NodeId) -> Result<()> {
        self.serve_peer_inner(connection, peer, None).await
    }
    async fn serve_peer_inner(
        &self,
        connection: Connection,
        peer: NodeId,
        speed: Option<super::speed::SpeedPeer>,
    ) -> Result<()> {
        let mut streams = JoinSet::new();
        if let Some(speed) = speed.clone() {
            streams.spawn(async move {
                speed.serve_uni().await;
                Ok(())
            });
        }
        loop {
            tokio::select! {
                accepted=connection.accept_bi()=> {
                    let (mut send,mut recv)=match accepted { Ok(streams)=>streams, Err(_)=>break };
                    if streams.len()>=8 {let _=send.reset(4u32.into());let _=recv.stop(4u32.into());continue;}
                    let service=self.clone();let connection=connection.clone();let speed=speed.clone();
                    streams.spawn(async move {
                        let buffered=tokio::time::timeout(Duration::from_secs(5),service.frame_budget.read(&mut recv,None)).await.map_err(|_|disk::failure("文件流首帧超时"))??;
                        let super::frame_budget::BufferedFrame {frame:first,_lease}=buffered;
                        match &first.message {
                            Message::Speed(_)=> { let speed=speed.ok_or_else(||disk::failure("对端不支持测速执行"))?;drop(_lease);speed.serve_control(send,recv,first).await },
                            Message::Offer{..} => service.receive_offer(send,recv,peer,super::frame_budget::BufferedFrame{frame:first,_lease}).await,
                            Message::ResumeTask{task_id} if first.request_id==1 => {
                                let id=task_id.clone();let lookup=id.clone();
                                let checked=service.read_store(move|store|disk::bound_task(store,peer,&lookup)).await;
                                if !matches!(checked, Ok(ref record) if record.direction()==TaskDirection::Send && can_continue(record)) {
                                    let code = match &checked {
                                        Ok(record) if record.direction()==TaskDirection::Send => match record.diagnostic().map(TaskDiagnostic::code) {
                                            Some(TaskErrorCode::SourceChanged) => ErrorCode::SourceChanged,
                                            Some(TaskErrorCode::SourceUnavailable) => ErrorCode::SourceMissing,
                                            _ => ErrorCode::InvalidState,
                                        },
                                        _ => ErrorCode::UnknownTask,
                                    };
                                    protocol::write(&mut send,&Frame{request_id:1,message:Message::Error{task_id:id.clone(),code}}).await?;
                                    let _=send.finish();return Err(remote_error(code));
                                }
                                service.wait_previous_attempt(&id).await?;
                                let slot=match service.reserve_send(peer,id.clone()).await {
                                    Ok(slot)=>slot,
                                    Err(error)=> {protocol::write(&mut send,&Frame{request_id:1,message:Message::Error{task_id:id.clone(),code:ErrorCode::Busy}}).await?;let _=send.finish();return Err(error);}
                                };
                                let metadata=checked.as_ref().unwrap().directory_details().is_some();
                                let (_guard,pause)=match service.claim(peer,&id,TaskDirection::Send,metadata,Some(slot.generation)) {
                                    Ok(claim)=>claim,
                                    Err(error)=> {
                                        protocol::write(&mut send,&Frame{request_id:1,message:Message::Error{task_id:id.clone(),code:ErrorCode::Busy}}).await?;
                                        let _=send.finish();return Err(error);
                                    }
                                };
                                let result=service.send_inner(&connection,peer,&id,pause,Some(&mut send)).await;
                                if let Err(error)=&result {
                                    let _=protocol::write(&mut send,&Frame{request_id:1,message:Message::Error{task_id:id.clone(),code:error_code(error)}}).await;
                                    let _=send.finish();service.finish_error(&id,error).await;
                                }
                                result
                            }
                            _=>Err(disk::failure("桌面流入口仅接受任务 Offer 或 ID-only Continue")),
                        }
                    });
                }
                result=streams.join_next(),if !streams.is_empty()=> {if let Some(Err(error))=result {tracing::warn!(%error,"桌面文件任务终止");}}
            }
        }
        streams.abort_all();
        while streams.join_next().await.is_some() {}
        Ok(())
    }
    pub async fn resume(&self, connection: &Connection, peer: NodeId, id: TaskId) -> Result<()> {
        let lookup = id.clone();
        let record = self
            .read_store(move |store| disk::bound_task(store, peer, &lookup))
            .await?;
        if record.direction() == TaskDirection::Send {
            #[cfg(test)]
            return self.send_file(connection, peer, id).await;
            #[cfg(not(test))]
            return self.enqueue_tasks(peer, vec![id]).await;
        }
        if !can_continue(&record) {
            return Err(disk::failure("任务当前不能继续"));
        }
        self.wait_previous_attempt(&id).await?;
        self.state(&id, TaskState::Queued).await?;
        let result = tokio::time::timeout(IDLE_TIMEOUT, async {
            let (mut send, mut recv) = connection.open_bi().await.map_err(disk::local_error)?;
            protocol::write(
                &mut send,
                &Frame {
                    request_id: 1,
                    message: Message::ResumeTask {
                        task_id: id.clone(),
                    },
                },
            )
            .await?;
            let response = protocol::read(&mut recv).await?;
            let _ = send.finish();
            match response.message {
                Message::ResumeTask { task_id } if task_id == id && response.request_id == 1 => {
                    Ok(())
                }
                Message::Error { task_id, code } if task_id == id => Err(remote_error(code)),
                _ => Err(disk::failure("继续响应身份不符")),
            }
        })
        .await
        .unwrap_or_else(|_| Err(disk::failure("继续请求超时")));
        if let Err(error) = &result {
            self.finish_error(&id, error).await;
        }
        result
    }
    async fn receive_offer(
        &self,
        mut send: SendStream,
        recv: RecvStream,
        peer: NodeId,
        buffered: super::frame_budget::BufferedFrame,
    ) -> Result<()> {
        let super::frame_budget::BufferedFrame {
            frame: first,
            _lease,
        } = buffered;
        let Message::Offer {
            task_id,
            relative_path,
            entry,
            group_id,
        } = first.message.clone()
        else {
            return Err(disk::failure("需要目录或文件 Offer"));
        };
        if entry == Entry::Directory {
            return self
                .receive_directory(
                    send,
                    recv,
                    peer,
                    super::frame_budget::BufferedFrame {
                        frame: first,
                        _lease,
                    },
                )
                .await;
        }
        let Entry::File(manifest) = entry else {
            unreachable!()
        };
        let (_guard, pause) = self.claim_receive(&mut send, peer, &task_id, false).await?;
        let mut io = TaskIo::new(send, recv, peer, task_id.clone(), self.frame_budget.clone());
        io.observe(&first)?;
        drop(first);
        let root = self.receive_root.lock().unwrap().clone();
        let id = task_id.clone();
        let record = self
            .store(move |store| {
                disk::accept_entry(store, peer, &id, &root, relative_path, *manifest, group_id)
            })
            .await?;
        drop(_lease);
        if record.file_details().unwrap().receipt_committed {
            let completed = record.clone();
            if blocking(move || disk::cleanup_staging(&completed))
                .await
                .is_err()
            {
                tracing::warn!("持久回执重发；暂存清理仍需重试");
            }
            io.send(Message::Completed {
                task_id,
                root_hash: record.file_details().unwrap().manifest.root_hash,
                receipt_version: 1,
            })
            .await?;
            io.finish();
            return Ok(());
        }
        self.state(&task_id, TaskState::Transferring).await?;
        let local = record.clone();
        let download = match blocking(move || disk::open_download(&local)).await {
            Ok(download) => download,
            Err(error) => {
                io.report_error(&error).await;
                self.finish_error(&task_id, &error).await;
                return Err(error);
            }
        };
        let download = Arc::new(Mutex::new(download));
        let result = self
            .receiver_loop(&mut io, &record, download.clone(), pause)
            .await;
        if let Err(error) = &result {
            let checkpoint = download.clone();
            let _ = blocking(move || {
                checkpoint
                    .lock()
                    .map_err(|_| disk::failure("接收文件锁不可用"))?
                    .checkpoint()
            })
            .await;
            io.report_error(error).await;
            self.finish_error(&task_id, error).await;
        }
        result
    }
    async fn receive_directory(
        &self,
        mut send: SendStream,
        recv: RecvStream,
        peer: NodeId,
        buffered: super::frame_budget::BufferedFrame,
    ) -> Result<()> {
        let super::frame_budget::BufferedFrame {
            frame: first,
            _lease,
        } = buffered;
        let Message::Offer {
            task_id,
            group_id,
            relative_path,
            entry: Entry::Directory,
        } = first.message.clone()
        else {
            return Err(disk::failure("目录 Offer 非法"));
        };
        let (_guard, _pause) = self.claim_receive(&mut send, peer, &task_id, true).await?;
        let mut io = TaskIo::new(send, recv, peer, task_id.clone(), self.frame_budget.clone());
        io.observe(&first)?;
        drop(first);
        let root = self.receive_root.lock().unwrap().clone();
        let id = task_id.clone();
        let record = self
            .store(move |store| {
                disk::accept_directory(store, peer, &id, &root, relative_path, group_id)
            })
            .await?;
        drop(_lease);
        let result = async {
            if !record.receipt_committed() {
                self.state(&task_id, TaskState::Transferring).await?;
                self.state(&task_id, TaskState::Finalizing).await?;
                let local = record.clone();
                self.store(move |store| super::publish::directory(store, &local))
                    .await?;
            }
            io.send(Message::Completed {
                task_id: task_id.clone(),
                root_hash: crate::protocol::manifest::ChunkHash::of(
                    record.relative_path().unwrap().as_bytes(),
                ),
                receipt_version: 1,
            })
            .await?;
            io.finish();
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            io.report_error(error).await;
            self.finish_error(&task_id, error).await;
        }
        result
    }
    async fn receiver_loop(
        &self,
        io: &mut TaskIo,
        record: &TaskRecord,
        download: Arc<Mutex<crate::storage::PartialDownload>>,
        mut pause: watch::Receiver<bool>,
    ) -> Result<()> {
        let id = record.task_id();
        let manifest = &record.file_details().unwrap().manifest;
        let initial = download.clone();
        let (have, missing, mut bytes) = blocking(move || {
            let download = initial
                .lock()
                .map_err(|_| disk::failure("接收文件锁不可用"))?;
            let present = download.bitmap().present().into_iter().collect();
            Ok((
                download.bitmap().to_bytes(),
                download.missing(),
                bytes_for(download.manifest(), &present),
            ))
        })
        .await?;
        let mut missing: VecDeque<_> = missing.into();
        let mut outstanding = HashSet::new();
        let mut sampled = Instant::now();
        let mut pausing = None;
        let mut remote_pause = None;
        let mut checkpointed = false;
        io.send(Message::Resume {
            task_id: id.clone(),
            root_hash: manifest.root_hash,
            have,
        })
        .await?;
        self.reset_rate(id, bytes);
        self.progress(id, bytes).await?;
        loop {
            if bytes == manifest.total_len {
                self.state(id, TaskState::Finalizing).await?;
                let record = record.clone();
                let output = download.clone();
                self.store(move |store| {
                    disk::publish(
                        store,
                        &record,
                        &mut *output
                            .lock()
                            .map_err(|_| disk::failure("接收文件锁不可用"))?,
                    )
                })
                .await?;
                self.progress(id, manifest.total_len).await?;
                #[cfg(test)]
                if self
                    .drop_completion
                    .swap(false, std::sync::atomic::Ordering::AcqRel)
                {
                    let _ = io.send.reset(77u32.into());
                    return Err(disk::failure("测试在持久回执后切断完成消息"));
                }
                io.send(Message::Completed {
                    task_id: id.clone(),
                    root_hash: manifest.root_hash,
                    receipt_version: 1,
                })
                .await?;
                io.finish();
                return Ok(());
            }
            if pausing.is_none() {
                while outstanding.len() < WINDOW {
                    let Some(index) = missing.pop_front() else {
                        break;
                    };
                    outstanding.insert(index);
                    io.send(Message::RequestChunk {
                        task_id: id.clone(),
                        index,
                    })
                    .await?;
                }
            } else if outstanding.is_empty() {
                if !checkpointed {
                    let file = download.clone();
                    blocking(move || {
                        file.lock()
                            .map_err(|_| disk::failure("接收文件锁不可用"))?
                            .checkpoint()
                    })
                    .await?;
                    checkpointed = true;
                }
                if let Some(request_id) = remote_pause.take() {
                    io.send(Message::Paused {
                        task_id: id.clone(),
                        pause_request_id: request_id,
                    })
                    .await?;
                }
                if io.gate.state(id) == Some(WireTaskState::Paused) {
                    self.progress(id, bytes).await?;
                    self.state(id, TaskState::Paused).await?;
                    io.finish();
                    return Ok(());
                }
            }
            let frame = match next_input(io, &mut pause, pausing).await? {
                Input::Pause => {
                    if pausing.is_none() {
                        self.state(id, TaskState::Pausing).await?;
                        pausing = Some(Instant::now());
                    }
                    io.send(Message::Pause {
                        task_id: id.clone(),
                    })
                    .await?;
                    continue;
                }
                Input::Frame(frame) => frame,
            };
            let super::frame_budget::BufferedFrame { frame, _lease } = frame;
            match frame.message {
                Message::Chunk { index, data, .. } => {
                    if !outstanding.remove(&index) {
                        return Err(disk::failure("收到未请求或重复的分片"));
                    }
                    let output = download.clone();
                    let length = data.len() as u64;
                    blocking(move || {
                        output
                            .lock()
                            .map_err(|_| disk::failure("接收文件锁不可用"))?
                            .write_chunk(index, &data)
                    })
                    .await?;
                    #[cfg(test)]
                    {
                        let checkpointed =
                            download.lock().unwrap().durable_bitmap().count_set() > 0;
                        if checkpointed {
                            let gate = self.checkpoint_gate.lock().unwrap().take();
                            if let Some((reached, release)) = gate {
                                let _ = reached.send(());
                                let _ = release.await;
                            }
                        }
                        let gate = self.first_chunk_gate.lock().unwrap().take();
                        if let Some((reached, release)) = gate {
                            let _ = reached.send(());
                            let _ = release.await;
                        }
                    }
                    bytes += length;
                    io.send(Message::ChunkAck {
                        task_id: id.clone(),
                        index,
                    })
                    .await?;
                    if sampled.elapsed() >= PROGRESS_INTERVAL {
                        self.progress(id, bytes).await?;
                        sampled = Instant::now();
                    }
                }
                Message::Pause { .. } => {
                    if pausing.is_none() {
                        self.state(id, TaskState::Pausing).await?;
                        pausing = Some(Instant::now());
                    }
                    remote_pause = Some(frame.request_id);
                }
                Message::Paused { .. } => {}
                Message::Error { code, .. } => return Err(remote_error(code)),
                _ => return Err(disk::failure("接收任务收到非法消息")),
            }
        }
    }
}

fn can_continue(record: &TaskRecord) -> bool {
    matches!(record.state(), TaskState::Paused | TaskState::Interrupted)
        || (record.state() == TaskState::Failed
            && record
                .diagnostic()
                .is_some_and(TaskDiagnostic::is_retryable))
}

fn bytes_for(manifest: &FileManifest, indices: &HashSet<u32>) -> u64 {
    indices
        .iter()
        .filter_map(|i| manifest.chunk_range(*i))
        .map(|(_, len)| len as u64)
        .sum()
}
fn is_storage_error(error: &Error) -> bool {
    if let Error::Io(error) = error {
        return !matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::TimedOut
        );
    }
    let text = error.to_string();
    text.contains("存储")
        || text.contains("发布")
        || text.contains("接收目标已存在")
        || text.contains("接收根目录")
}
fn error_code(error: &Error) -> ErrorCode {
    let text = error.to_string();
    if text.contains("源文件内容已变化") {
        ErrorCode::SourceChanged
    } else if text.contains("源文件不可用") {
        ErrorCode::SourceMissing
    } else if is_storage_error(error) {
        ErrorCode::Storage
    } else {
        ErrorCode::Interrupted
    }
}
fn remote_error(code: ErrorCode) -> Error {
    disk::failure(match code {
        ErrorCode::SourceChanged => "源文件内容已变化",
        ErrorCode::SourceMissing => "源文件不可用",
        ErrorCode::Storage => "对端存储不可用",
        ErrorCode::Busy => "对端资源忙，请稍后继续",
        _ => "对端传输中断",
    })
}

struct TaskIo {
    send: SendStream,
    incoming: mpsc::Receiver<Result<super::frame_budget::BufferedFrame>>,
    reader: JoinHandle<()>,
    gate: TaskProtocol,
    peer: NodeId,
    id: TaskId,
}
impl Drop for TaskIo {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
impl TaskIo {
    fn new(
        send: SendStream,
        mut recv: RecvStream,
        peer: NodeId,
        id: TaskId,
        budget: super::frame_budget::FrameBudget,
    ) -> Self {
        let (tx, incoming) = mpsc::channel(2);
        let task_limit = super::frame_budget::FrameBudget::task_limit();
        let reader = tokio::spawn(async move {
            loop {
                let frame = budget.read(&mut recv, Some(task_limit.clone())).await;
                let failed = frame.is_err();
                if tx.send(frame).await.is_err() || failed {
                    break;
                }
            }
        });
        Self {
            send,
            incoming,
            reader,
            gate: TaskProtocol::new(peer),
            peer,
            id,
        }
    }
    fn observe(&mut self, frame: &Frame) -> Result<()> {
        self.gate.observe(self.peer, Actor::Remote, frame)
    }
    async fn send(&mut self, message: Message) -> Result<()> {
        let frame = Frame {
            request_id: self.gate.next_request_id(&self.id, Actor::Local)?,
            message,
        };
        self.gate.observe(self.peer, Actor::Local, &frame)?;
        tokio::time::timeout(IDLE_TIMEOUT, protocol::write(&mut self.send, &frame))
            .await
            .map_err(|_| disk::failure("文件控制帧发送超时"))?
    }
    async fn send_chunk(
        &mut self,
        ticket: &super::queue::WriteTicket,
        message: Message,
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let frame = Frame {
            request_id: self.gate.next_request_id(&self.id, Actor::Local)?,
            message,
        };
        self.gate.observe(self.peer, Actor::Local, &frame)?;
        let Message::Chunk { data, .. } = &frame.message else {
            return Err(disk::failure("字节调度仅接受分片数据"));
        };
        let encoded = frame.encode()?;
        // Chunk.data is the final postcard field. Keep framing/control bytes
        // outside the payload quantum; verify the layout instead of guessing.
        if !encoded.ends_with(data) {
            return Err(disk::failure("分片编码布局不受支持"));
        }
        let prefix = encoded.len() - data.len();
        drop(frame);
        tokio::time::timeout(IDLE_TIMEOUT, async {
            self.send
                .write_all(&(encoded.len() as u32).to_le_bytes())
                .await
                .map_err(disk::local_error)?;
            self.send
                .write_all(&encoded[..prefix])
                .await
                .map_err(disk::local_error)?;
            ticket.write_all(&mut self.send, &encoded[prefix..]).await?;
            self.send.flush().await.map_err(disk::local_error)?;
            Ok::<(), Error>(())
        })
        .await
        .map_err(|_| disk::failure("文件数据帧发送超时"))?
    }
    fn finish(&mut self) {
        let _ = self.send.finish();
    }
    async fn report_error(&mut self, error: &Error) {
        let _ = self
            .send(Message::Error {
                task_id: self.id.clone(),
                code: error_code(error),
            })
            .await;
        self.finish();
    }
}
enum Input {
    Pause,
    Frame(super::frame_budget::BufferedFrame),
}
async fn next_input(
    io: &mut TaskIo,
    pause: &mut watch::Receiver<bool>,
    pausing: Option<Instant>,
) -> Result<Input> {
    let timeout = pausing.map_or(IDLE_TIMEOUT, |started| {
        PAUSE_TIMEOUT.saturating_sub(started.elapsed())
    });
    if timeout.is_zero() {
        return Err(disk::failure("暂停确认超时"));
    }
    tokio::select! {
        biased;
        changed=pause.changed()=> {changed.map_err(|_|disk::failure("暂停控制已关闭"))?;Ok(Input::Pause)}
        frame=io.incoming.recv()=> {let frame=frame.ok_or_else(||disk::failure("文件流已关闭"))??;io.observe(&frame.frame)?;Ok(Input::Frame(frame))}
        _=tokio::time::sleep(timeout)=>Err(disk::failure(if pausing.is_some(){"暂停确认超时"}else{"文件传输超时"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::Identity,
        transport::{
            handshake::{handshake_initiator, handshake_responder},
            quic::{ChannelBinding, client_endpoint, server_endpoint},
        },
    };
    use std::fs;
    struct Pair {
        root: PathBuf,
        a: TransferService,
        b: TransferService,
        ca: Connection,
        cb: Connection,
        ia: NodeId,
        ib: NodeId,
        ea: quinn::Endpoint,
        eb: quinn::Endpoint,
        tasks: JoinSet<Result<()>>,
    }
    impl Pair {
        async fn new() -> Self {
            Self::new_inner(false).await
        }
        async fn new_inner(speed: bool) -> Self {
            let root = std::env::temp_dir()
                .join(format!("p2p-desktop-transfer-{}", rand::random::<u128>()));
            fs::create_dir(&root).unwrap();
            for dir in ["a-receive", "b-receive"] {
                fs::create_dir(root.join(dir)).unwrap();
            }
            let (store_a, _) = TaskStore::open(&root.join("a-state/tasks.json")).unwrap();
            let (store_b, _) = TaskStore::open(&root.join("b-state/tasks.json")).unwrap();
            let a = TransferService::new(store_a, root.join("a-receive"));
            let b = TransferService::new(store_b, root.join("b-receive"));
            let identity_a = Identity::generate();
            let identity_b = Identity::generate();
            let ia = identity_a.node_id();
            let ib = identity_b.node_id();
            let ea = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
            let eb = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
            let server = eb.clone();
            let remote = tokio::spawn(async move {
                let connection = server.accept().await.unwrap().await.unwrap();
                let binding = ChannelBinding::from_connection(&connection).unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let outcome = handshake_responder(&mut send, &mut recv, &identity_b, &binding)
                    .await
                    .unwrap();
                assert_eq!(outcome.peer_node_id, ia);
                send.finish().unwrap();
                protocol::negotiate(&connection, false).await.unwrap();
                connection
            });
            let ca = crate::transport::quic::connect(&ea, eb.local_addr().unwrap(), "p2pfile")
                .await
                .unwrap();
            let binding = ChannelBinding::from_connection(&ca).unwrap();
            let (mut send, mut recv) = ca.open_bi().await.unwrap();
            let outcome = handshake_initiator(&mut send, &mut recv, &identity_a, &binding)
                .await
                .unwrap();
            assert_eq!(outcome.peer_node_id, ib);
            send.finish().unwrap();
            protocol::negotiate(&ca, true).await.unwrap();
            let cb = remote.await.unwrap();
            let mut tasks = JoinSet::new();
            let service = a.clone();
            let conn = ca.clone();
            tasks.spawn(async move {
                if speed {
                    service.serve_peer_with_speed(conn, ib, ia).await
                } else {
                    service.serve_peer(conn, ib).await
                }
            });
            let service = b.clone();
            let conn = cb.clone();
            tasks.spawn(async move {
                if speed {
                    service.serve_peer_with_speed(conn, ia, ib).await
                } else {
                    service.serve_peer(conn, ia).await
                }
            });
            if speed {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if a.speed_peers.lock().unwrap().contains_key(&ib)
                            && b.speed_peers.lock().unwrap().contains_key(&ia)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                a.speed_peers.lock().unwrap()[&ib].set_test_duration(Duration::from_millis(80));
                b.speed_peers.lock().unwrap()[&ia].set_test_duration(Duration::from_millis(80));
            }
            Self {
                root,
                a,
                b,
                ca,
                cb,
                ia,
                ib,
                ea,
                eb,
                tasks,
            }
        }
        async fn select(&self, length: usize) -> (TaskId, Vec<u8>) {
            let bytes = (0..length).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let path = self.root.join("文件.bin");
            fs::write(&path, &bytes).unwrap();
            let id = self.a.select_file(self.ib, path).await.unwrap();
            (id, bytes)
        }
        async fn shutdown(mut self) {
            self.ca.close(0u32.into(), b"test done");
            self.cb.close(0u32.into(), b"test done");
            while self.tasks.join_next().await.is_some() {}
            self.ea.close(0u32.into(), b"test done");
            self.eb.close(0u32.into(), b"test done");
            self.ea.wait_idle().await;
            self.eb.wait_idle().await;
            drop(self.a);
            drop(self.b);
            fs::remove_dir_all(self.root).unwrap();
        }
        fn sender(&self, id: TaskId) -> JoinHandle<Result<()>> {
            let service = self.a.clone();
            let conn = self.ca.clone();
            let peer = self.ib;
            tokio::spawn(async move { service.send_file(&conn, peer, id).await })
        }
        fn gate(
            &self,
        ) -> (
            tokio::sync::oneshot::Receiver<()>,
            tokio::sync::oneshot::Sender<()>,
        ) {
            let (reached_tx, reached) = tokio::sync::oneshot::channel();
            let (release, release_rx) = tokio::sync::oneshot::channel();
            *self.b.first_chunk_gate.lock().unwrap() = Some((reached_tx, release_rx));
            (reached, release)
        }
    }
    async fn wait_state(service: &TransferService, id: &TaskId, state: TaskState) {
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            let mut events = service.subscribe();
            loop {
                if service
                    .task(id.clone())
                    .await
                    .is_ok_and(|r| r.state() == state)
                {
                    break;
                }
                events.changed().await.unwrap();
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "waiting {state:?}, actual {:?}",
            service
                .task(id.clone())
                .await
                .map(|record| (record.state(), record.diagnostic()))
        );
    }
    #[tokio::test]
    async fn authenticated_single_file_and_empty_file_complete_with_durable_receipts() {
        let pair = Pair::new().await;
        for size in [2 * 1024 * 1024, 0] {
            let (id, bytes) = pair.select(size).await;
            if size == 0 {
                fs::remove_file(pair.root.join("b-receive/文件.bin")).unwrap();
            }
            tokio::time::timeout(
                Duration::from_secs(10),
                pair.a.send_file(&pair.ca, pair.ib, id.clone()),
            )
            .await
            .unwrap()
            .unwrap();
            wait_state(&pair.b, &id, TaskState::Completed).await;
            assert_eq!(
                fs::read(pair.root.join("b-receive/文件.bin")).unwrap(),
                bytes
            );
            for service in [&pair.a, &pair.b] {
                let record = service.task(id.clone()).await.unwrap();
                assert_eq!(record.state(), TaskState::Completed);
                assert!(record.file_details().unwrap().receipt_committed);
                assert_eq!(
                    record.progress_hint().unwrap().verified_bytes(),
                    size as u64
                );
            }
        }
        let reverse = pair.root.join("返回.bin");
        let reverse_bytes = vec![91; 300 * 1024];
        fs::write(&reverse, &reverse_bytes).unwrap();
        let reverse_id = pair.b.select_file(pair.ia, reverse).await.unwrap();
        pair.b
            .send_file(&pair.cb, pair.ia, reverse_id.clone())
            .await
            .unwrap();
        wait_state(&pair.a, &reverse_id, TaskState::Completed).await;
        assert_eq!(
            fs::read(pair.root.join("a-receive/返回.bin")).unwrap(),
            reverse_bytes
        );
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn sender_receiver_and_simultaneous_pause_then_id_only_continue() {
        for side in 0..3 {
            let pair = Pair::new().await;
            let (id, bytes) = pair.select(4 * 1024 * 1024).await;
            let (reached, release) = pair.gate();
            let sender = pair.sender(id.clone());
            tokio::time::timeout(Duration::from_secs(10), reached)
                .await
                .unwrap()
                .unwrap();
            if side != 1 {
                pair.a.pause(&id).unwrap();
                pair.a.pause(&id).unwrap();
            }
            if side != 0 {
                pair.b.pause(&id).unwrap();
            }
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(10), sender)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            wait_state(&pair.a, &id, TaskState::Paused).await;
            wait_state(&pair.b, &id, TaskState::Paused).await;
            let receiver = pair.b.task(id.clone()).await.unwrap();
            let download = disk::open_download(&receiver).unwrap();
            assert!(download.bitmap().count_set() > 0);
            assert!(!download.is_complete());
            drop(download);
            pair.b.resume(&pair.cb, pair.ia, id.clone()).await.unwrap();
            wait_state(&pair.a, &id, TaskState::Completed).await;
            wait_state(&pair.b, &id, TaskState::Completed).await;
            assert_eq!(
                fs::read(pair.root.join("b-receive/文件.bin")).unwrap(),
                bytes
            );
            pair.shutdown().await;
        }
    }
    #[tokio::test]
    async fn pause_racing_last_chunk_preserves_completed_receipt() {
        let pair = Pair::new().await;
        let (id, _) = pair.select(33).await;
        let (reached, release) = pair.gate();
        let sender = pair.sender(id.clone());
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .unwrap()
            .unwrap();
        pair.a.pause(&id).unwrap();
        pair.b.pause(&id).unwrap();
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), sender)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        wait_state(&pair.a, &id, TaskState::Completed).await;
        wait_state(&pair.b, &id, TaskState::Completed).await;
        pair.shutdown().await;
    }

    // This test function is also the isolated child-process entrypoint. The parent
    // below executes this exact test only; no production binary/test switches exist.
    #[test]
    fn process_worker_entry() {
        let Some(root) = std::env::var_os("P2P_DESKTOP_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let role = std::env::var("P2P_DESKTOP_TEST_ROLE").unwrap();
        let mode = std::env::var("P2P_DESKTOP_TEST_MODE").unwrap();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let identity =
                    Identity::load_or_create(&root.join(format!("{role}-state/identity.bin")))
                        .unwrap();
                let other = if role == "a" { "b" } else { "a" };
                let peer =
                    Identity::load_or_create(&root.join(format!("{other}-state/identity.bin")))
                        .unwrap()
                        .node_id();
                let (store, _) =
                    TaskStore::open(&root.join(format!("{role}-state/tasks.json"))).unwrap();
                let service = TransferService::new(store, root.join(format!("{role}-receive")));
                let endpoint = if role == "a" {
                    client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap()
                } else {
                    server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap()
                };
                let connection = if role == "b" {
                    fs::write(
                        root.join("receiver-address"),
                        endpoint.local_addr().unwrap().to_string(),
                    )
                    .unwrap();
                    let connection = endpoint.accept().await.unwrap().await.unwrap();
                    let binding = ChannelBinding::from_connection(&connection).unwrap();
                    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                    assert_eq!(
                        handshake_responder(&mut send, &mut recv, &identity, &binding)
                            .await
                            .unwrap()
                            .peer_node_id,
                        peer
                    );
                    send.finish().unwrap();
                    protocol::negotiate(&connection, false).await.unwrap();
                    connection
                } else {
                    let addr = fs::read_to_string(root.join("receiver-address"))
                        .unwrap()
                        .parse()
                        .unwrap();
                    let connection = crate::transport::quic::connect(&endpoint, addr, "p2pfile")
                        .await
                        .unwrap();
                    let binding = ChannelBinding::from_connection(&connection).unwrap();
                    let (mut send, mut recv) = connection.open_bi().await.unwrap();
                    assert_eq!(
                        handshake_initiator(&mut send, &mut recv, &identity, &binding)
                            .await
                            .unwrap()
                            .peer_node_id,
                        peer
                    );
                    send.finish().unwrap();
                    protocol::negotiate(&connection, true).await.unwrap();
                    connection
                };
                let mut helpers = JoinSet::new();
                if role == "b" && mode == "first" {
                    let (reached_tx, reached) = tokio::sync::oneshot::channel();
                    let (release, release_rx) = tokio::sync::oneshot::channel();
                    *service.checkpoint_gate.lock().unwrap() = Some((reached_tx, release_rx));
                    let root = root.clone();
                    helpers.spawn(async move {
                        reached.await.unwrap();
                        fs::write(root.join("checkpoint-reached"), b"durable bitmap nonempty")
                            .unwrap();
                        while !root.join("release").exists() {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        let _ = release.send(());
                    });
                }
                let stop_root = root.clone();
                let stop_connection = connection.clone();
                helpers.spawn(async move {
                    while !stop_root.join("stop").exists() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    stop_connection.close(0u32.into(), b"surviving process graceful stop");
                });
                if role == "a" {
                    let id = if mode == "first" {
                        let id = service
                            .select_file(peer, root.join("source.bin"))
                            .await
                            .unwrap();
                        fs::write(root.join("task-id"), id.as_str()).unwrap();
                        id
                    } else {
                        TaskId::parse(&fs::read_to_string(root.join("task-id")).unwrap()).unwrap()
                    };
                    let result = service.send_file(&connection, peer, id.clone()).await;
                    if mode == "resume" {
                        result.unwrap();
                        assert_eq!(
                            service.task(id).await.unwrap().state(),
                            TaskState::Completed
                        );
                        fs::write(root.join("sender-complete"), b"receipt").unwrap();
                    } else {
                        assert!(root.join("stop").exists());
                    }
                    connection.close(0u32.into(), b"sender done");
                } else {
                    let _ = service.serve_peer(connection.clone(), peer).await;
                    if mode == "resume" {
                        let id = TaskId::parse(&fs::read_to_string(root.join("task-id")).unwrap())
                            .unwrap();
                        assert_eq!(
                            service.task(id).await.unwrap().state(),
                            TaskState::Completed
                        );
                    }
                }
                helpers.abort_all();
                while helpers.join_next().await.is_some() {}
                service.interrupt_all().await.unwrap();
                endpoint.close(0u32.into(), b"child done");
                endpoint.wait_idle().await;
            });
    }

    struct ChildProcess(std::process::Child);
    impl Drop for ChildProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn child(root: &std::path::Path, role: &str, mode: &str) -> ChildProcess {
        let log = fs::File::create(root.join(format!("{role}-{mode}.log"))).unwrap();
        ChildProcess(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "desktop::transfer::tests::process_worker_entry",
                    "--nocapture",
                ])
                .env("P2P_DESKTOP_TEST_ROOT", root)
                .env("P2P_DESKTOP_TEST_ROLE", role)
                .env("P2P_DESKTOP_TEST_MODE", mode)
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        )
    }
    fn await_file(path: &std::path::Path) {
        let start = Instant::now();
        while !path.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "process milestone missing: {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn await_success(child: &mut ChildProcess, root: &std::path::Path, role: &str, mode: &str) {
        let start = Instant::now();
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "child failed: {}",
                    fs::read_to_string(root.join(format!("{role}-{mode}.log"))).unwrap()
                );
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "child exit deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn real_process_kill_of_either_endpoint_resumes_verified_durable_chunks() {
        use std::io::Write;
        for killed in ["a", "b"] {
            let root = std::env::temp_dir().join(format!(
                "p2p-desktop-process-kill-{killed}-{}",
                rand::random::<u128>()
            ));
            fs::create_dir(&root).unwrap();
            for role in ["a", "b"] {
                super::super::config::ensure_private_app_dir(&root.join(format!("{role}-state")))
                    .unwrap();
                fs::create_dir(root.join(format!("{role}-receive"))).unwrap();
                Identity::load_or_create(&root.join(format!("{role}-state/identity.bin"))).unwrap();
            }
            let mut source = fs::File::create(root.join("source.bin")).unwrap();
            let chunk = vec![73; 1024 * 1024];
            for _ in 0..70 {
                source.write_all(&chunk).unwrap();
            }
            source.sync_all().unwrap();
            drop(source);
            let mut receiver = child(&root, "b", "first");
            await_file(&root.join("receiver-address"));
            let mut sender = child(&root, "a", "first");
            await_file(&root.join("checkpoint-reached"));
            let victim = if killed == "a" {
                &mut sender
            } else {
                &mut receiver
            };
            victim.0.kill().unwrap();
            assert!(!victim.0.wait().unwrap().success());
            fs::write(root.join("release"), b"release survivor").unwrap();
            fs::write(root.join("stop"), b"graceful survivor").unwrap();
            if killed == "a" {
                await_success(&mut receiver, &root, "b", "first");
            } else {
                await_success(&mut sender, &root, "a", "first");
            }
            let id = TaskId::parse(&fs::read_to_string(root.join("task-id")).unwrap()).unwrap();
            let (store, _) = TaskStore::open(&root.join("b-state/tasks.json")).unwrap();
            let record = store.task(&id).unwrap();
            assert_eq!(record.state(), TaskState::Interrupted);
            let download = disk::open_download(&record).unwrap();
            let durable = download.bitmap().count_set();
            assert!(durable > 0);
            assert!(!download.is_complete());
            drop(download);
            drop(store);
            for name in ["receiver-address", "checkpoint-reached", "release", "stop"] {
                fs::remove_file(root.join(name)).unwrap();
            }
            let mut receiver = child(&root, "b", "resume");
            await_file(&root.join("receiver-address"));
            let mut sender = child(&root, "a", "resume");
            await_success(&mut sender, &root, "a", "resume");
            await_success(&mut receiver, &root, "b", "resume");
            let expected = crate::transfer::chunker::manifest_from_path(
                &root.join("source.bin"),
                crate::protocol::manifest::DEFAULT_CHUNK_SIZE,
            )
            .unwrap();
            let actual = crate::transfer::chunker::manifest_from_path(
                &root.join("b-receive/source.bin"),
                expected.chunk_size,
            )
            .unwrap();
            assert_eq!(actual, expected);
            for role in ["a", "b"] {
                let (store, _) =
                    TaskStore::open(&root.join(format!("{role}-state/tasks.json"))).unwrap();
                assert_eq!(store.list().len(), 1);
                assert_eq!(store.task(&id).unwrap().state(), TaskState::Completed);
            }
            eprintln!(
                "process hard-kill {killed}: resume from {durable} durable chunks; 70 MiB manifest and both receipts verified"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn lost_completed_frame_replays_receipt_without_republishing() {
        let pair = Pair::new().await;
        let (id, bytes) = pair.select(256 * 1024).await;
        pair.b
            .drop_completion
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(
            pair.a
                .send_file(&pair.ca, pair.ib, id.clone())
                .await
                .is_err()
        );
        wait_state(&pair.a, &id, TaskState::Interrupted).await;
        wait_state(&pair.b, &id, TaskState::Completed).await;
        let before = pair.b.task(id.clone()).await.unwrap().updated_at_unix_ms();
        pair.a
            .send_file(&pair.ca, pair.ib, id.clone())
            .await
            .unwrap();
        wait_state(&pair.a, &id, TaskState::Completed).await;
        assert_eq!(pair.b.task(id).await.unwrap().updated_at_unix_ms(), before);
        assert_eq!(
            fs::read(pair.root.join("b-receive/文件.bin")).unwrap(),
            bytes
        );
        assert_eq!(
            fs::read_dir(pair.root.join("b-receive"))
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().unwrap().is_file())
                .count(),
            1
        );
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn pause_timeout_retains_download_and_marks_interrupted() {
        let pair = Pair::new().await;
        let (id, _) = pair.select(4 * 1024 * 1024).await;
        let (reached, release) = pair.gate();
        let sender = pair.sender(id.clone());
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .unwrap()
            .unwrap();
        pair.a.pause(&id).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(8), sender)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("暂停确认超时"));
        release.send(()).unwrap();
        wait_state(&pair.a, &id, TaskState::Interrupted).await;
        wait_state(&pair.b, &id, TaskState::Interrupted).await;
        let record = pair.b.task(id).await.unwrap();
        let download = disk::open_download(&record).unwrap();
        assert!(download.bitmap().count_set() > 0);
        assert!(download.temp_path().exists());
        drop(download);
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn reading_snapshots_does_not_emit_progress_events() {
        let pair = Pair::new().await;
        let mut changed = pair.a.subscribe();
        pair.a.snapshot().await.unwrap();
        assert!(!changed.has_changed().unwrap());
        changed.borrow_and_update();
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn publication_failure_never_completes_and_receiver_can_retry_after_conflict_removed() {
        let pair = Pair::new().await;
        let (id, bytes) = pair.select(300 * 1024).await;
        let target = pair.root.join("b-receive/文件.bin");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("previous.bin"), b"previous user data").unwrap();
        assert!(
            pair.a
                .send_file(&pair.ca, pair.ib, id.clone())
                .await
                .is_err()
        );
        wait_state(&pair.b, &id, TaskState::Failed).await;
        for service in [&pair.a, &pair.b] {
            let record = service.task(id.clone()).await.unwrap();
            assert_eq!(record.state(), TaskState::Failed);
            assert!(!record.file_details().unwrap().receipt_committed);
        }
        assert_eq!(
            fs::read(target.join("previous.bin")).unwrap(),
            b"previous user data"
        );
        fs::remove_dir_all(&target).unwrap();
        pair.b.resume(&pair.cb, pair.ia, id.clone()).await.unwrap();
        wait_state(&pair.a, &id, TaskState::Completed).await;
        wait_state(&pair.b, &id, TaskState::Completed).await;
        assert_eq!(fs::read(&target).unwrap(), bytes);
        pair.shutdown().await;
    }
    #[test]
    fn queued_old_epoch_store_write_cannot_reactivate_an_interrupted_task() {
        let root =
            std::env::temp_dir().join(format!("p2p-transfer-epoch-{}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("receive")).unwrap();
        let (mut store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        let path = root.join("source.bin");
        fs::write(&path, b"source").unwrap();
        let id = disk::select_file(&mut store, Identity::generate().node_id(), path)
            .unwrap()
            .task_id()
            .clone();
        let service = TransferService::new(store, root.join("receive"));
        tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).enable_all().build().unwrap().block_on(async {
            let (release,held)=std::sync::mpsc::channel();let (started,ready)=tokio::sync::oneshot::channel();
            let blocker=tokio::task::spawn_blocking(move||{started.send(()).unwrap();held.recv().unwrap();});ready.await.unwrap();
            let mut old=Box::pin(service.state(&id,TaskState::Connecting));
            tokio::select! {biased; result=&mut old=>panic!("worker should be queued: {result:?}"), _=std::future::ready(())=>{}}
            let mut interrupt=Box::pin(service.interrupt_all());
            tokio::select! {biased; result=&mut interrupt=>panic!("interrupt worker should be queued: {result:?}"), _=std::future::ready(())=>{}}
            release.send(()).unwrap();blocker.await.unwrap();assert!(old.await.unwrap_err().to_string().contains("旧传输会话"));interrupt.await.unwrap();assert_eq!(service.task(id.clone()).await.unwrap().state(),TaskState::Interrupted);
        });
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn receiver_continue_reports_previously_detected_source_change() {
        let pair = Pair::new().await;
        let (id, _) = pair.select(4 * 1024 * 1024).await;
        let (reached, release) = pair.gate();
        let sender = pair.sender(id.clone());
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .unwrap()
            .unwrap();
        pair.a.pause(&id).unwrap();
        release.send(()).unwrap();
        sender.await.unwrap().unwrap();
        wait_state(&pair.b, &id, TaskState::Paused).await;
        fs::write(pair.root.join("文件.bin"), b"different source").unwrap();
        let error = pair
            .a
            .resume(&pair.ca, pair.ib, id.clone())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("变化"));
        wait_state(&pair.a, &id, TaskState::Failed).await;
        let error = pair
            .b
            .resume(&pair.cb, pair.ia, id.clone())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("源文件内容已变化"),
            "unexpected receiver diagnostic: {error}"
        );
        let record = pair.b.task(id).await.unwrap();
        assert_eq!(record.state(), TaskState::Failed);
        assert_eq!(
            record.diagnostic().unwrap().code(),
            TaskErrorCode::SourceChanged
        );
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn authenticated_directory_preserves_structure_empty_entries_and_collision_backups() {
        let pair = Pair::new().await;
        let source = pair.root.join("目录");
        fs::create_dir_all(source.join("nested/空目录")).unwrap();
        fs::write(source.join("nested/空文件.txt"), []).unwrap();
        fs::write(source.join("中文.txt"), b"new selected content").unwrap();
        fs::create_dir(pair.root.join("b-receive/目录")).unwrap();
        fs::write(pair.root.join("b-receive/目录/中文.txt"), b"old content").unwrap();
        let ids = pair.a.select_directory(pair.ib, source).await.unwrap();
        assert_eq!(ids.len(), 5);
        pair.a
            .send_selection(&pair.ca, pair.ib, ids.clone())
            .await
            .unwrap();
        for id in &ids {
            wait_state(&pair.a, id, TaskState::Completed).await;
            wait_state(&pair.b, id, TaskState::Completed).await;
        }
        assert!(pair.root.join("b-receive/目录/nested/空目录").is_dir());
        assert_eq!(
            fs::read(pair.root.join("b-receive/目录/nested/空文件.txt")).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            fs::read(pair.root.join("b-receive/目录/中文.txt")).unwrap(),
            b"new selected content"
        );
        let backups = fs::read_dir(pair.root.join("b-receive/目录"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("中文+")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(&backups[0]).unwrap(), b"old content");
        let records = pair.b.snapshot().await.unwrap();
        assert!(
            records
                .iter()
                .all(|r| r.group_id() == records[0].group_id())
        );
        // Completed task replay does not create another backup or another record.
        pair.a.send_selection(&pair.ca, pair.ib, ids).await.unwrap();
        assert_eq!(pair.b.snapshot().await.unwrap().len(), 5);
        assert_eq!(
            fs::read_dir(pair.root.join("b-receive/目录"))
                .unwrap()
                .filter(|e| e
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("中文+"))
                .count(),
            1
        );
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn rejected_directory_scan_leaves_no_partial_persistent_group() {
        let pair = Pair::new().await;
        let source = pair.root.join("invalid");
        fs::create_dir(&source).unwrap();
        // Windows treats CON.txt as a device rather than creating a file.
        // This real directory entry is illegal to the portable protocol on all OSes.
        fs::create_dir(source.join(".p2p-desktop")).unwrap();
        assert!(pair.a.select_directory(pair.ib, source).await.is_err());
        assert!(pair.a.snapshot().await.unwrap().is_empty());
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn directory_group_keeps_original_receive_root_after_settings_change() {
        let pair = Pair::new().await;
        let source = pair.root.join("selected-dir");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file.txt"), b"bound to original root").unwrap();
        let ids = pair.a.select_directory(pair.ib, source).await.unwrap();
        assert_eq!(ids.len(), 2);
        pair.a
            .send_file(&pair.ca, pair.ib, ids[0].clone())
            .await
            .unwrap();
        let changed_root = pair.root.join("changed-root");
        fs::create_dir(&changed_root).unwrap();
        pair.b.set_receive_root(changed_root.clone());
        pair.a
            .send_file(&pair.ca, pair.ib, ids[1].clone())
            .await
            .unwrap();
        assert_eq!(
            fs::read(pair.root.join("b-receive/selected-dir/file.txt")).unwrap(),
            b"bound to original root"
        );
        assert_eq!(fs::read_dir(changed_root).unwrap().count(), 0);
        for record in pair.b.snapshot().await.unwrap() {
            assert_eq!(record.local_path(), pair.root.join("b-receive"));
        }
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn reserved_but_unstarted_pause_cancels_nonce_and_preserves_manual_retry() {
        let pair = Pair::new().await;
        let (id, _) = pair.select(64 * 1024).await;
        pair.a
            .enqueue_tasks(pair.ib, vec![id.clone()])
            .await
            .unwrap();
        assert!(pair.a.dispatch_ready(&HashMap::new()).is_empty());
        assert_eq!(pair.a.queue_metrics().pending, 1);
        let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
        let old = pair.a.dispatch_ready(&connections).pop().unwrap();
        assert_eq!(pair.a.queue_metrics().active_files, 1);
        pair.a.pause_task(id.clone()).await.unwrap();
        assert_eq!(
            pair.a.task(id.clone()).await.unwrap().state(),
            TaskState::Paused
        );
        assert_eq!(pair.a.queue_metrics().active_files, 0);
        // A new attempt may be reserved before the old future even starts.
        pair.a
            .enqueue_tasks(pair.ib, vec![id.clone()])
            .await
            .unwrap();
        let retry = pair.a.dispatch_ready(&connections).pop().unwrap();
        assert!(pair.a.execute_queued(old, pair.ca.clone()).await.is_err());
        assert_eq!(pair.a.queue_metrics().active_files, 1);
        pair.a.execute_queued(retry, pair.ca.clone()).await.unwrap();
        assert_eq!(
            pair.a.task(id.clone()).await.unwrap().state(),
            TaskState::Completed
        );
        assert_eq!(pair.b.task(id).await.unwrap().state(), TaskState::Completed);
        pair.shutdown().await;
    }

    #[tokio::test]
    async fn real_queue_runs_one_two_three_files_on_the_same_authenticated_peer() {
        for limit in 1..=3 {
            let pair = Pair::new().await;
            pair.a.set_send_limit(limit).unwrap();
            let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
            let mut ids = Vec::new();
            for index in 0..4 {
                let path = pair.root.join(format!("queued-{index}.bin"));
                fs::write(&path, vec![index as u8; 96 * 1024]).unwrap();
                ids.push(pair.a.select_file(pair.ib, path).await.unwrap());
            }
            pair.a.enqueue_tasks(pair.ib, ids.clone()).await.unwrap();
            let first = pair.a.dispatch_ready(&connections);
            assert_eq!(first.len(), limit as usize);
            assert_eq!(pair.a.queue_metrics().pending, 4 - limit as usize);
            let mut running = JoinSet::new();
            for scheduled in first {
                let service = pair.a.clone();
                let connection = pair.ca.clone();
                running.spawn(async move { service.execute_queued(scheduled, connection).await });
            }
            while let Some(result) = running.join_next().await {
                result.unwrap().unwrap();
                for scheduled in pair.a.dispatch_ready(&connections) {
                    let service = pair.a.clone();
                    let connection = pair.ca.clone();
                    running
                        .spawn(async move { service.execute_queued(scheduled, connection).await });
                }
                assert!(pair.a.queue_metrics().active_files <= limit as usize);
            }
            for id in ids {
                assert!(pair.a.task(id.clone()).await.unwrap().receipt_committed());
                assert!(pair.b.task(id).await.unwrap().receipt_committed());
            }
            assert_eq!(pair.a.queue_metrics().pending, 0);
            assert_eq!(pair.a.queue_metrics().active_files, 0);
            assert!(pair.a.set_send_limit(0).is_err());
            assert!(pair.a.set_send_limit(4).is_err());
            pair.shutdown().await;
        }
    }

    #[tokio::test]
    async fn independent_receive_cap_reports_busy_before_creating_a_task_and_is_retryable() {
        let pair = Pair::new().await;
        let mut receive_guards = Vec::new();
        for _ in 0..3 {
            receive_guards.push(
                pair.b
                    .claim(
                        pair.ia,
                        &TaskId::generate(),
                        TaskDirection::Receive,
                        false,
                        None,
                    )
                    .unwrap(),
            );
        }
        // Receiving directory metadata has its own budget, as does sending.
        let metadata = pair
            .b
            .claim(
                pair.ia,
                &TaskId::generate(),
                TaskDirection::Receive,
                true,
                None,
            )
            .unwrap();
        assert!(
            pair.b
                .claim(
                    pair.ia,
                    &TaskId::generate(),
                    TaskDirection::Receive,
                    false,
                    None
                )
                .is_err()
        );
        let (id, bytes) = pair.select(64 * 1024).await;
        pair.a
            .enqueue_tasks(pair.ib, vec![id.clone()])
            .await
            .unwrap();
        let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
        let scheduled = pair.a.dispatch_ready(&connections).pop().unwrap();
        assert!(
            pair.a
                .execute_queued(scheduled, pair.ca.clone())
                .await
                .is_err()
        );
        let rejected = pair.a.task(id.clone()).await.unwrap();
        assert_eq!(rejected.state(), TaskState::Failed);
        assert_eq!(
            rejected.diagnostic().unwrap().code(),
            TaskErrorCode::PeerBusy
        );
        assert!(can_continue(&rejected));
        assert!(pair.b.snapshot().await.unwrap().is_empty());
        assert!(!pair.root.join("b-receive/文件.bin").exists());
        receive_guards.pop();
        drop(metadata);
        pair.a
            .enqueue_tasks(pair.ib, vec![id.clone()])
            .await
            .unwrap();
        let scheduled = pair.a.dispatch_ready(&connections).pop().unwrap();
        pair.a
            .execute_queued(scheduled, pair.ca.clone())
            .await
            .unwrap();
        assert_eq!(
            fs::read(pair.root.join("b-receive/文件.bin")).unwrap(),
            bytes
        );
        drop(receive_guards);
        pair.shutdown().await;
    }

    #[tokio::test]
    async fn queued_pause_and_invalid_batch_leave_no_unowned_or_rebound_task() {
        let pair = Pair::new().await;
        let (id, _) = pair.select(1024).await;
        pair.a
            .enqueue_tasks(pair.ib, vec![id.clone()])
            .await
            .unwrap();
        pair.a.pause_task(id.clone()).await.unwrap();
        assert_eq!(pair.a.queue_metrics().pending, 0);
        assert_eq!(
            pair.a.task(id.clone()).await.unwrap().state(),
            TaskState::Paused
        );
        assert!(
            pair.a
                .enqueue_tasks(pair.ib, vec![id.clone(), TaskId::generate()])
                .await
                .is_err()
        );
        assert_eq!(
            pair.a.task(id.clone()).await.unwrap().state(),
            TaskState::Paused
        );
        assert!(
            pair.a
                .enqueue_tasks(pair.ia, vec![id.clone()])
                .await
                .is_err()
        );
        let view = pair.a.presentation().await.unwrap();
        assert_eq!(view.bytes_per_second[&id], 0.0);
        assert_eq!(view.queue.pending, 0);
        pair.shutdown().await;
    }

    #[tokio::test]
    async fn directory_group_counts_partial_failure_without_claiming_complete() {
        let pair = Pair::new().await;
        let source = pair.root.join("group");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("good.bin"), vec![7; 3000]).unwrap();
        fs::write(source.join("missing.bin"), vec![8; 4000]).unwrap();
        let ids = pair
            .a
            .select_directory(pair.ib, source.clone())
            .await
            .unwrap();
        let group = pair
            .a
            .task(ids[0].clone())
            .await
            .unwrap()
            .group_id()
            .unwrap()
            .clone();
        fs::remove_file(source.join("missing.bin")).unwrap();
        pair.a.enqueue_tasks(pair.ib, ids).await.unwrap();
        let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
        let mut failures = 0;
        loop {
            let scheduled = pair.a.dispatch_ready(&connections);
            if scheduled.is_empty() {
                break;
            }
            for scheduled in scheduled {
                failures += usize::from(
                    pair.a
                        .execute_queued(scheduled, pair.ca.clone())
                        .await
                        .is_err(),
                );
            }
        }
        assert_eq!(failures, 1);
        let view = pair.a.presentation().await.unwrap();
        let aggregate = &view.groups[&group];
        assert_eq!(aggregate.children, 3);
        assert_eq!(aggregate.completed, 2);
        assert_eq!(aggregate.failed, 1);
        assert_eq!(aggregate.total_bytes, 7000);
        assert_eq!(aggregate.confirmed_bytes, 3000);
        assert!(!aggregate.complete);
        assert_eq!(
            fs::read(pair.root.join("b-receive/group/good.bin")).unwrap(),
            vec![7; 3000]
        );
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn blocked_file_does_not_stop_ready_file_and_pause_releases_pending_slot() {
        let pair = Pair::new().await;
        pair.a.set_send_limit(2).unwrap();
        let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
        let (slow, _) = pair.select(4 * 1024 * 1024).await;
        let mut others = Vec::new();
        for index in 0..2 {
            let path = pair.root.join(format!("independent-{index}.bin"));
            fs::write(&path, vec![index as u8; 96 * 1024]).unwrap();
            others.push(pair.a.select_file(pair.ib, path).await.unwrap());
        }
        pair.a
            .enqueue_tasks(
                pair.ib,
                vec![slow.clone(), others[0].clone(), others[1].clone()],
            )
            .await
            .unwrap();
        let (reached, release) = pair.gate();
        // Start only the first selected executor, so the injected disk gate
        // deterministically belongs to it rather than a second racing stream.
        let mut selected = pair.a.dispatch_ready(&connections);
        let first = selected.remove(0);
        let service = pair.a.clone();
        let conn = pair.ca.clone();
        let blocked = tokio::spawn(async move { service.execute_queued(first, conn).await });
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .unwrap()
            .unwrap();
        pair.a
            .execute_queued(selected.pop().unwrap(), pair.ca.clone())
            .await
            .unwrap();
        assert_eq!(
            pair.a.task(others[0].clone()).await.unwrap().state(),
            TaskState::Completed
        );
        assert!(!blocked.is_finished());
        pair.a.pause_task(slow.clone()).await.unwrap();
        release.send(()).unwrap();
        blocked.await.unwrap().unwrap();
        assert_eq!(
            pair.a.task(slow.clone()).await.unwrap().state(),
            TaskState::Paused
        );
        assert_eq!(pair.a.queue_metrics().active_files, 0);
        let pending = pair.a.dispatch_ready(&connections).pop().unwrap();
        assert_eq!(pending.entry.id, others[1]);
        pair.a
            .execute_queued(pending, pair.ca.clone())
            .await
            .unwrap();
        let presentation = pair.a.presentation().await.unwrap();
        assert_eq!(presentation.bytes_per_second[&slow], 0.0);
        assert_eq!(pair.a.task(slow).await.unwrap().state(), TaskState::Paused);
        pair.shutdown().await;
    }

    #[tokio::test]
    async fn bounded_event_overflow_is_repaired_by_authoritative_lifecycle_snapshot() {
        let pair = Pair::new().await;
        let path = pair.root.join("snapshot.bin");
        fs::write(&path, b"snapshot").unwrap();
        let peer = pair.ib;
        let ids = pair
            .a
            .store(move |store| {
                let records = (0..140)
                    .map(|_| {
                        disk::scan_selected_file(
                            peer,
                            path.clone(),
                            &super::super::files::ScanCancellation::default(),
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                let ids = store.create_selection(records).map_err(disk::local_error)?;
                for id in &ids {
                    disk::transition(store, id, TaskState::Queued)?;
                }
                Ok(ids)
            })
            .await
            .unwrap();
        pair.a.interrupt_all().await.unwrap();
        let view = pair.a.presentation().await.unwrap();
        assert!(view.resync_required);
        assert_eq!(view.events.len(), 256);
        assert_eq!(view.tasks.len(), ids.len());
        assert!(
            view.tasks
                .iter()
                .all(|task| task.state() == TaskState::Interrupted)
        );
        assert_eq!(view.queue.pending, 0);
        let next = pair.a.presentation().await.unwrap();
        assert!(!next.resync_required);
        assert!(next.events.is_empty());
        assert_eq!(next.tasks.len(), ids.len());
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn pause_after_durable_queued_before_worker_return_cannot_be_lost() {
        let pair = Pair::new().await;
        let (id, _) = pair.select(1024).await;
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel();
        *pair.a.admission_gate.lock().unwrap() = Some((reached_tx, release_rx));
        let service = pair.a.clone();
        let task = id.clone();
        let peer = pair.ib;
        let worker = tokio::spawn(async move { service.enqueue_tasks(peer, vec![task]).await });
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pair.a.task(id.clone()).await.unwrap().state(),
            TaskState::Queued
        );
        let pause = pair.a.pause_task(id.clone()).await;
        release.send(()).unwrap();
        let admission = worker.await.unwrap();
        let record = pair.a.task(id).await.unwrap();
        let metrics = pair.a.queue_metrics();
        pair.shutdown().await;
        assert!(pause.is_ok(), "visible Queued task lost pause: {pause:?}");
        admission.unwrap();
        assert_eq!(record.state(), TaskState::Paused);
        assert_eq!(metrics.pending, 0);
        assert_eq!(metrics.active_files, 0);
    }
    #[tokio::test]
    async fn fresh_file_and_directory_selection_are_pauseable_before_worker_returns() {
        for directory in [false, true] {
            let pair = Pair::new().await;
            let source = pair.root.join(if directory {
                "selected-dir"
            } else {
                "selected.bin"
            });
            if directory {
                fs::create_dir(&source).unwrap();
                fs::create_dir(source.join("empty")).unwrap();
                fs::write(source.join("child.bin"), b"child").unwrap();
            } else {
                fs::write(&source, b"file").unwrap();
            }
            let (reached_tx, reached) = tokio::sync::oneshot::channel();
            let (release, release_rx) = tokio::sync::oneshot::channel();
            *pair.a.admission_gate.lock().unwrap() = Some((reached_tx, release_rx));
            let service = pair.a.clone();
            let peer = pair.ib;
            let worker = tokio::spawn(async move {
                if directory {
                    service.select_directory(peer, source).await
                } else {
                    service.select_file(peer, source).await.map(|id| vec![id])
                }
            });
            tokio::time::timeout(Duration::from_secs(10), reached)
                .await
                .unwrap()
                .unwrap();
            let records = pair.a.snapshot().await.unwrap();
            assert_eq!(records.len(), if directory { 3 } else { 1 });
            assert_eq!(pair.a.queue_metrics().pending, records.len());
            for record in &records {
                assert_eq!(record.state(), TaskState::Queued);
                pair.a.pause_task(record.task_id().clone()).await.unwrap();
            }
            release.send(()).unwrap();
            let ids = worker.await.unwrap().unwrap();
            assert_eq!(ids.len(), records.len());
            for id in ids {
                assert_eq!(pair.a.task(id).await.unwrap().state(), TaskState::Paused);
            }
            assert_eq!(pair.a.queue_metrics().pending, 0);
            assert_eq!(pair.a.queue_metrics().active_files, 0);
            assert!(pair.b.snapshot().await.unwrap().is_empty());
            pair.shutdown().await;
        }
    }

    #[tokio::test]
    async fn full_queue_retains_new_selection_as_manually_retryable_interrupted_record() {
        let pair = Pair::new().await;
        // Model the full pending budget without doing 4096 unnecessary fsyncs.
        // The selected record and its subsequent QUIC retry are real.
        pair.a
            .sender_queue
            .lock()
            .unwrap()
            .enqueue(
                (0..super::super::queue::MAX_QUEUED)
                    .map(|_| super::super::queue::QueueEntry {
                        id: TaskId::generate(),
                        peer: pair.ib,
                        metadata: false,
                    })
                    .collect(),
            )
            .unwrap();
        let path = pair.root.join("capacity.bin");
        fs::write(&path, b"capacity").unwrap();
        assert!(pair.a.select_file(pair.ib, path).await.is_err());
        let records = pair.a.snapshot().await.unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.state(), TaskState::Interrupted);
        assert!(can_continue(record));
        assert_eq!(
            pair.a.queue_metrics().pending,
            super::super::queue::MAX_QUEUED
        );
        let id = record.task_id().clone();
        pair.a.sender_queue.lock().unwrap().clear();
        pair.a
            .enqueue_tasks(pair.ib, vec![id.clone()])
            .await
            .unwrap();
        let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
        let scheduled = pair.a.dispatch_ready(&connections).pop().unwrap();
        pair.a
            .execute_queued(scheduled, pair.ca.clone())
            .await
            .unwrap();
        assert!(pair.a.task(id.clone()).await.unwrap().receipt_committed());
        assert!(pair.b.task(id).await.unwrap().receipt_committed());
        assert_eq!(
            fs::read(pair.root.join("b-receive/capacity.bin")).unwrap(),
            b"capacity"
        );
        pair.shutdown().await;
    }
    #[test]
    fn cancelling_selection_while_its_commit_is_queued_cannot_create_a_ghost_task() {
        let root =
            std::env::temp_dir().join(format!("p2p-cancel-selection-{}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("receive")).unwrap();
        let source = root.join("source.bin");
        fs::write(&source, b"cancelled source").unwrap();
        let (store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        let service = TransferService::new(store, root.join("receive"));
        tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).enable_all().build().unwrap().block_on(async {
            let (release_first, held_first) = std::sync::mpsc::channel();
            let (started_first, ready_first) = tokio::sync::oneshot::channel();
            let first = tokio::task::spawn_blocking(move || {started_first.send(()).unwrap(); held_first.recv().unwrap();});
            ready_first.await.unwrap();
            let peer = Identity::generate().node_id();
            let mut selection = Box::pin(service.select_file(peer, source));
            tokio::select! {biased; result=&mut selection=>panic!("scan must be queued: {result:?}"), _=std::future::ready(())=>{}}
            // FIFO in the single blocking worker: scan first, then this barrier,
            // then the store commit submitted when we poll the completed scan.
            let (release_second, held_second) = std::sync::mpsc::channel();
            let (started_second, ready_second) = tokio::sync::oneshot::channel();
            let second = tokio::task::spawn_blocking(move || {started_second.send(()).unwrap(); held_second.recv().unwrap();});
            release_first.send(()).unwrap(); ready_second.await.unwrap();
            tokio::select! {biased; result=&mut selection=>panic!("commit must be queued: {result:?}"), _=std::future::ready(())=>{}}
            drop(selection);
            release_second.send(()).unwrap(); first.await.unwrap(); second.await.unwrap();
            tokio::task::spawn_blocking(|| {}).await.unwrap();
            assert!(service.snapshot().await.unwrap().is_empty(), "cancelled worker created a task after its future was dropped");
            assert_eq!(service.queue_metrics().pending, 0);
        });
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn continue_after_paused_receipt_waits_for_previous_owned_slot_cleanup() {
        tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).enable_all().build().unwrap().block_on(async {
            let pair = Pair::new().await;
            let (id, bytes) = pair.select(4 * 1024 * 1024).await;
            let (data_reached, data_release) = pair.gate();
            let (cleanup_reached_tx, cleanup_reached) = tokio::sync::oneshot::channel();
            let (cleanup_release, cleanup_release_rx) = tokio::sync::oneshot::channel();
            *pair.a.source_cleanup_gate.lock().unwrap() = Some((cleanup_reached_tx, cleanup_release_rx));
            let sender = pair.sender(id.clone());
            tokio::time::timeout(Duration::from_secs(10), data_reached).await.unwrap().unwrap();
            pair.a.pause_task(id.clone()).await.unwrap(); data_release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(10), cleanup_reached).await.unwrap().unwrap();
            assert_eq!(pair.a.task(id.clone()).await.unwrap().state(), TaskState::Paused);
            wait_state(&pair.b, &id, TaskState::Paused).await;
            assert_eq!(pair.a.queue_metrics().active_files, 1);
            let mut continuation = Box::pin(pair.a.enqueue_tasks(pair.ib, vec![id.clone()]));
            tokio::select! {biased; result=&mut continuation=>panic!("continuation must await old cleanup: {result:?}"), _=std::future::ready(())=>{}}
            // Single blocking worker ensures the first store/read job completes
            // before this barrier, without a timing/sleep assumption.
            tokio::task::spawn_blocking(|| {}).await.unwrap();
            tokio::select! {biased; result=&mut continuation=>panic!("continuation lost behind old active slot: {result:?}"), _=std::future::ready(())=>{}}
            cleanup_release.send(()).unwrap(); sender.await.unwrap().unwrap();
            continuation.await.unwrap();
            assert_eq!(pair.a.queue_metrics().pending, 1);
            assert_eq!(pair.a.queue_metrics().active_files, 0);
            let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
            let scheduled = pair.a.dispatch_ready(&connections).pop().unwrap();
            assert_eq!(scheduled.entry.id, id);
            pair.a.execute_queued(scheduled, pair.ca.clone()).await.unwrap();
            assert!(pair.a.task(id.clone()).await.unwrap().receipt_committed());
            assert!(pair.b.task(id).await.unwrap().receipt_committed());
            assert_eq!(fs::read(pair.root.join("b-receive/文件.bin")).unwrap(), bytes);
            pair.shutdown().await;
        });
    }
    #[tokio::test]
    async fn speed_uses_authenticated_connection_receiver_result_and_never_creates_file_tasks() {
        use super::super::{protocol::SpeedDirection, speed::SpeedStatus};
        let pair = Pair::new_inner(true).await;
        for direction in [SpeedDirection::Upload, SpeedDirection::Download] {
            let report = pair.a.start_speed(pair.ib, direction, 600).await.unwrap();
            assert_eq!(report.status, SpeedStatus::Completed);
            assert!(report.bytes > 0);
            assert!(report.elapsed > Duration::ZERO);
            let mut changed = pair.b.subscribe();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if pair.b.speed_snapshots().get(&pair.ia).is_some_and(|s| {
                        s.test_id == report.test_id && s.status == SpeedStatus::Completed
                    }) {
                        break;
                    }
                    changed.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
            let other = pair.b.speed_snapshots()[&pair.ia].clone();
            assert_eq!(other.test_id, report.test_id);
            assert_eq!(other.bytes, report.bytes);
            assert_eq!(other.elapsed, report.elapsed);
            assert_eq!(other.status, SpeedStatus::Completed);
            assert!(pair.a.snapshot().await.unwrap().is_empty());
            assert!(pair.b.snapshot().await.unwrap().is_empty());
            assert_eq!(
                fs::read_dir(pair.root.join("a-receive")).unwrap().count(),
                0
            );
            assert_eq!(
                fs::read_dir(pair.root.join("b-receive")).unwrap().count(),
                0
            );
        }
        assert!(
            pair.a
                .start_speed(pair.ib, SpeedDirection::Upload, 3000)
                .await
                .is_err()
        );
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn speed_simultaneous_requests_have_one_grant_and_one_busy() {
        use super::super::protocol::SpeedDirection;
        let pair = Pair::new_inner(true).await;
        let (a, b) = tokio::join!(
            pair.a.start_speed(pair.ib, SpeedDirection::Upload, 30),
            pair.b.start_speed(pair.ia, SpeedDirection::Download, 30)
        );
        assert_eq!(
            usize::from(a.is_ok()) + usize::from(b.is_ok()),
            1,
            "a={a:?} b={b:?}"
        );
        let error = a.err().or_else(|| b.err()).unwrap().to_string();
        assert!(error.contains("进行"), "{error}");
        assert!(pair.ca.close_reason().is_none());
        assert!(pair.cb.close_reason().is_none());
        pair.a
            .start_speed(pair.ib, SpeedDirection::Download, 60)
            .await
            .unwrap();
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn speed_and_file_activity_exclude_each_other_without_silent_pause() {
        use super::super::protocol::SpeedDirection;
        let pair = Pair::new_inner(true).await;
        let (id, _) = pair.select(1024).await;
        let connections = HashMap::from([(pair.ib, pair.ca.clone())]);
        let scheduled = pair.a.dispatch_ready(&connections).pop().unwrap();
        assert!(
            pair.a
                .start_speed(pair.ib, SpeedDirection::Upload, 30)
                .await
                .is_err()
        );
        assert_eq!(
            pair.a.task(id.clone()).await.unwrap().state(),
            TaskState::Queued
        );
        assert_eq!(pair.a.queue_metrics().active_files, 1);
        pair.a.pause_task(id.clone()).await.unwrap();
        drop(scheduled);
        pair.a.speed_peers.lock().unwrap()[&pair.ib].set_test_duration(Duration::from_secs(2));
        let service = pair.a.clone();
        let peer = pair.ib;
        let job =
            tokio::spawn(
                async move { service.start_speed(peer, SpeedDirection::Upload, 30).await },
            );
        let mut changes = pair.a.subscribe();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if pair.a.activity.lock().speed_active(pair.ib)
                    && pair.b.activity.lock().speed_active(pair.ia)
                {
                    break;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let count = pair.a.snapshot().await.unwrap().len();
        let source = pair.root.join("reject.bin");
        fs::write(&source, b"reject").unwrap();
        assert!(pair.a.select_file(pair.ib, source).await.is_err());
        assert_eq!(pair.a.snapshot().await.unwrap().len(), count);
        assert!(pair.a.dispatch_ready(&connections).is_empty());
        assert_eq!(pair.a.task(id).await.unwrap().state(), TaskState::Paused);
        let test = pair.a.speed_snapshots()[&pair.ib].test_id.clone();
        pair.a.cancel_speed(pair.ib, &test).unwrap();
        assert!(job.await.unwrap().is_err());
        tokio::time::timeout(Duration::from_secs(5), async {
            while pair.b.activity.lock().speed_active(pair.ia) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(pair.ca.close_reason().is_none());
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn speed_cancel_and_stale_uni_token_do_not_pollute_next_test_or_file_transfer() {
        use super::super::{
            protocol::{SpeedControl, SpeedDirection},
            speed::SpeedStatus,
        };
        for (direction, remote_cancel) in [
            (SpeedDirection::Upload, false),
            (SpeedDirection::Download, true),
        ] {
            let pair = Pair::new_inner(true).await;
            pair.a.speed_peers.lock().unwrap()[&pair.ib].set_test_duration(Duration::from_secs(2));
            pair.b.speed_peers.lock().unwrap()[&pair.ia].set_test_duration(Duration::from_secs(2));
            let service = pair.a.clone();
            let peer = pair.ib;
            let job = tokio::spawn(async move { service.start_speed(peer, direction, 600).await });
            let mut changes = pair.a.subscribe();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if pair
                        .a
                        .speed_snapshots()
                        .get(&pair.ib)
                        .is_some_and(|s| s.bytes > 0)
                    {
                        break;
                    }
                    changes.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
            let old = pair.a.speed_peers.lock().unwrap()[&pair.ib]
                .test_lease()
                .unwrap();
            if remote_cancel {
                pair.b.cancel_speed(pair.ia, &old.test_id).unwrap();
            } else {
                pair.a.cancel_speed(pair.ib, &old.test_id).unwrap();
            }
            assert!(
                job.await
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("已取消")
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if !pair.a.activity.lock().speed_active(pair.ib)
                        && !pair.b.activity.lock().speed_active(pair.ia)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                pair.a.speed_snapshots()[&pair.ib].status,
                SpeedStatus::Cancelled
            );
            assert_eq!(pair.a.speed_snapshots()[&pair.ib].bytes_per_second, 0.0);
            pair.a.speed_peers.lock().unwrap()[&pair.ib]
                .set_test_duration(Duration::from_millis(200));
            pair.b.speed_peers.lock().unwrap()[&pair.ia]
                .set_test_duration(Duration::from_millis(200));
            let service = pair.a.clone();
            let peer = pair.ib;
            let next =
                tokio::spawn(
                    async move { service.start_speed(peer, SpeedDirection::Upload, 30).await },
                );
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if pair.b.speed_snapshots().get(&pair.ia).is_some_and(|s| {
                        s.test_id != old.test_id && s.status == SpeedStatus::Running
                    }) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let mut stale = pair.ca.open_uni().await.unwrap();
            protocol::write(
                &mut stale,
                &Frame {
                    request_id: 1,
                    message: Message::Speed(SpeedControl::Granted(old.clone())),
                },
            )
            .await
            .unwrap();
            let _ = stale.write_all(b"old payload must not be consumed").await;
            let _ = stale.finish();
            let report = next.await.unwrap().unwrap();
            assert_ne!(report.test_id, old.test_id);
            assert_eq!(report.status, SpeedStatus::Completed);
            assert!(pair.ca.close_reason().is_none());
            assert!(pair.cb.close_reason().is_none());
            tokio::time::timeout(Duration::from_secs(5), async {
                while pair.b.activity.lock().speed_active(pair.ia) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let (id, bytes) = pair.select(4096).await;
            pair.a
                .send_file(&pair.ca, pair.ib, id.clone())
                .await
                .unwrap();
            assert!(pair.a.task(id.clone()).await.unwrap().receipt_committed());
            assert!(pair.b.task(id).await.unwrap().receipt_committed());
            assert_eq!(
                fs::read(pair.root.join("b-receive/文件.bin")).unwrap(),
                bytes
            );
            pair.shutdown().await;
        }
    }
    #[tokio::test]
    async fn speed_remote_busy_and_invalid_uni_headers_preserve_connection_and_next_lease() {
        use super::super::protocol::{SpeedControl, SpeedDirection};
        let pair = Pair::new_inner(true).await;
        let peer_file = pair.b.activity.file(pair.ia).unwrap();
        let error = pair
            .a
            .start_speed(pair.ib, SpeedDirection::Upload, 30)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("进行"), "{error}");
        drop(peer_file);
        tokio::time::timeout(Duration::from_secs(5), async {
            while pair.a.activity.lock().speed_active(pair.ib) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        pair.a.speed_peers.lock().unwrap()[&pair.ib].set_test_duration(Duration::from_millis(300));
        pair.b.speed_peers.lock().unwrap()[&pair.ia].set_test_duration(Duration::from_millis(300));
        let (data_reached, data_release) = pair.a.speed_peers.lock().unwrap()[&pair.ib].gate_data();
        let service = pair.a.clone();
        let peer = pair.ib;
        let job =
            tokio::spawn(
                async move { service.start_speed(peer, SpeedDirection::Upload, 60).await },
            );
        tokio::time::timeout(Duration::from_secs(5), async {
            while pair.b.speed_peers.lock().unwrap()[&pair.ia]
                .test_lease()
                .is_none()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), data_reached)
            .await
            .unwrap()
            .unwrap();
        let mut forged = pair.b.speed_peers.lock().unwrap()[&pair.ia]
            .test_lease()
            .unwrap();
        forged.stream_token[0] ^= 1;
        let mut bad = pair.ca.open_uni().await.unwrap();
        protocol::write(
            &mut bad,
            &Frame {
                request_id: 1,
                message: Message::Speed(SpeedControl::Granted(forged)),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), bad.stopped())
                .await
                .unwrap()
                .unwrap(),
            Some(5u32.into())
        );
        let mut oversized = pair.ca.open_uni().await.unwrap();
        oversized.write_all(&4097u32.to_le_bytes()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), oversized.stopped())
                .await
                .unwrap()
                .unwrap(),
            Some(5u32.into())
        );
        data_release.send(()).unwrap();
        job.await.unwrap().unwrap();
        assert!(pair.ca.close_reason().is_none());
        tokio::time::timeout(Duration::from_secs(5), async {
            while pair.b.activity.lock().speed_active(pair.ia) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        pair.a
            .start_speed(pair.ib, SpeedDirection::Download, 30)
            .await
            .unwrap();
        assert!(pair.a.snapshot().await.unwrap().is_empty());
        assert!(pair.b.snapshot().await.unwrap().is_empty());
        pair.shutdown().await;
    }
    #[tokio::test]
    async fn next_speed_request_waits_for_completed_peer_lease_cleanup() {
        use super::super::protocol::SpeedDirection;
        let pair = Pair::new_inner(true).await;
        let (cleanup_reached, cleanup_release) =
            pair.b.speed_peers.lock().unwrap()[&pair.ia].gate_cleanup();
        let first = pair
            .a
            .start_speed(pair.ib, SpeedDirection::Upload, 30)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), cleanup_reached)
            .await
            .unwrap()
            .unwrap();
        assert!(pair.b.activity.lock().speed_active(pair.ia));
        let waiting = pair.b.speed_peers.lock().unwrap()[&pair.ia].gate_wait();
        let service = pair.a.clone();
        let peer = pair.ib;
        let mut next = tokio::spawn(async move {
            service
                .start_speed(peer, SpeedDirection::Download, 60)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result=&mut next=>panic!("new request lost behind completed old lease: {result:?}"),
                reached=waiting=>reached.unwrap(),
            }
        })
        .await
        .unwrap();
        assert!(!next.is_finished());
        cleanup_release.send(()).unwrap();
        let second = next.await.unwrap().unwrap();
        assert_ne!(second.test_id, first.test_id);
        assert_eq!(second.direction, SpeedDirection::Download);
        pair.shutdown().await;
    }
}
