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
const MAX_ACTIVE: usize = 3;

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
    #[cfg(test)]
    drop_completion: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    first_chunk_gate: TestGate,
    #[cfg(test)]
    checkpoint_gate: TestGate,
}
struct Active {
    peer: NodeId,
    pause: watch::Sender<bool>,
}
struct ActiveGuard {
    service: TransferService,
    id: TaskId,
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.service.active.lock().unwrap().remove(&self.id);
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
            changed,
            epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            #[cfg(test)]
            drop_completion: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            first_chunk_gate: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            checkpoint_gate: Arc::new(Mutex::new(None)),
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
    pub async fn interrupt_all(&self) -> Result<()> {
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
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
        self.store(move |store| disk::select_file(store, peer, source).map(|r| r.task_id().clone()))
            .await
    }
    pub async fn task(&self, id: TaskId) -> Result<TaskRecord> {
        self.read_store(move |store| store.task(&id).map_err(disk::local_error))
            .await
    }
    async fn wait_previous_attempt(&self, id: &TaskId) -> Result<()> {
        let mut changed = self.subscribe();
        tokio::time::timeout(PAUSE_TIMEOUT, async {
            loop {
                if !self.active.lock().unwrap().contains_key(id) {
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
    fn claim(&self, peer: NodeId, id: &TaskId) -> Result<(ActiveGuard, watch::Receiver<bool>)> {
        let mut active = self.active.lock().unwrap();
        if active.len() >= MAX_ACTIVE
            || active.contains_key(id)
            || active.values().any(|a| a.peer == peer)
        {
            return Err(disk::failure("已有文件任务活动，请稍后继续"));
        }
        let (pause, rx) = watch::channel(false);
        active.insert(id.clone(), Active { peer, pause });
        Ok((
            ActiveGuard {
                service: self.clone(),
                id: id.clone(),
            },
            rx,
        ))
    }
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
    async fn progress(&self, id: &TaskId, bytes: u64) -> Result<()> {
        let id = id.clone();
        self.store(move |store| {
            store
                .set_progress_hint(
                    &id,
                    ProgressHint::new(bytes, system_time_unix_ms().map_err(disk::local_error)?),
                )
                .map_err(disk::local_error)
        })
        .await
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
    pub async fn send_file(&self, connection: &Connection, peer: NodeId, id: TaskId) -> Result<()> {
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
        if can_continue(&current) {
            self.wait_previous_attempt(&id).await?;
        }
        let (_guard, pause) = self.claim(peer, &id)?;
        let result = self.send_inner(connection, peer, &id, pause, None).await;
        if let Err(error) = &result {
            self.finish_error(&id, error).await;
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
        let source = record.clone();
        let file = blocking(move || disk::verify_source(&source)).await?;
        let details = record.file_details().unwrap();
        let (send, recv) = tokio::time::timeout(IDLE_TIMEOUT, connection.open_bi())
            .await
            .map_err(|_| disk::failure("文件流打开超时"))?
            .map_err(disk::local_error)?;
        let mut io = TaskIo::new(send, recv, peer, id.clone());
        io.send(Message::Offer {
            task_id: id.clone(),
            group_id: None,
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
    async fn sender_loop(
        &self,
        io: &mut TaskIo,
        id: &TaskId,
        manifest: &FileManifest,
        file: disk::VerifiedSource,
        mut pause: watch::Receiver<bool>,
    ) -> Result<()> {
        let file = Arc::new(Mutex::new(file));
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
            match frame.message {
                Message::Resume { have, .. } => {
                    let bitmap = ChunkBitmap::from_bytes(manifest.chunk_count(), &have)?;
                    acknowledged.extend(bitmap.present());
                    bytes = bytes_for(manifest, &acknowledged);
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
                    io.send(Message::Chunk {
                        task_id: id.clone(),
                        index,
                        data,
                    })
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
    /// Called only by the authenticated session owner, once per peer connection.
    pub async fn serve_peer(&self, connection: Connection, peer: NodeId) -> Result<()> {
        let mut streams = JoinSet::new();
        loop {
            tokio::select! {
                accepted=connection.accept_bi()=> {
                    let (mut send,mut recv)=match accepted { Ok(streams)=>streams, Err(_)=>break };
                    if streams.len()>=8 {let _=send.reset(4u32.into());let _=recv.stop(4u32.into());continue;}
                    let service=self.clone();let connection=connection.clone();
                    streams.spawn(async move {
                        let first=tokio::time::timeout(Duration::from_secs(5),protocol::read(&mut recv)).await.map_err(|_|disk::failure("文件流首帧超时"))??;
                        match &first.message {
                            Message::Offer{..} => service.receive_offer(send,recv,peer,first).await,
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
                                let (_guard,pause)=match service.claim(peer,&id) {
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
        while streams.join_next().await.is_some() {}
        Ok(())
    }
    pub async fn resume(&self, connection: &Connection, peer: NodeId, id: TaskId) -> Result<()> {
        let lookup = id.clone();
        let record = self
            .read_store(move |store| disk::bound_task(store, peer, &lookup))
            .await?;
        if record.direction() == TaskDirection::Send {
            return self.send_file(connection, peer, id).await;
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
        send: SendStream,
        recv: RecvStream,
        peer: NodeId,
        first: Frame,
    ) -> Result<()> {
        let Message::Offer {
            task_id,
            relative_path,
            entry: Entry::File(manifest),
            group_id: None,
        } = first.message.clone()
        else {
            return Err(disk::failure("本阶段仅接受单文件任务"));
        };
        let (_guard, pause) = self.claim(peer, &task_id)?;
        let mut io = TaskIo::new(send, recv, peer, task_id.clone());
        io.observe(&first)?;
        let root = self.receive_root.lock().unwrap().clone();
        let id = task_id.clone();
        let record = self
            .store(move |store| {
                disk::accept_offer(store, peer, &id, &root, relative_path, *manifest)
            })
            .await?;
        if record.file_details().unwrap().receipt_committed {
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
        _ => "对端传输中断",
    })
}

struct TaskIo {
    send: SendStream,
    incoming: mpsc::Receiver<Result<Frame>>,
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
    fn new(send: SendStream, mut recv: RecvStream, peer: NodeId, id: TaskId) -> Self {
        let (tx, incoming) = mpsc::channel(8);
        let reader = tokio::spawn(async move {
            loop {
                let frame = protocol::read(&mut recv).await;
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
    Frame(Frame),
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
        frame=io.incoming.recv()=> {let frame=frame.ok_or_else(||disk::failure("文件流已关闭"))??;io.observe(&frame)?;Ok(Input::Frame(frame))}
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
            tasks.spawn(async move { service.serve_peer(conn, ib).await });
            let service = b.clone();
            let conn = cb.clone();
            tasks.spawn(async move { service.serve_peer(conn, ia).await });
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
        fs::write(&target, b"previous user data").unwrap();
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
        assert_eq!(fs::read(&target).unwrap(), b"previous user data");
        fs::remove_file(&target).unwrap();
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
}
