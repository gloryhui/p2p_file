//! Long-lived desktop network session. One task owns signaling events; Quinn owns all UDP reads.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{self, Sleep};
use tracing::{debug, warn};

use crate::discovery::signal::{Candidate, CandidateKind, SignalMessage, SignalingClient};
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::nat::punch::{PunchConfig, PunchToken};
use crate::net::{DesktopNetwork, DesktopNetworkConfig, prepare_desktop_network};
use crate::transport::handshake::{handshake_initiator, handshake_responder};
use crate::transport::quic::{
    ACCEPT_FIRST_BI_STREAM_TIMEOUT, APPLICATION_HANDSHAKE_TIMEOUT, ChannelBinding,
    QUIC_HANDSHAKE_TIMEOUT, connect as quic_connect,
};

use super::network_state::{
    BeginPeerAttempt, MAX_PENDING_PEERS, NetworkLifecycle, PeerLifecycle, PeerRegistry,
    reconnect_delay, should_initiate_quic,
};

const COMMAND_CAPACITY: usize = 64;
const EVENT_CAPACITY: usize = 128;
const SESSION_INPUT_CAPACITY: usize = 64;
const MAX_CANDIDATES: usize = 16;
const PEER_PUNCH_CONFIG: PunchConfig = PunchConfig {
    interval: Duration::from_millis(200),
    attempts: 30,
};

fn is_current_signal_generation(current: u64, result_generation: u64) -> bool {
    current == result_generation
}

#[derive(Clone, Debug)]
pub struct DesktopSessionConfig {
    pub signal_server: String,
    pub network: DesktopNetworkConfig,
    pub(crate) transfer: Option<super::transfer::TransferService>,
}

impl DesktopSessionConfig {
    pub fn new(signal_server: impl Into<String>) -> Self {
        Self {
            signal_server: signal_server.into(),
            network: DesktopNetworkConfig::default(),
            transfer: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SessionEvent {
    Lifecycle(NetworkLifecycle),
    PeerState {
        peer: NodeId,
        generation: u64,
        state: PeerLifecycle,
    },
    SignalIdentityRegistered(NodeId),
    Diagnostic(String),
}

#[derive(Clone)]
pub struct DesktopSessionHandle {
    commands: mpsc::Sender<SessionCommand>,
    lifetime: Arc<SessionLifetime>,
}

struct SessionLifetime {
    stop: watch::Sender<bool>,
    done: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for SessionLifetime {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        // Bound application exit even if an OS operation fails to unwind.
        if self
            .done
            .get_mut()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .is_ok()
            && let Some(thread) = self.thread.get_mut().unwrap().take()
        {
            let _ = thread.join();
        }
    }
}

impl DesktopSessionHandle {
    pub fn connect_peer(&self, peer: NodeId) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::ConnectPeer(peer))
            .map_err(|error| format!("网络会话暂时无法接收连接请求：{error}"))
    }

    pub fn reconfigure_signal(&self, server: impl Into<String>) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::ReconfigureSignal(server.into()))
            .map_err(|error| format!("网络会话暂时无法接收配置变更：{error}"))
    }

    #[allow(dead_code)] // T010 product controls call this tested backend command.
    pub fn send_file(
        &self,
        peer: NodeId,
        source: std::path::PathBuf,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::SendFile { peer, source })
            .map_err(|_| "传输命令队列已满或会话已关闭".into())
    }
    #[allow(dead_code)] // T010 product controls call this tested backend command.
    pub fn pause_task(&self, id: super::task_model::TaskId) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::PauseTask(id))
            .map_err(|_| "传输命令队列已满或会话已关闭".into())
    }
    #[allow(dead_code)] // T010 product controls call this tested backend command.
    pub fn resume_task(
        &self,
        peer: NodeId,
        id: super::task_model::TaskId,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::ResumeTask { peer, id })
            .map_err(|_| "传输命令队列已满或会话已关闭".into())
    }

    #[allow(dead_code)] // T010 selection controls.
    pub fn send_directory(
        &self,
        peer: NodeId,
        source: std::path::PathBuf,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::SendDirectory { peer, source })
            .map_err(|_| "传输命令队列已满或会话已关闭".into())
    }
    #[allow(dead_code)] // T010 controls.
    pub fn start_speed(
        &self,
        peer: NodeId,
        direction: super::protocol::SpeedDirection,
        seconds: u16,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::StartSpeed {
                peer,
                direction,
                seconds,
            })
            .map_err(|_| "测速命令队列已满或会话已关闭".into())
    }
    #[allow(dead_code)] // T010 controls.
    pub fn cancel_speed(
        &self,
        peer: NodeId,
        id: super::task_model::TaskId,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::CancelSpeed { peer, id })
            .map_err(|_| "测速命令队列已满或会话已关闭".into())
    }
    pub fn is_running(&self) -> bool {
        !self.commands.is_closed()
    }

    pub fn shutdown(&self) {
        let _ = self.lifetime.stop.send(true);
    }
}

enum SessionCommand {
    StartSpeed {
        peer: NodeId,
        direction: super::protocol::SpeedDirection,
        seconds: u16,
    },
    CancelSpeed {
        peer: NodeId,
        id: super::task_model::TaskId,
    },
    #[allow(dead_code)] // T010 selection controls.
    SendDirectory {
        peer: NodeId,
        source: std::path::PathBuf,
    },
    #[allow(dead_code)] // T010 product controls.
    SendFile {
        peer: NodeId,
        source: std::path::PathBuf,
    },
    #[allow(dead_code)] // T010 product controls.
    PauseTask(super::task_model::TaskId),
    #[allow(dead_code)] // T010 product controls.
    ResumeTask {
        peer: NodeId,
        id: super::task_model::TaskId,
    },
    ConnectPeer(NodeId),
    ReconfigureSignal(String),
    #[cfg(test)]
    Inspect(oneshot::Sender<HashMap<NodeId, (u64, quinn::Connection)>>),
}

enum SessionInput {
    Incoming(Box<quinn::Incoming>),
    SignalConnected {
        generation: u64,
        result: Result<SignalingClient>,
    },
    PeerProgress {
        peer: NodeId,
        generation: u64,
        state: PeerLifecycle,
    },
    PeerConnected {
        peer: NodeId,
        generation: u64,
        connection: quinn::Connection,
    },
    PeerFailed {
        peer: NodeId,
        generation: u64,
        detail: String,
    },
    PeerClosed {
        peer: NodeId,
        generation: u64,
        detail: String,
    },
}

/// Start a dedicated Tokio runtime so GPUI's UI thread never performs network work.
pub fn spawn(
    identity: Identity,
    config: DesktopSessionConfig,
) -> std::io::Result<(DesktopSessionHandle, mpsc::Receiver<SessionEvent>)> {
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
    let thread_events = event_tx.clone();
    let (stop, mut stopped) = watch::channel(false);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let thread =
        std::thread::Builder::new()
            .name("p2p-desktop-network".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build();
                match runtime {
                    Ok(runtime) => {
                        runtime.block_on(async move {
                        let transfer = config.transfer.clone();
                        tokio::select! {
                            biased;
                            _ = stopped.changed() => {},
                            _ = event_tx.closed() => {},
                            _ = run_session(identity, config, command_rx, event_tx.clone()) => {},
                        }
                        if let Some(transfer) = transfer { let _ = transfer.interrupt_all().await; }
                    });
                        runtime.shutdown_timeout(Duration::from_secs(1));
                    }
                    Err(error) => {
                        let _ = thread_events.blocking_send(SessionEvent::Lifecycle(
                            NetworkLifecycle::Failed {
                                detail: format!("创建网络运行时失败：{error}"),
                            },
                        ));
                    }
                }
                let _ = done_tx.send(());
            })?;
    Ok((
        DesktopSessionHandle {
            commands: command_tx,
            lifetime: Arc::new(SessionLifetime {
                stop,
                done: std::sync::Mutex::new(done_rx),
                thread: std::sync::Mutex::new(Some(thread)),
            }),
        },
        event_rx,
    ))
}

async fn run_session(
    identity: Identity,
    config: DesktopSessionConfig,
    mut commands: mpsc::Receiver<SessionCommand>,
    events: mpsc::Sender<SessionEvent>,
) {
    emit_lifecycle(&events, NetworkLifecycle::ConnectingSignal).await;
    let network = match prepare_desktop_network(&config.network).await {
        Ok(network) => network,
        Err(error) => {
            emit_lifecycle(
                &events,
                NetworkLifecycle::Failed {
                    detail: error.to_string(),
                },
            )
            .await;
            return;
        }
    };

    let local_node = identity.node_id();
    let endpoint = network.endpoint.clone();
    let (input_tx, mut inputs) = mpsc::channel(SESSION_INPUT_CAPACITY);
    let accept_endpoint = endpoint.clone();
    let accept_inputs = input_tx.clone();
    let mut session_tasks = JoinSet::new();
    session_tasks.spawn(async move {
        accept_incoming_loop(accept_endpoint, accept_inputs).await;
    });

    let semaphore = Arc::new(Semaphore::new(MAX_PENDING_PEERS));
    let mut peer_tasks = JoinSet::new();
    let selection_workers = Arc::new(Semaphore::new(3));
    let selection_jobs = Arc::new(Semaphore::new(64));
    let continuation_jobs = Arc::new(Semaphore::new(3));
    let mut queue_changes = config.transfer.as_ref().map(|service| service.subscribe());
    let mut peers = PeerRegistry::default();
    let mut connections: HashMap<NodeId, (u64, quinn::Connection)> = HashMap::new();
    let mut pending_inbound: HashMap<(NodeId, u64), oneshot::Sender<quinn::Incoming>> =
        HashMap::new();
    let mut queued_lookups: VecDeque<(NodeId, u64)> = VecDeque::new();
    let mut signal: Option<SignalingClient> = None;
    let mut signal_server = config.signal_server;
    let mut signal_generation = 0u64;
    let mut connect_task: Option<tokio::task::AbortHandle> = None;
    let mut reconnect_sleep: Option<Pin<Box<Sleep>>> = None;
    let mut reconnect_attempt = 0u32;
    let mut session_shutdown = false;
    let mut maintenance = time::interval(Duration::from_secs(1));

    start_signal_connect(
        &identity,
        &signal_server,
        &network.local_candidates,
        signal_generation,
        input_tx.clone(),
        &mut connect_task,
        &mut session_tasks,
    );

    while !session_shutdown {
        enum Wake {
            Command(Option<SessionCommand>),
            Signal(Result<SignalMessage>),
            Input(Option<SessionInput>),
            Retry,
            Maintenance,
            QueueChanged,
            Task(Option<std::result::Result<(), tokio::task::JoinError>>),
        }

        let wake = tokio::select! {
            command = commands.recv() => Wake::Command(command),
            _ = maintenance.tick() => Wake::Maintenance,
            _ = async {
                match queue_changes.as_mut() {
                    Some(changes) => {let _ = changes.changed().await;},
                    None => std::future::pending::<()>().await,
                }
            } => Wake::QueueChanged,
            message = async {
                match signal.as_mut() {
                    Some(client) => client.next_event().await,
                    None => std::future::pending::<Result<SignalMessage>>().await,
                }
            } => Wake::Signal(message),
            input = inputs.recv() => Wake::Input(input),
            _ = async {
                match reconnect_sleep.as_mut() {
                    Some(sleep) => sleep.as_mut().await,
                    None => std::future::pending::<()>().await,
                }
            } => Wake::Retry,
            task = peer_tasks.join_next(), if !peer_tasks.is_empty() => Wake::Task(task),
            task = session_tasks.join_next(), if !session_tasks.is_empty() => Wake::Task(task),
        };

        match wake {
            #[cfg(test)]
            Wake::Command(Some(SessionCommand::Inspect(reply))) => {
                let _ = reply.send(connections.clone());
            }
            Wake::Command(None) => {
                session_shutdown = true;
            }
            Wake::Command(Some(SessionCommand::StartSpeed {
                peer,
                direction,
                seconds,
            })) => {
                if let Some(service) = config.transfer.clone() {
                    let events = events.clone();
                    peer_tasks.spawn(async move {
                        if let Err(error) = service.start_speed(peer, direction, seconds).await {
                            let _ = events
                                .send(SessionEvent::Diagnostic(error.to_string()))
                                .await;
                        }
                    });
                }
            }
            Wake::Command(Some(SessionCommand::CancelSpeed { peer, id })) => {
                if let Some(service) = config.transfer.as_ref()
                    && let Err(error) = service.cancel_speed(peer, &id)
                {
                    let _ = events
                        .send(SessionEvent::Diagnostic(error.to_string()))
                        .await;
                }
            }
            Wake::Command(Some(SessionCommand::PauseTask(id))) => {
                if let Some(service) = &config.transfer
                    && let Err(error) = service.pause_task(id).await
                {
                    let _ = events
                        .send(SessionEvent::Diagnostic(error.to_string()))
                        .await;
                }
            }
            Wake::Command(Some(
                command @ (SessionCommand::SendFile { .. }
                | SessionCommand::SendDirectory { .. }
                | SessionCommand::ResumeTask { .. }),
            )) => {
                let peer = match &command {
                    SessionCommand::SendFile { peer, .. }
                    | SessionCommand::SendDirectory { peer, .. }
                    | SessionCommand::ResumeTask { peer, .. } => *peer,
                    _ => unreachable!(),
                };
                let Some(service) = config.transfer.clone() else {
                    let _ = events
                        .send(SessionEvent::Diagnostic("任务存储尚未就绪".into()))
                        .await;
                    continue;
                };
                if peer == local_node {
                    let _ = events
                        .send(SessionEvent::Diagnostic("不能向本机发送任务".into()))
                        .await;
                    continue;
                }
                let connection = connections
                    .get(&peer)
                    .map(|(_, connection)| connection.clone());
                let job_pool = if matches!(&command, SessionCommand::ResumeTask { .. }) {
                    continuation_jobs.clone()
                } else {
                    selection_jobs.clone()
                };
                let Ok(permit) = job_pool.try_acquire_owned() else {
                    let _ = events
                        .send(SessionEvent::Diagnostic(
                            "文件命令排队已达上限，请稍后重试".into(),
                        ))
                        .await;
                    continue;
                };
                let selection_workers = selection_workers.clone();
                let events = events.clone();
                peer_tasks.spawn(async move {
                    let _permit = permit;
                    let result = async {
                        match command {
                            SessionCommand::SendFile { source, .. } => {
                                let _worker =
                                    selection_workers.clone().acquire_owned().await.map_err(
                                        |_| super::transfer_files::failure("扫描任务已关闭"),
                                    )?;
                                service.select_file(peer, source).await.map(|_| ())
                            }
                            SessionCommand::SendDirectory { source, .. } => {
                                let _worker =
                                    selection_workers.clone().acquire_owned().await.map_err(
                                        |_| super::transfer_files::failure("扫描任务已关闭"),
                                    )?;
                                service.select_directory(peer, source).await.map(|_| ())
                            }
                            SessionCommand::ResumeTask { id, .. } => {
                                let record = service.task(id.clone()).await?;
                                if record.direction() == super::task_model::TaskDirection::Send {
                                    service.enqueue_tasks(peer, vec![id]).await
                                } else {
                                    let connection = connection.ok_or_else(|| {
                                        super::transfer_files::failure("请先连接任务绑定的对端")
                                    })?;
                                    service.resume(&connection, peer, id).await
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    .await;
                    if let Err(error) = result {
                        let _ = events
                            .send(SessionEvent::Diagnostic(error.to_string()))
                            .await;
                    }
                });
            }
            Wake::Command(Some(SessionCommand::ConnectPeer(peer))) => {
                if peer == local_node {
                    let _ = events
                        .send(SessionEvent::Diagnostic("不能连接本机 Node ID".into()))
                        .await;
                    continue;
                }
                match peers.begin_attempt(peer) {
                    BeginPeerAttempt::Started(generation) => {
                        emit_peer_state(&events, peer, generation, PeerLifecycle::PeerPending)
                            .await;
                        emit_lifecycle(&events, NetworkLifecycle::PeerPending { peer }).await;
                        if let Some(client) = signal.as_ref() {
                            if client.request_lookup(peer).await.is_err() {
                                queued_lookups.push_back((peer, generation));
                                signal = None;
                                schedule_reconnect(
                                    &events,
                                    &mut reconnect_attempt,
                                    &mut reconnect_sleep,
                                    "信令写入失败".into(),
                                )
                                .await;
                            }
                        } else {
                            queued_lookups.push_back((peer, generation));
                        }
                    }
                    BeginPeerAttempt::AlreadyActive(_) => {
                        let _ = events
                            .send(SessionEvent::Diagnostic(format!(
                                "已存在对端 {} 的连接请求，忽略重复点击",
                                peer.short()
                            )))
                            .await;
                    }
                    BeginPeerAttempt::AtCapacity => {
                        let _ = events
                            .send(SessionEvent::Diagnostic("待连接对端已达资源上限".into()))
                            .await;
                    }
                }
            }
            Wake::Command(Some(SessionCommand::ReconfigureSignal(server))) => {
                signal_server = server;
                signal_generation = signal_generation.wrapping_add(1);
                // An explicit server change supersedes this generation's attempts
                // and authenticated peers. An involuntary outage below preserves them.
                peer_tasks.abort_all();
                while peer_tasks.join_next().await.is_some() {}
                if let Some(service) = &config.transfer {
                    let _ = service.interrupt_all().await;
                }
                pending_inbound.clear();
                queued_lookups.clear();
                for (_, (_, connection)) in connections.drain() {
                    connection.close(0u32.into(), b"desktop network reconfigured");
                }
                for (peer, generation) in peers.active_peers() {
                    let state = PeerLifecycle::Failed("网络配置已更改，请重新连接".into());
                    if peers.transition(peer, generation, state.clone()) {
                        emit_peer_state(&events, peer, generation, state).await;
                    }
                }
                signal = None;
                reconnect_sleep = None;
                reconnect_attempt = 0;
                if let Some(task) = connect_task.take() {
                    task.abort();
                }
                emit_lifecycle(&events, NetworkLifecycle::ConnectingSignal).await;
                start_signal_connect(
                    &identity,
                    &signal_server,
                    &network.local_candidates,
                    signal_generation,
                    input_tx.clone(),
                    &mut connect_task,
                    &mut session_tasks,
                );
            }
            Wake::Signal(Ok(message)) => match message {
                SignalMessage::Pong => {
                    let _ = events
                        .send(SessionEvent::Diagnostic("信令心跳已确认".into()))
                        .await;
                }
                SignalMessage::PeerPending { node_id } => {
                    if peers.state(node_id) == Some(&PeerLifecycle::PeerPending) {
                        emit_peer_state(
                            &events,
                            node_id,
                            peers.generation(node_id).unwrap_or_default(),
                            PeerLifecycle::PeerPending,
                        )
                        .await;
                        emit_lifecycle(&events, NetworkLifecycle::PeerPending { peer: node_id })
                            .await;
                    }
                }
                SignalMessage::PeerCandidates {
                    node_id,
                    candidates,
                    token,
                } => {
                    start_peer_attempt(
                        node_id,
                        candidates,
                        token,
                        local_node,
                        identity.clone(),
                        &network,
                        &events,
                        &input_tx,
                        &semaphore,
                        &mut peers,
                        &mut pending_inbound,
                        &mut peer_tasks,
                    )
                    .await;
                }
                SignalMessage::Error { reason } => {
                    let detail = format!("信令查询失败：{reason}");
                    for (peer, generation) in peers.pending_peers() {
                        if peers.transition(peer, generation, PeerLifecycle::Failed(detail.clone()))
                        {
                            emit_peer_state(
                                &events,
                                peer,
                                generation,
                                PeerLifecycle::Failed(detail.clone()),
                            )
                            .await;
                        }
                    }
                    queued_lookups.clear();
                    let _ = events
                        .send(SessionEvent::Diagnostic(format!(
                            "信令服务拒绝请求：{reason}"
                        )))
                        .await;
                }
                other => {
                    debug!(
                        kind = other.kind(),
                        "桌面 session 忽略注册阶段以外的信令消息"
                    );
                }
            },
            Wake::Signal(Err(error)) => {
                warn!(%error, "桌面信令连接断开；保留已有认证 P2P 连接");
                signal = None;
                enqueue_pending_lookups(&peers, &mut queued_lookups);
                schedule_reconnect(
                    &events,
                    &mut reconnect_attempt,
                    &mut reconnect_sleep,
                    error.to_string(),
                )
                .await;
            }
            Wake::Input(Some(SessionInput::SignalConnected { generation, result })) => {
                if !is_current_signal_generation(signal_generation, generation) {
                    drop(result);
                    continue;
                }
                connect_task = None;
                match result {
                    Ok(client) => {
                        let registered_node = client.node_id();
                        signal = Some(client);
                        reconnect_attempt = 0;
                        reconnect_sleep = None;
                        let _ = events
                            .send(SessionEvent::SignalIdentityRegistered(registered_node))
                            .await;
                        emit_lifecycle(&events, NetworkLifecycle::SignalOnline).await;
                        while let Some((peer, generation)) = queued_lookups.pop_front() {
                            if !peers.is_current(peer, generation)
                                || peers.state(peer) != Some(&PeerLifecycle::PeerPending)
                            {
                                continue;
                            }
                            let Some(client) = signal.as_ref() else {
                                queued_lookups.push_front((peer, generation));
                                break;
                            };
                            if let Err(error) = client.request_lookup(peer).await {
                                warn!(%error, "发送待处理 lookup 失败");
                                queued_lookups.push_front((peer, generation));
                                signal = None;
                                schedule_reconnect(
                                    &events,
                                    &mut reconnect_attempt,
                                    &mut reconnect_sleep,
                                    error.to_string(),
                                )
                                .await;
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        schedule_reconnect(
                            &events,
                            &mut reconnect_attempt,
                            &mut reconnect_sleep,
                            error.to_string(),
                        )
                        .await;
                    }
                }
            }
            Wake::Input(Some(SessionInput::Incoming(incoming))) => {
                let incoming = *incoming;
                let remote = incoming.remote_address();
                let Some((peer, generation)) = network.punch_socket.claim_authorized_peer(remote)
                else {
                    incoming.refuse();
                    continue;
                };
                if !peers.is_current(peer, generation) || should_initiate_quic(local_node, peer) {
                    incoming.refuse();
                    continue;
                }
                let Some(waiting) = pending_inbound.remove(&(peer, generation)) else {
                    incoming.refuse();
                    continue;
                };
                if let Err(incoming) = waiting.send(incoming) {
                    incoming.refuse();
                }
            }
            Wake::Input(Some(SessionInput::PeerProgress {
                peer,
                generation,
                state,
            })) => {
                if peers.transition(peer, generation, state.clone()) {
                    emit_peer_state(&events, peer, generation, state.clone()).await;
                    if state == PeerLifecycle::Authenticating {
                        emit_lifecycle(&events, NetworkLifecycle::Authenticating { peer }).await;
                    }
                }
            }
            Wake::Input(Some(SessionInput::PeerConnected {
                peer,
                generation,
                connection,
            })) => {
                pending_inbound.remove(&(peer, generation));
                if !peers.is_current(peer, generation)
                    || peers.state(peer) == Some(&PeerLifecycle::Connected)
                {
                    connection.close(0u32.into(), b"duplicate or stale peer generation");
                    continue;
                }
                if !peers.transition(peer, generation, PeerLifecycle::Connected) {
                    connection.close(0u32.into(), b"stale peer generation");
                    continue;
                }
                connections.insert(peer, (generation, connection.clone()));
                emit_peer_state(&events, peer, generation, PeerLifecycle::Connected).await;
                emit_lifecycle(&events, NetworkLifecycle::Connected { peer }).await;
                if let Some(service) = config.transfer.clone() {
                    let transfer_connection = connection.clone();
                    let transfer_events = events.clone();
                    peer_tasks.spawn(async move {
                        if service
                            .serve_peer_with_speed(transfer_connection, peer, local_node)
                            .await
                            .is_err()
                        {
                            let _ = transfer_events
                                .send(SessionEvent::Diagnostic(
                                    "文件会话已中断，任务可手动继续".into(),
                                ))
                                .await;
                        }
                    });
                }
                let closed_inputs = input_tx.clone();
                peer_tasks.spawn(async move {
                    let detail = connection.closed().await.to_string();
                    let _ = closed_inputs
                        .send(SessionInput::PeerClosed {
                            peer,
                            generation,
                            detail,
                        })
                        .await;
                });
            }
            Wake::Input(Some(SessionInput::PeerFailed {
                peer,
                generation,
                detail,
            })) => {
                pending_inbound.remove(&(peer, generation));
                if peers.transition(peer, generation, PeerLifecycle::Failed(detail.clone())) {
                    emit_peer_state(
                        &events,
                        peer,
                        generation,
                        PeerLifecycle::Failed(detail.clone()),
                    )
                    .await;
                }
            }
            Wake::Input(Some(SessionInput::PeerClosed {
                peer,
                generation,
                detail,
            })) => {
                if peers.is_current(peer, generation)
                    && connections
                        .get(&peer)
                        .is_some_and(|(current, _)| *current == generation)
                {
                    connections.remove(&peer);
                    if peers.transition(peer, generation, PeerLifecycle::Disconnected) {
                        emit_peer_state(&events, peer, generation, PeerLifecycle::Disconnected)
                            .await;
                        emit_lifecycle(
                            &events,
                            NetworkLifecycle::Disconnected {
                                peer: Some(peer),
                                detail,
                            },
                        )
                        .await;
                    }
                }
            }
            Wake::QueueChanged => {}
            Wake::Maintenance => {
                for (peer, generation) in peers.expired_lookups(time::Instant::now()) {
                    let state = PeerLifecycle::Failed("目标离线或候选等待超时，请重试连接".into());
                    if peers.transition(peer, generation, state.clone()) {
                        queued_lookups.retain(|entry| *entry != (peer, generation));
                        emit_peer_state(&events, peer, generation, state).await;
                    }
                }
            }
            Wake::Input(None) => session_shutdown = true,
            Wake::Retry => {
                reconnect_sleep = None;
                emit_lifecycle(
                    &events,
                    NetworkLifecycle::ReconnectingSignal {
                        attempt: reconnect_attempt,
                        delay: Duration::ZERO,
                    },
                )
                .await;
                start_signal_connect(
                    &identity,
                    &signal_server,
                    &network.local_candidates,
                    signal_generation,
                    input_tx.clone(),
                    &mut connect_task,
                    &mut session_tasks,
                );
            }
            Wake::Task(Some(Err(error))) => {
                warn!(%error, "desktop session 子任务异常退出");
            }
            Wake::Task(Some(Ok(()))) | Wake::Task(None) => {}
        }
        if !session_shutdown && let Some(service) = config.transfer.as_ref() {
            let ready_connections = connections
                .iter()
                .map(|(peer, (_, connection))| (*peer, connection.clone()))
                .collect();
            for scheduled in service.dispatch_ready(&ready_connections) {
                let connection = ready_connections[&scheduled.entry.peer].clone();
                let service = service.clone();
                let events = events.clone();
                // Same structured owner as receive/RPC workers: shutdown aborts
                // and drains every executor before persisted interruption recovery.
                peer_tasks.spawn(async move {
                    if let Err(error) = service.execute_queued(scheduled, connection).await {
                        let _ = events
                            .send(SessionEvent::Diagnostic(error.to_string()))
                            .await;
                    }
                });
            }
        }
    }

    if let Some(task) = connect_task.take() {
        task.abort();
    }
    drop(signal);
    for (_, (_, connection)) in connections.drain() {
        connection.close(0u32.into(), b"desktop session shutdown");
    }
    endpoint.close(0u32.into(), b"desktop session shutdown");
    session_tasks.abort_all();
    peer_tasks.abort_all();
    while peer_tasks.join_next().await.is_some() {}
    while session_tasks.join_next().await.is_some() {}
    let _ = time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

fn start_signal_connect(
    identity: &Identity,
    signal_server: &str,
    candidates: &[Candidate],
    generation: u64,
    inputs: mpsc::Sender<SessionInput>,
    task: &mut Option<tokio::task::AbortHandle>,
    tasks: &mut JoinSet<()>,
) {
    let identity = identity.clone();
    let signal_server = signal_server.to_owned();
    let candidates = candidates.to_vec();
    *task = Some(tasks.spawn(async move {
        let result =
            SignalingClient::connect_with_events(&signal_server, &identity, candidates).await;
        let _ = inputs
            .send(SessionInput::SignalConnected { generation, result })
            .await;
    }));
}

fn enqueue_pending_lookups(peers: &PeerRegistry, queued_lookups: &mut VecDeque<(NodeId, u64)>) {
    for pending in peers.pending_peers() {
        if !queued_lookups.contains(&pending) {
            queued_lookups.push_back(pending);
        }
    }
}

async fn schedule_reconnect(
    events: &mpsc::Sender<SessionEvent>,
    attempt: &mut u32,
    sleep: &mut Option<Pin<Box<Sleep>>>,
    detail: String,
) {
    let jitter = i32::from(rand::random::<u16>() % 401) - 200;
    let delay = reconnect_delay(*attempt, jitter);
    *attempt = attempt.saturating_add(1);
    *sleep = Some(Box::pin(time::sleep(delay)));
    let _ = events
        .send(SessionEvent::Diagnostic(format!(
            "信令已断开，将在 {:.1} 秒后重试：{detail}",
            delay.as_secs_f32()
        )))
        .await;
    emit_lifecycle(
        events,
        NetworkLifecycle::ReconnectingSignal {
            attempt: *attempt,
            delay,
        },
    )
    .await;
}

async fn emit_lifecycle(events: &mpsc::Sender<SessionEvent>, lifecycle: NetworkLifecycle) {
    let _ = events.send(SessionEvent::Lifecycle(lifecycle)).await;
}

async fn emit_peer_state(
    events: &mpsc::Sender<SessionEvent>,
    peer: NodeId,
    generation: u64,
    state: PeerLifecycle,
) {
    let _ = events
        .send(SessionEvent::PeerState {
            peer,
            generation,
            state,
        })
        .await;
}

async fn accept_incoming_loop(endpoint: quinn::Endpoint, inputs: mpsc::Sender<SessionInput>) {
    while let Some(incoming) = endpoint.accept().await {
        if inputs
            .send(SessionInput::Incoming(Box::new(incoming)))
            .await
            .is_err()
        {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_peer_attempt(
    peer: NodeId,
    candidates: Vec<Candidate>,
    token: PunchToken,
    local_node: NodeId,
    identity: Identity,
    network: &DesktopNetwork,
    events: &mpsc::Sender<SessionEvent>,
    inputs: &mpsc::Sender<SessionInput>,
    semaphore: &Arc<Semaphore>,
    peers: &mut PeerRegistry,
    pending_inbound: &mut HashMap<(NodeId, u64), oneshot::Sender<quinn::Incoming>>,
    tasks: &mut JoinSet<()>,
) {
    if peer == local_node {
        return;
    }
    let generation = match peers.state(peer) {
        Some(PeerLifecycle::PeerPending) => peers.generation(peer),
        Some(state) if state.is_active() => None,
        _ => match peers.begin_attempt(peer) {
            BeginPeerAttempt::Started(generation) => Some(generation),
            BeginPeerAttempt::AlreadyActive(_) => None,
            BeginPeerAttempt::AtCapacity => {
                let _ = events
                    .send(SessionEvent::Diagnostic("对端连接数已达资源上限".into()))
                    .await;
                return;
            }
        },
    };
    let Some(generation) = generation else {
        return;
    };
    let Ok(permit) = Arc::clone(semaphore).try_acquire_owned() else {
        let detail = "待认证连接已达资源上限".to_owned();
        peers.transition(peer, generation, PeerLifecycle::Failed(detail.clone()));
        emit_peer_state(
            events,
            peer,
            generation,
            PeerLifecycle::Failed(detail.clone()),
        )
        .await;
        let _ = events.send(SessionEvent::Diagnostic(detail)).await;
        return;
    };

    let filtered: Vec<Candidate> = candidates
        .into_iter()
        .filter(|candidate| candidate.kind != CandidateKind::Relay)
        .collect::<Vec<_>>();
    let reachable = network.reachable_candidates(&filtered);
    if reachable.is_empty() {
        let detail = "对端候选地址与本机 UDP 地址族不匹配".to_owned();
        peers.transition(peer, generation, PeerLifecycle::Failed(detail.clone()));
        emit_peer_state(
            events,
            peer,
            generation,
            PeerLifecycle::Failed(detail.clone()),
        )
        .await;
        return;
    }

    if !peers.transition(peer, generation, PeerLifecycle::Punching) {
        return;
    }
    emit_peer_state(events, peer, generation, PeerLifecycle::Punching).await;
    emit_lifecycle(events, NetworkLifecycle::Punching { peer }).await;
    let (inbound_tx, inbound_rx) = oneshot::channel();
    pending_inbound.insert((peer, generation), inbound_tx);
    let input_sender = inputs.clone();
    let endpoint = network.endpoint.clone();
    let punch_socket = network.punch_socket.clone();
    tasks.spawn(async move {
        let result = run_peer_attempt(
            peer,
            generation,
            local_node,
            identity,
            endpoint,
            punch_socket,
            reachable,
            token,
            inbound_rx,
            permit,
            input_sender.clone(),
        )
        .await;
        if let Err(detail) = result {
            let _ = input_sender
                .send(SessionInput::PeerFailed {
                    peer,
                    generation,
                    detail,
                })
                .await;
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn run_peer_attempt(
    peer: NodeId,
    generation: u64,
    local_node: NodeId,
    identity: Identity,
    endpoint: quinn::Endpoint,
    punch_socket: crate::transport::quic::PunchSocketHandle,
    candidates: Vec<SocketAddr>,
    token: PunchToken,
    inbound: oneshot::Receiver<quinn::Incoming>,
    _pending_permit: tokio::sync::OwnedSemaphorePermit,
    inputs: mpsc::Sender<SessionInput>,
) -> std::result::Result<(), String> {
    let mut probe_events = punch_socket
        .register_peer_probe(&token, peer, generation)
        .map_err(|error| error.to_string())?;
    let remote = punch_candidates(&punch_socket, &mut probe_events, &candidates, &token)
        .await
        .map_err(|error| error.to_string())?;
    let _ = inputs
        .send(SessionInput::PeerProgress {
            peer,
            generation,
            state: PeerLifecycle::Authenticating,
        })
        .await;

    let connection = if should_initiate_quic(local_node, peer) {
        authenticate_outgoing(&endpoint, remote, &identity, peer).await?
    } else {
        let incoming = time::timeout(
            QUIC_HANDSHAKE_TIMEOUT + APPLICATION_HANDSHAKE_TIMEOUT,
            inbound,
        )
        .await
        .map_err(|_| "打洞确认后未收到发起方的 QUIC 连接".to_owned())?
        .map_err(|_| "入站 QUIC 等待已取消".to_owned())?;
        // The dispatcher already checked this incoming source against this peer's
        // live token and generation. Multiple valid local/public paths may race;
        // the responder's first probe source need not be the dialer's chosen path.
        authenticate_incoming(incoming, &identity, peer).await?
    };

    let _ = inputs
        .send(SessionInput::PeerProgress {
            peer,
            generation,
            state: PeerLifecycle::Negotiating,
        })
        .await;
    super::protocol::negotiate(&connection, should_initiate_quic(local_node, peer))
        .await
        .map_err(|error| error.to_string())?;

    inputs
        .send(SessionInput::PeerConnected {
            peer,
            generation,
            connection,
        })
        .await
        .map_err(|_| "desktop session 已关闭".to_owned())
}

async fn punch_candidates(
    socket: &crate::transport::quic::PunchSocketHandle,
    events: &mut crate::transport::quic::PunchProbeReceiver,
    candidates: &[SocketAddr],
    token: &PunchToken,
) -> Result<SocketAddr> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(Error::Transport("对端候选地址超过桌面连接上限".into()));
    }
    for attempt in 0..PEER_PUNCH_CONFIG.attempts {
        for candidate in candidates {
            if let Err(error) = socket.send_probe_to(token, *candidate).await {
                debug!(%candidate, %error, attempt, "发送桌面打洞探测包失败");
            }
        }
        match time::timeout(PEER_PUNCH_CONFIG.interval, events.recv()).await {
            Ok(Some(source)) => {
                // The first outbound probe may predate the remote token registration.
                // Reply to the validated actual source before stopping our probe loop.
                socket.send_probe_to(token, source).await?;
                return Ok(source);
            }
            Ok(None) => return Err(Error::Transport("打洞令牌接收器已关闭".into())),
            Err(_) => {}
        }
    }
    Err(Error::Transport(format!(
        "打洞超时：未收到带正确令牌的探测回应（{} 个候选）",
        candidates.len()
    )))
}

async fn authenticate_outgoing(
    endpoint: &quinn::Endpoint,
    remote: SocketAddr,
    identity: &Identity,
    expected_peer: NodeId,
) -> std::result::Result<quinn::Connection, String> {
    let connection = time::timeout(
        QUIC_HANDSHAKE_TIMEOUT,
        quic_connect(endpoint, remote, "p2pfile"),
    )
    .await
    .map_err(|_| "QUIC 握手超时".to_owned())?
    .map_err(|error| error.to_string())?;
    let binding =
        ChannelBinding::from_connection(&connection).map_err(|error| error.to_string())?;
    let (mut send, mut recv) = time::timeout(ACCEPT_FIRST_BI_STREAM_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| "打开 Ed25519 身份握手流超时".to_owned())?
        .map_err(|error| error.to_string())?;
    let outcome = time::timeout(
        APPLICATION_HANDSHAKE_TIMEOUT,
        handshake_initiator(&mut send, &mut recv, identity, &binding),
    )
    .await
    .map_err(|_| "Ed25519/channel-binding 发起方握手超时".to_owned())?
    .map_err(|error| error.to_string())?;
    let _ = send.finish();
    if outcome.peer_node_id != expected_peer {
        connection.close(2u32.into(), b"unexpected peer");
        return Err(format!(
            "对端身份不符：期待 {}，实际 {}",
            expected_peer.short(),
            outcome.peer_node_id.short()
        ));
    }
    Ok(connection)
}

async fn authenticate_incoming(
    incoming: quinn::Incoming,
    identity: &Identity,
    expected_peer: NodeId,
) -> std::result::Result<quinn::Connection, String> {
    let connection = time::timeout(QUIC_HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|_| "入站 QUIC 握手超时".to_owned())?
        .map_err(|error| error.to_string())?;
    let binding =
        ChannelBinding::from_connection(&connection).map_err(|error| error.to_string())?;
    let (mut send, mut recv) =
        time::timeout(ACCEPT_FIRST_BI_STREAM_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| "等待对端身份握手流超时".to_owned())?
            .map_err(|error| error.to_string())?;
    let outcome = time::timeout(
        APPLICATION_HANDSHAKE_TIMEOUT,
        handshake_responder(&mut send, &mut recv, identity, &binding),
    )
    .await
    .map_err(|_| "Ed25519/channel-binding 接收方握手超时".to_owned())?
    .map_err(|error| error.to_string())?;
    let _ = send.finish();
    if outcome.peer_node_id != expected_peer {
        connection.close(2u32.into(), b"unexpected peer");
        return Err(format!(
            "入站身份不符：期待 {}，实际 {}",
            expected_peer.short(),
            outcome.peer_node_id.short()
        ));
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::discovery::signal::{
        SignalServerConfig, run_signal_server_on, run_signal_server_on_with,
    };

    async fn start_local_server() -> (SocketAddr, JoinHandle<()>) {
        start_local_server_with(SignalServerConfig::default()).await
    }

    async fn start_local_server_with(config: SignalServerConfig) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = run_signal_server_on_with(listener, config).await;
        });
        (address, server)
    }

    fn local_config(signal_server: SocketAddr) -> DesktopSessionConfig {
        DesktopSessionConfig {
            signal_server: signal_server.to_string(),
            transfer: None,
            network: DesktopNetworkConfig {
                local_port: 0,
                stun_servers: Vec::new(),
                include_loopback: true,
                ..DesktopNetworkConfig::default()
            },
        }
    }

    async fn inspect(handle: &DesktopSessionHandle) -> HashMap<NodeId, (u64, quinn::Connection)> {
        let (tx, rx) = oneshot::channel();
        handle
            .commands
            .send(SessionCommand::Inspect(tx))
            .await
            .unwrap();
        time::timeout(Duration::from_secs(2), rx)
            .await
            .unwrap()
            .unwrap()
    }

    async fn wait_signal_online(events: &mut mpsc::Receiver<SessionEvent>) {
        time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events.recv().await {
                if matches!(
                    event,
                    SessionEvent::Lifecycle(NetworkLifecycle::SignalOnline)
                ) {
                    return;
                }
            }
            panic!("session stopped before signal registration");
        })
        .await
        .expect("signal registration should complete");
    }

    async fn wait_connected(events: &mut mpsc::Receiver<SessionEvent>, expected: &[NodeId]) {
        time::timeout(Duration::from_secs(20), async {
            let mut connected = HashSet::new();
            while connected.len() < expected.len() {
                let Some(event) = events.recv().await else {
                    panic!("session stopped before all peers authenticated");
                };
                if let SessionEvent::PeerState {
                    state: PeerLifecycle::Failed(ref detail),
                    ..
                } = event
                {
                    panic!("peer establishment failed: {detail}");
                }
                if let SessionEvent::PeerState {
                    peer,
                    state: PeerLifecycle::Connected,
                    ..
                } = event
                {
                    connected.insert(peer);
                }
            }
            for peer in expected {
                assert!(
                    connected.contains(peer),
                    "missing authenticated peer {peer}"
                );
            }
        })
        .await
        .expect("authenticated peer connection should complete");
    }

    #[tokio::test]
    async fn passive_peer_uses_same_registration_and_third_peer_progresses() {
        let (signal_server, server) = start_local_server().await;
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let identity_c = Identity::generate();
        let (handle_a, mut events_a) =
            spawn(identity_a.clone(), local_config(signal_server)).unwrap();
        let (handle_b, mut events_b) =
            spawn(identity_b.clone(), local_config(signal_server)).unwrap();
        let (handle_c, mut events_c) =
            spawn(identity_c.clone(), local_config(signal_server)).unwrap();

        wait_signal_online(&mut events_a).await;
        wait_signal_online(&mut events_b).await;
        wait_signal_online(&mut events_c).await;

        // A never chooses or enters B. B's lookup must reach the passive session
        // and complete the existing authenticated handshake in both directions.
        handle_b.connect_peer(identity_a.node_id()).unwrap();
        wait_connected(&mut events_a, &[identity_b.node_id()]).await;
        wait_connected(&mut events_b, &[identity_a.node_id()]).await;

        let before_b = inspect(&handle_b).await;
        let original_connection = &before_b[&identity_a.node_id()].1;

        // Keep B<->A alive while C requests B. One registration per identity and
        // the shared endpoint must allow this third peer to progress independently.
        handle_c.connect_peer(identity_b.node_id()).unwrap();
        wait_connected(&mut events_b, &[identity_c.node_id()]).await;
        wait_connected(&mut events_c, &[identity_b.node_id()]).await;
        let after_b = inspect(&handle_b).await;
        assert_eq!(after_b.len(), 2);
        assert_eq!(
            after_b[&identity_a.node_id()].1.stable_id(),
            original_connection.stable_id()
        );
        assert!(
            after_b
                .values()
                .all(|(_, connection)| connection.close_reason().is_none())
        );

        handle_a.shutdown();
        handle_b.shutdown();
        handle_c.shutdown();
        drop((handle_a, handle_b, handle_c));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn signal_restart_re_registers_the_same_identity_after_bounded_backoff() {
        let (signal_server, server) = start_local_server_with(SignalServerConfig {
            idle_timeout: Duration::from_millis(250),
            ..SignalServerConfig::default()
        })
        .await;
        let identity = Identity::generate();
        let (handle, mut events) = spawn(identity.clone(), local_config(signal_server)).unwrap();
        wait_signal_online(&mut events).await;
        server.abort();
        let _ = server.await;

        time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events.recv().await {
                if matches!(
                    event,
                    SessionEvent::Lifecycle(NetworkLifecycle::ReconnectingSignal { .. })
                ) {
                    return;
                }
            }
        })
        .await
        .expect("session should detect signaling disconnect and schedule bounded retry");

        let listener = TcpListener::bind(signal_server).await.unwrap();
        let restarted_server = tokio::spawn(async move {
            let _ = run_signal_server_on(listener).await;
        });
        time::timeout(Duration::from_secs(12), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::SignalIdentityRegistered(node_id) = event {
                    assert_eq!(node_id, identity.node_id());
                    return;
                }
            }
        })
        .await
        .expect("same identity should register again after the server restarts");

        handle.shutdown();
        drop(handle);
        restarted_server.abort();
        let _ = restarted_server.await;
    }

    #[tokio::test]
    async fn simultaneous_connect_requests_converge_to_one_authenticated_peer() {
        let (signal_server, mut server) = start_local_server().await;
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let (handle_a, mut events_a) =
            spawn(identity_a.clone(), local_config(signal_server)).unwrap();
        let (handle_b, mut events_b) =
            spawn(identity_b.clone(), local_config(signal_server)).unwrap();
        wait_signal_online(&mut events_a).await;
        wait_signal_online(&mut events_b).await;

        handle_a.connect_peer(identity_b.node_id()).unwrap();
        handle_a.connect_peer(identity_b.node_id()).unwrap();
        handle_b.connect_peer(identity_a.node_id()).unwrap();
        handle_b.connect_peer(identity_a.node_id()).unwrap();
        wait_connected(&mut events_a, &[identity_b.node_id()]).await;
        wait_connected(&mut events_b, &[identity_a.node_id()]).await;

        let before_a = inspect(&handle_a).await;
        let before_b = inspect(&handle_b).await;
        assert_eq!(before_a.len(), 1);
        assert_eq!(before_b.len(), 1);
        handle_a.connect_peer(identity_b.node_id()).unwrap();
        handle_b.connect_peer(identity_a.node_id()).unwrap();
        let after_a = inspect(&handle_a).await;
        let after_b = inspect(&handle_b).await;
        let conn_a = &before_a[&identity_b.node_id()].1;
        let conn_b = &before_b[&identity_a.node_id()].1;
        assert_eq!(
            conn_a.stable_id(),
            after_a[&identity_b.node_id()].1.stable_id()
        );
        assert_eq!(
            conn_b.stable_id(),
            after_b[&identity_a.node_id()].1.stable_id()
        );
        server.abort();
        let _ = (&mut server).await;
        time::timeout(Duration::from_secs(3), async {
            while let Some(event) = events_a.recv().await {
                if matches!(
                    event,
                    SessionEvent::Lifecycle(NetworkLifecycle::ReconnectingSignal { .. })
                ) {
                    return;
                }
            }
            panic!("session stopped during signaling outage");
        })
        .await
        .unwrap();
        let payload = b"authenticated connection survives signaling outage";
        time::timeout(Duration::from_secs(3), async {
            let send = async {
                let mut stream = conn_a.open_uni().await.unwrap();
                stream.write_all(payload).await.unwrap();
                stream.finish().unwrap();
                stream.stopped().await.unwrap();
            };
            let receive = async {
                let mut stream = conn_b.accept_uni().await.unwrap();
                assert_eq!(stream.read_to_end(1024).await.unwrap(), payload);
            };
            tokio::join!(send, receive);
        })
        .await
        .unwrap();
        assert!(conn_a.close_reason().is_none());
        assert!(conn_b.close_reason().is_none());
        handle_a.shutdown();
        handle_b.shutdown();
        drop((handle_a, handle_b));
    }

    #[tokio::test]
    async fn unexpected_authenticated_target_fails_before_connected() {
        let local_identity = Identity::generate();
        let remote_identity = Identity::generate();
        let unexpected_target = Identity::generate().node_id();
        assert_ne!(unexpected_target, remote_identity.node_id());
        let server =
            crate::transport::quic::server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("QUIC should arrive");
            let connection = incoming.await.expect("transport handshake should pass");
            let binding = ChannelBinding::from_connection(&connection).unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            handshake_responder(&mut send, &mut recv, &remote_identity, &binding)
                .await
                .unwrap();
            let _ = send.finish();
            connection.closed().await;
            server.wait_idle().await;
        });
        let client =
            crate::transport::quic::client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();

        let result =
            authenticate_outgoing(&client, address, &local_identity, unexpected_target).await;
        assert!(result.unwrap_err().contains("对端身份不符"));
        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_legacy_peer_is_rejected_by_desktop_negotiation() {
        time::timeout(Duration::from_secs(10), async {
            let local = Identity::generate();
            let remote = Identity::generate();
            let expected = remote.node_id();
            let server =
                crate::transport::quic::server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
            let address = server.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let connection = server.accept().await.unwrap().await.unwrap();
                let binding = ChannelBinding::from_connection(&connection).unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                handshake_responder(&mut send, &mut recv, &remote, &binding)
                    .await
                    .unwrap();
                send.finish().unwrap();
                let (send, mut recv) = connection.accept_bi().await.unwrap();
                assert!(crate::protocol::frame::read_frame(&mut recv).await.is_err());
                drop(send);
                connection.closed().await;
                server.wait_idle().await;
            });
            let client =
                crate::transport::quic::client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
            let connection = authenticate_outgoing(&client, address, &local, expected)
                .await
                .unwrap();
            let error = super::super::protocol::negotiate(&connection, true)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("桌面版本或能力不兼容"));
            assert!(connection.close_reason().is_some());
            client.close(0u32.into(), b"test complete");
            client.wait_idle().await;
            server_task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn late_probe_registration_receives_reply_at_validated_actual_source() {
        let (endpoint, socket) =
            crate::transport::quic::endpoint_from_socket_with_punch_dispatcher(
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            )
            .unwrap();
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let token = PunchToken::random();
        let mut probes = socket.register_probe(&token).unwrap();
        let remote_addr = remote.local_addr().unwrap();
        let local_addr = endpoint.local_addr().unwrap();
        let exchange = async {
            let mut packet = [0; 256];
            // Drop the first outgoing probe, as when remote registration is late.
            remote.recv_from(&mut packet).await.unwrap();
            remote
                .send_to(&crate::nat::punch::probe_packet(&token), local_addr)
                .await
                .unwrap();
            let (len, source) = remote.recv_from(&mut packet).await.unwrap();
            assert_eq!(source, local_addr);
            assert!(crate::nat::punch::is_probe_with_token(
                &packet[..len],
                &token
            ));
        };
        time::timeout(Duration::from_secs(2), async {
            let candidates = [remote_addr];
            let (source, ()) = tokio::join!(
                punch_candidates(&socket, &mut probes, &candidates, &token),
                exchange
            );
            assert_eq!(source.unwrap(), remote_addr);
        })
        .await
        .expect("validated probe must receive a final reply even after first packet loss");
        endpoint.close(0u32.into(), b"test complete");
        endpoint.wait_idle().await;
    }

    #[tokio::test]
    async fn reconfiguration_cancels_stalled_registration_and_uses_new_server() {
        let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stalled_address = stalled.local_addr().unwrap();
        let (new_address, server) = start_local_server().await;
        let (handle, mut events) =
            spawn(Identity::generate(), local_config(stalled_address)).unwrap();
        let (mut old_stream, _) = time::timeout(Duration::from_secs(3), stalled.accept())
            .await
            .unwrap()
            .unwrap();
        // TCP accept alone is not a registration barrier: wait for Hello before
        // canceling, so this test really exercises a stalled registration.
        let mut hello_prefix = [0u8; 1];
        time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_exact(&mut old_stream, &mut hello_prefix),
        )
        .await
        .unwrap()
        .unwrap();
        handle.reconfigure_signal(new_address.to_string()).unwrap();
        wait_signal_online(&mut events).await;
        // Drain the original Hello; canceled registration must then close TCP.
        let mut bytes = Vec::new();
        time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_to_end(&mut old_stream, &mut bytes),
        )
        .await
        .expect("superseded registration must release its socket")
        .unwrap();
        assert!(
            !bytes.is_empty(),
            "remaining Hello frame must be drained before EOF"
        );
        handle.shutdown();
        drop(handle);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn shutdown_joins_runtime_even_with_full_ui_event_queue() {
        let (address, server) = start_local_server().await;
        let (handle, mut events) = spawn(Identity::generate(), local_config(address)).unwrap();
        wait_signal_online(&mut events).await;
        let peer = Identity::generate().node_id();
        // Stop consuming UI events and fill both bounded channels. Shutdown has
        // its own watch channel and cannot get stuck behind these messages.
        for _ in 0..EVENT_CAPACITY + COMMAND_CAPACITY {
            let _ = handle.connect_peer(peer);
            tokio::task::yield_now().await;
        }
        handle.shutdown();
        let lifetime = Arc::clone(&handle.lifetime);
        drop(handle);
        tokio::task::spawn_blocking(move || {
            lifetime
                .done
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .expect("network runtime must finish despite UI backpressure");
            let thread = lifetime.thread.lock().unwrap().take().unwrap();
            thread.join().unwrap();
        })
        .await
        .unwrap();
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn stale_signal_connect_result_is_fenced_by_configuration_generation() {
        let old_generation = 7u64;
        let new_generation = old_generation.wrapping_add(1);
        assert!(is_current_signal_generation(old_generation, old_generation));
        assert!(!is_current_signal_generation(
            new_generation,
            old_generation
        ));
    }
    #[tokio::test]
    async fn session_command_sends_to_passive_peer_using_owned_transfer_service() {
        use super::super::{
            task_model::TaskState, task_store::TaskStore, transfer::TransferService,
        };
        let root =
            std::env::temp_dir().join(format!("p2p-session-transfer-{}", rand::random::<u128>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("a-receive")).unwrap();
        std::fs::create_dir(root.join("b-receive")).unwrap();
        let (a_store, _) = TaskStore::open(&root.join("a-state/tasks.json")).unwrap();
        let (b_store, _) = TaskStore::open(&root.join("b-state/tasks.json")).unwrap();
        let a = TransferService::new(a_store, root.join("a-receive"));
        let b = TransferService::new(b_store, root.join("b-receive"));
        let (address, server) = start_local_server().await;
        let ia = Identity::generate();
        let ib = Identity::generate();
        let mut ca = local_config(address);
        ca.transfer = Some(a.clone());
        let mut cb = local_config(address);
        cb.transfer = Some(b.clone());
        let (ha, mut ea) = spawn(ia.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(ib.clone(), cb).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        ha.connect_peer(ib.node_id()).unwrap();
        wait_connected(&mut ea, &[ib.node_id()]).await;
        wait_connected(&mut eb, &[ia.node_id()]).await;
        let bytes = vec![55; 1024 * 1024];
        let source = root.join("selected.bin");
        std::fs::write(&source, &bytes).unwrap();
        ha.send_file(ib.node_id(), source).unwrap();
        time::timeout(Duration::from_secs(10), async {
            let mut changed = a.subscribe();
            loop {
                let tasks = a.snapshot().await.unwrap();
                if tasks.len() == 1 && tasks[0].state() == TaskState::Completed {
                    break;
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(b.snapshot().await.unwrap()[0].state(), TaskState::Completed);
        assert_eq!(
            std::fs::read(root.join("b-receive/selected.bin")).unwrap(),
            bytes
        );
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        let _ = server.await;
        drop((a, b));
        std::fs::remove_dir_all(root).unwrap();
    }
}
