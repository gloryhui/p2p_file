//! Long-lived desktop network session. One task owns signaling events; Quinn owns all UDP reads.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{self, Sleep};
use tracing::{debug, warn};

use crate::discovery::signal::{Candidate, CandidateKind, SignalMessage, SignalingClient};
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::nat::punch::{PunchConfig, PunchToken};
use crate::net::race::{ConnectionGuard, PreparedTransport};
use crate::net::{
    AddressFamily, DesktopNetwork, DesktopNetworkConfig, NetworkPath, prepare_desktop_network,
};
#[cfg(test)]
use crate::transport::handshake::handshake_initiator;
use crate::transport::handshake::handshake_responder;
#[cfg(test)]
use crate::transport::quic::connect as quic_connect;
use crate::transport::quic::{
    ACCEPT_FIRST_BI_STREAM_TIMEOUT, APPLICATION_HANDSHAKE_TIMEOUT, ChannelBinding,
    QUIC_HANDSHAKE_TIMEOUT,
};

use super::remote_auth::{AuthContext, RemoteAuthorization, RemoteVerifier, SecretPassword};
use crate::discovery::short_id::ShortId;

use super::network_state::{
    BeginPeerAttempt, MAX_PENDING_PEERS, NetworkLifecycle, PeerLifecycle, PeerRegistry,
    reconnect_delay, should_initiate_quic,
};

const COMMAND_CAPACITY: usize = 64;
const EVENT_CAPACITY: usize = 128;
const SESSION_INPUT_CAPACITY: usize = 64;
const MAX_CANDIDATES: usize = crate::discovery::signal::MAX_CANDIDATES;
const MAX_RECONNECT_PROBES_PER_PEER: usize = 2;
// Bound waiting across signaling, punching and application authentication.
const TUNNEL_PEER_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
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
    pub remote_auth: Option<RemoteVerifier>,
    pub trusted_devices: Vec<super::trusted_devices::TrustedDevice>,
    pub config_path: Option<std::path::PathBuf>,
    #[cfg(test)]
    pub test_outgoing_password: Option<SecretPassword>,
    pub network: DesktopNetworkConfig,
    pub allowed_forward_targets: Vec<super::config::AllowedForwardTarget>,
    pub tunnel_rules: Vec<super::config::TunnelRule>,
    pub(crate) transfer: Option<super::transfer::TransferService>,
}

impl DesktopSessionConfig {
    pub fn new(signal_server: impl Into<String>) -> Self {
        Self {
            signal_server: signal_server.into(),
            remote_auth: None,
            trusted_devices: Vec::new(),
            config_path: None,
            #[cfg(test)]
            test_outgoing_password: None,
            network: DesktopNetworkConfig::default(),
            allowed_forward_targets: Vec::new(),
            tunnel_rules: Vec::new(),
            transfer: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelRuntimeState {
    WaitingAuthorization,
    Starting,
    Running,
    Stopped,
    Error(String),
}

#[derive(Clone, Debug)]
pub enum SessionEvent {
    NetworkPaths(String),
    PeerPath {
        peer: NodeId,
        generation: u64,
        detail: String,
    },
    TrustedDevicesChanged(Vec<super::trusted_devices::TrustedDevice>),
    Lifecycle(NetworkLifecycle),
    PeerState {
        peer: NodeId,
        generation: u64,
        state: PeerLifecycle,
    },
    SignalIdentityRegistered(NodeId),
    ShortIdRegistered(ShortId),
    ShortIdResolved {
        short_id: ShortId,
        peer: Option<NodeId>,
    },
    Diagnostic(String),
    SelectionQueued {
        peer: NodeId,
        count: usize,
    },
    SpeedRequestEnded {
        peer: NodeId,
    },
    SpeedPhaseCompleted {
        peer: NodeId,
        snapshot: super::speed::SpeedSnapshot,
    },
    TunnelState {
        rule_id: String,
        state: TunnelRuntimeState,
    },
    TunnelError {
        rule_id: String,
        detail: String,
    },
}

#[derive(Clone)]
struct SessionEvents {
    sender: mpsc::Sender<SessionEvent>,
    shutdown: watch::Receiver<bool>,
}

impl SessionEvents {
    fn new(sender: mpsc::Sender<SessionEvent>, shutdown: watch::Receiver<bool>) -> Self {
        Self { sender, shutdown }
    }

    async fn send(&self, event: SessionEvent) -> bool {
        let mut shutdown = self.shutdown.clone();
        if *shutdown.borrow() {
            return false;
        }
        let mut event = Some(event);
        tokio::select! {
            biased;
            _ = shutdown.changed() => false,
            permit = self.sender.reserve() => match permit {
                Ok(permit) => {
                    permit.send(event.take().expect("event is sent only once"));
                    true
                }
                Err(_) => false,
            }
        }
    }
}

#[derive(Clone)]
pub struct DesktopSessionHandle {
    commands: mpsc::Sender<SessionCommand>,
    allowed_forward_targets: watch::Sender<Vec<super::config::AllowedForwardTarget>>,
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
            .recv_timeout(Duration::from_secs(5))
            .is_ok()
            && let Some(thread) = self.thread.get_mut().unwrap().take()
        {
            let _ = thread.join();
        }
    }
}

impl DesktopSessionHandle {
    #[cfg(test)]
    pub fn connect_peer(&self, peer: NodeId) -> std::result::Result<(), String> {
        self.connect_peer_with_password(peer, test_password())
    }
    pub fn connect_peer_with_password(
        &self,
        peer: NodeId,
        password: SecretPassword,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::ConnectAuthenticated { peer, password })
            .map_err(|_| "网络会话暂时无法接收连接请求".into())
    }
    pub fn connect_short_id(
        &self,
        short_id: ShortId,
        password: SecretPassword,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::ConnectShort {
                short_id,
                password: Some(password),
            })
            .map_err(|_| "网络会话暂时无法接收短 ID 查询".into())
    }
    pub fn connect_peer_trusted(&self, peer: NodeId) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::ConnectTrusted(peer))
            .map_err(|_| "连接请求队列不可用".into())
    }
    pub fn connect_short_id_trusted(&self, short_id: ShortId) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::ConnectShort {
                short_id,
                password: None,
            })
            .map_err(|_| "短 ID 查询队列不可用".into())
    }
    pub async fn change_trusted_device(
        &self,
        change: TrustedDeviceChange,
    ) -> std::result::Result<Vec<super::trusted_devices::TrustedDevice>, String> {
        let (done, result) = oneshot::channel();
        self.commands
            .send(SessionCommand::ChangeTrustedDevice { change, done })
            .await
            .map_err(|_| "会话已关闭".to_owned())?;
        result.await.map_err(|_| "会话已关闭".to_owned())?
    }
    pub async fn update_remote_auth(
        &self,
        verifier: RemoteVerifier,
    ) -> std::result::Result<(), String> {
        let (done, finished) = oneshot::channel();
        self.commands
            .send(SessionCommand::UpdateRemoteAuth { verifier, done })
            .await
            .map_err(|_| "网络会话已经关闭".to_owned())?;
        finished.await.map_err(|_| "网络会话已经关闭".into())
    }

    pub fn reconfigure_network(
        &self,
        server: String,
        relay_server: Option<String>,
    ) -> std::result::Result<(), String> {
        if let Some(spec) = &relay_server {
            crate::relay::client::validate_server_spec(spec).map_err(|e| e.to_string())?;
        }
        self.commands
            .try_send(SessionCommand::ReconfigureNetwork {
                server,
                relay_server,
            })
            .map_err(|e| format!("网络配置队列不可用：{e}"))
    }

    pub fn start_tunnel_rule(&self, rule_id: impl Into<String>) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::StartTunnel(rule_id.into()))
            .map_err(|error| format!("无法启动本机转发规则：{error}"))
    }

    pub fn stop_tunnel_rule(&self, rule_id: impl Into<String>) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::StopTunnel(rule_id.into()))
            .map_err(|error| format!("无法停止本机转发规则：{error}"))
    }

    pub fn update_tunnel_settings(
        &self,
        allowed_forward_targets: Vec<super::config::AllowedForwardTarget>,
        tunnel_rules: Vec<super::config::TunnelRule>,
    ) -> std::result::Result<(), String> {
        self.commands
            .try_send(SessionCommand::UpdateTunnelSettings { tunnel_rules })
            .map_err(|error| format!("无法应用端口转发设置：{error}"))?;
        self.allowed_forward_targets
            .send_replace(allowed_forward_targets);
        Ok(())
    }

    /// Apply only revocations from an unsaved draft; grants require successful persistence.
    pub fn restrict_forward_targets(&self, draft: &[super::config::AllowedForwardTarget]) {
        self.allowed_forward_targets.send_modify(|applied| {
            applied.retain_mut(|entry| {
                let Some(next) = draft.iter().find(|next| {
                    next.id == entry.id && next.enabled && next.target == entry.target
                }) else {
                    return false;
                };
                entry
                    .allowed_peers
                    .retain(|peer| next.allowed_peers.contains(peer));
                !entry.allowed_peers.is_empty()
            });
        });
    }

    /// Complete only after the listener task has drained and released its socket.
    pub async fn revoke_tunnel_rule(
        &self,
        rule_id: String,
        delete: bool,
    ) -> std::result::Result<(), String> {
        let (done, stopped) = oneshot::channel();
        self.commands
            .send(SessionCommand::RevokeTunnel {
                rule_id,
                delete,
                done,
            })
            .await
            .map_err(|_| "网络会话已关闭".to_owned())?;
        stopped
            .await
            .map_err(|_| "网络会话在停止规则前退出".to_owned())
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
        direction: super::config::SpeedtestDirection,
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

    /// Wait off the UI thread for structured task cleanup and durable checkpoints.
    pub(super) fn shutdown_and_wait(&self) {
        self.shutdown();
        if self
            .lifetime
            .done
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .is_ok()
            && let Some(thread) = self.lifetime.thread.lock().unwrap().take()
        {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
pub enum TrustedDeviceChange {
    Trust {
        peer: NodeId,
        generation: u64,
        display_name: String,
    },
    Rename {
        peer: NodeId,
        display_name: String,
    },
    Revoke {
        peer: NodeId,
    },
}

/// Shell mutations use a live actor for runtime revocation, or the latest
/// durable configuration after the command channel has closed. Trust is live-only.
pub(super) async fn change_trusted_device(
    session: Option<&DesktopSessionHandle>,
    path: &std::path::Path,
    change: TrustedDeviceChange,
) -> std::result::Result<Vec<super::trusted_devices::TrustedDevice>, String> {
    if let Some(session) = session
        && session.is_running()
    {
        let result = session.change_trusted_device(change.clone()).await;
        if result.is_ok()
            || session.is_running()
            || matches!(change, TrustedDeviceChange::Trust { .. })
        {
            return result;
        }
        // Shutdown may close the channel after the running check. Only a dead
        // actor permits the offline path; a live actor's errors stay failures.
    }
    match change {
        TrustedDeviceChange::Trust { .. } => Err("当前认证会话不可用，未信任设备".into()),
        TrustedDeviceChange::Revoke { peer } => {
            super::config::DesktopConfig::revoke_trusted_device(path, peer)
                .map_err(|e| e.to_string())
        }
        TrustedDeviceChange::Rename { peer, display_name } => {
            super::config::DesktopConfig::rename_trusted_device(path, peer, display_name)
                .map_err(|e| e.to_string())
        }
    }
}
enum SessionCommand {
    RetryCandidates {
        peer: NodeId,
        candidates: Vec<Candidate>,
        token: PunchToken,
    },
    ChangeTrustedDevice {
        change: TrustedDeviceChange,
        done: oneshot::Sender<
            std::result::Result<Vec<super::trusted_devices::TrustedDevice>, String>,
        >,
    },
    StartSpeed {
        peer: NodeId,
        direction: super::config::SpeedtestDirection,
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
    ConnectTrusted(NodeId),
    ConnectAuthenticated {
        peer: NodeId,
        password: SecretPassword,
    },
    ConnectShort {
        short_id: ShortId,
        password: Option<SecretPassword>,
    },
    UpdateRemoteAuth {
        verifier: RemoteVerifier,
        done: oneshot::Sender<()>,
    },
    ReconfigureNetwork {
        server: String,
        relay_server: Option<String>,
    },
    StartTunnel(String),
    StopTunnel(String),
    RevokeTunnel {
        rule_id: String,
        delete: bool,
        done: oneshot::Sender<()>,
    },
    UpdateTunnelSettings {
        tunnel_rules: Vec<super::config::TunnelRule>,
    },
    #[cfg(test)]
    InspectDeferred(NodeId, oneshot::Sender<Option<PunchToken>>),
    #[cfg(test)]
    Inspect(oneshot::Sender<HashMap<NodeId, (u64, quinn::Connection)>>),
}

impl SessionCommand {
    fn business_peer(&self) -> Option<NodeId> {
        match self {
            Self::SendFile { peer, .. }
            | Self::SendDirectory { peer, .. }
            | Self::ResumeTask { peer, .. }
            | Self::StartSpeed { peer, .. } => Some(*peer),
            _ => None,
        }
    }
}

enum SessionInput {
    AuthorizationChanged {
        peer: NodeId,
        generation: u64,
        transport: usize,
    },
    Incoming(AddressFamily, Box<quinn::Incoming>),
    SignalConnected {
        generation: u64,
        result: Result<SignalingClient>,
    },
    PeerPath {
        peer: NodeId,
        generation: u64,
        detail: String,
    },
    PeerProgress {
        peer: NodeId,
        generation: u64,
        state: PeerLifecycle,
    },
    PeerConnected {
        peer: NodeId,
        generation: u64,
        capabilities: u64,
        authorization: RemoteAuthorization,
        control: Option<Box<super::remote_auth::TrustedControl>>,
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

// A lookup alone must preserve a live connection. A matching fresh probe is
// evidence that the peer is actually establishing a new transport. These watches
// use Quinn's existing dispatcher, never a second UDP receive owner.
struct ReconnectProbe {
    generation: u64,
    candidates: Vec<Candidate>,
    token: PunchToken,
    receivers: Vec<crate::transport::quic::PunchProbeReceiver>,
    deadline: Pin<Box<Sleep>>,
}
fn poll_reconnect_probes(
    probes: &mut HashMap<NodeId, VecDeque<ReconnectProbe>>,
    cx: &mut std::task::Context<'_>,
) -> Poll<(NodeId, usize, bool)> {
    for (peer, watches) in probes {
        for (index, watch) in watches.iter_mut().enumerate() {
            for receiver in &mut watch.receivers {
                if let Poll::Ready(Some(_)) = receiver.poll_recv(cx) {
                    return Poll::Ready((*peer, index, true));
                }
            }
            if watch.deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready((*peer, index, false));
            }
        }
    }
    Poll::Pending
}

struct RunningTunnel {
    rule: super::config::TunnelRule,
    shutdown: watch::Sender<bool>,
}

type TunnelTaskResult = (String, std::result::Result<(), String>);
type TunnelTaskJoin = Option<std::result::Result<TunnelTaskResult, tokio::task::JoinError>>;

/// Start a dedicated Tokio runtime so GPUI's UI thread never performs network work.
pub fn spawn(
    identity: Identity,
    config: DesktopSessionConfig,
) -> std::io::Result<(DesktopSessionHandle, mpsc::Receiver<SessionEvent>)> {
    super::trusted_devices::validate(&config.trusted_devices)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
    let session_command_tx = command_tx.clone();
    let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
    let thread_events = event_tx.clone();
    let (allowed_forward_targets, _) = watch::channel(config.allowed_forward_targets.clone());
    let runtime_allowed_targets = allowed_forward_targets.clone();
    let (stop, stopped) = watch::channel(false);
    let event_shutdown = stopped.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
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
                        run_session(
                            identity,
                            config,
                            session_command_tx,
                            command_rx,
                            runtime_allowed_targets,
                            stopped,
                            SessionEvents::new(event_tx.clone(), event_shutdown),
                        )
                        .await;
                        if let Some(transfer) = transfer {
                            let _ = transfer.interrupt_all().await;
                        }
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
            allowed_forward_targets,
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
    command_tx: mpsc::Sender<SessionCommand>,
    mut commands: mpsc::Receiver<SessionCommand>,
    allowed_forward_targets: watch::Sender<Vec<super::config::AllowedForwardTarget>>,
    mut shutdown: watch::Receiver<bool>,
    events: SessionEvents,
) {
    emit_lifecycle(&events, NetworkLifecycle::ConnectingSignal).await;
    let mut network = match prepare_desktop_network(&config.network).await {
        Ok(network) => network,
        Err(error) => {
            for rule in config
                .tunnel_rules
                .iter()
                .filter(|rule| rule.enabled && rule.auto_start)
            {
                let _ = events
                    .send(SessionEvent::TunnelState {
                        rule_id: rule.id.clone(),
                        state: TunnelRuntimeState::Error(error.to_string()),
                    })
                    .await;
            }
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

    let mut remote_verifier = config.remote_auth.clone();
    let auth_context = AuthContext::default();
    let mut trusted_devices = config.trusted_devices.clone();
    auth_context.set_trusted(&trusted_devices);
    let mut authorizations: HashMap<
        NodeId,
        (u64, usize, super::remote_auth::AuthorizationPublisher),
    > = HashMap::new();
    let mut credentials: HashMap<NodeId, SecretPassword> = HashMap::new();
    let mut credential_retries = HashSet::new();
    let mut resolved_short_ids: HashMap<NodeId, ShortId> = HashMap::new();
    let mut short_queries: HashMap<ShortId, (Option<SecretPassword>, time::Instant)> =
        HashMap::new();
    let local_node = identity.node_id();
    let (input_tx, mut inputs) = mpsc::channel(SESSION_INPUT_CAPACITY);
    let mut session_tasks = JoinSet::new();
    let _ = events
        .send(SessionEvent::NetworkPaths(network.diagnostics.join("; ")))
        .await;
    for path in &network.paths {
        let endpoint = path.endpoint.clone();
        let family = path.family;
        let accept_inputs = input_tx.clone();
        session_tasks.spawn(async move {
            accept_incoming_loop(endpoint, family, accept_inputs).await;
        });
    }

    let semaphore = Arc::new(Semaphore::new(MAX_PENDING_PEERS));
    let mut peer_tasks = JoinSet::new();
    let mut peer_attempts: HashMap<NodeId, (PunchToken, tokio::task::AbortHandle)> = HashMap::new();
    let mut deferred_candidates: HashMap<NodeId, (Vec<Candidate>, PunchToken)> = HashMap::new();
    let mut tunnel_tasks: JoinSet<TunnelTaskResult> = JoinSet::new();
    let selection_workers = Arc::new(Semaphore::new(3));
    let selection_jobs = Arc::new(Semaphore::new(64));
    let continuation_jobs = Arc::new(Semaphore::new(3));
    let mut queue_changes = config.transfer.as_ref().map(|service| service.subscribe());
    let mut peers = PeerRegistry::default();
    let mut connections: HashMap<NodeId, (u64, quinn::Connection)> = HashMap::new();
    let mut reconnect_probes: HashMap<NodeId, VecDeque<ReconnectProbe>> = HashMap::new();
    let mut peer_capabilities: HashMap<NodeId, u64> = HashMap::new();
    let mut peer_connection_updates: HashMap<NodeId, watch::Sender<Option<quinn::Connection>>> =
        HashMap::new();
    let mut tunnel_stop_waiters: HashMap<String, Vec<oneshot::Sender<()>>> = HashMap::new();
    let mut tunnel_rules: HashMap<String, super::config::TunnelRule> = config
        .tunnel_rules
        .iter()
        .cloned()
        .map(|rule| (rule.id.clone(), rule))
        .collect();
    let mut waiting_tunnels = HashMap::new();
    let credential_fallback = {
        #[cfg(test)]
        {
            config.test_outgoing_password.is_some()
        }
        #[cfg(not(test))]
        {
            false
        }
    };
    let mut running_tunnels: HashMap<String, RunningTunnel> = HashMap::new();
    let mut restart_after_tunnel_stop = HashSet::new();
    let mut forced_tunnel_errors: HashMap<String, String> = HashMap::new();
    // Candidate sets are bound to the same peer generation as authenticated connections.
    let mut peer_candidates: HashMap<NodeId, (u64, Vec<Candidate>)> = HashMap::new();
    let mut pending_inbound: HashMap<(NodeId, u64), mpsc::Sender<quinn::Incoming>> = HashMap::new();
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

    for rule in config
        .tunnel_rules
        .iter()
        .filter(|rule| rule.enabled && rule.auto_start)
        .cloned()
    {
        start_tunnel_rule(
            rule,
            local_node,
            &connections,
            &peers,
            &credentials,
            credential_fallback,
            &mut waiting_tunnels,
            &peer_capabilities,
            &mut peer_connection_updates,
            &mut running_tunnels,
            &mut tunnel_tasks,
            &command_tx,
            &events,
        )
        .await;
    }

    while !session_shutdown {
        enum Wake {
            Command(Option<SessionCommand>),
            Signal(Result<SignalMessage>),
            Input(Option<SessionInput>),
            Retry,
            ReconnectProbe(NodeId, usize, bool),
            Maintenance,
            QueueChanged,
            Shutdown,
            EventsClosed,
            Task(Option<std::result::Result<(), tokio::task::JoinError>>),
            TunnelTask(TunnelTaskJoin),
        }

        let wake = tokio::select! {
            command = commands.recv() => Wake::Command(command),
            changed = shutdown.changed() => {
                let _ = changed;
                Wake::Shutdown
            }
            _ = events.sender.closed() => Wake::EventsClosed,
            _ = maintenance.tick() => Wake::Maintenance,
            (peer, index, ready) = std::future::poll_fn(|cx| poll_reconnect_probes(&mut reconnect_probes, cx)) => Wake::ReconnectProbe(peer, index, ready),
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
            task = tunnel_tasks.join_next(), if !tunnel_tasks.is_empty() => Wake::TunnelTask(task),
        };

        let wake = match wake {
            Wake::Command(Some(SessionCommand::RetryCandidates {
                peer,
                candidates,
                token,
            })) => Wake::Signal(Ok(SignalMessage::PeerCandidates {
                node_id: peer,
                candidates,
                token,
            })),
            wake => wake,
        };
        // One authorization gate covers outgoing sensitive commands. Local cancellation,
        // settings, and listener startup remain available while a peer is unavailable.
        if let Wake::Command(Some(command)) = &wake
            && let Some(peer) = command.business_peer()
            && (!peers
                .state(peer)
                .is_some_and(PeerLifecycle::outbound_authorized)
                || !connections
                    .get(&peer)
                    .is_some_and(|(_, connection)| connection.close_reason().is_none()))
        {
            let _ = events
                .send(SessionEvent::Diagnostic(
                    "远程访问尚未授权；请先连接设备并完成密码认证".into(),
                ))
                .await;
            if matches!(command, SessionCommand::StartSpeed { .. }) {
                let _ = events.send(SessionEvent::SpeedRequestEnded { peer }).await;
            }
            continue;
        }
        match wake {
            #[cfg(test)]
            Wake::Command(Some(SessionCommand::InspectDeferred(peer, reply))) => {
                let _ = reply.send(deferred_candidates.get(&peer).map(|(_, token)| *token));
            }
            #[cfg(test)]
            Wake::Command(Some(SessionCommand::Inspect(reply))) => {
                let _ = reply.send(connections.clone());
            }
            Wake::Command(Some(SessionCommand::ChangeTrustedDevice { change, done })) => {
                let candidate: std::result::Result<
                    Vec<super::trusted_devices::TrustedDevice>,
                    String,
                > = (|| {
                    let mut devices = trusted_devices.clone();
                    match change {
                        TrustedDeviceChange::Trust {
                            peer,
                            generation,
                            display_name,
                        } => {
                            let valid = peer != local_node
                                && connections.get(&peer).is_some_and(|(g, c)| {
                                    *g == generation && c.close_reason().is_none()
                                })
                                && authorizations.get(&peer).is_some_and(|(g, _, a)| {
                                    *g == generation && {
                                        let a = a.borrow();
                                        a.inbound.password
                                    }
                                });
                            if !valid {
                                return Err("只能明确信任当前已证明知道本机密码的真实设备".into());
                            }
                            if super::trusted_devices::contains(&devices, peer) {
                                return Err("设备已经受信任".into());
                            }
                            devices.push(super::trusted_devices::TrustedDevice::new(
                                peer,
                                display_name,
                                resolved_short_ids.get(&peer).map(ToString::to_string),
                            ));
                        }
                        TrustedDeviceChange::Rename { peer, display_name } => {
                            let device = devices
                                .iter_mut()
                                .find(|d| d.node_id == peer.to_hex())
                                .ok_or("可信设备不存在")?;
                            device.display_name = display_name;
                            device.updated_at = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                .max(device.trusted_at);
                        }
                        TrustedDeviceChange::Revoke { peer } => {
                            devices.retain(|d| d.node_id != peer.to_hex())
                        }
                    }
                    super::trusted_devices::validate(&devices).map_err(|e| e.to_string())?;
                    let path = config
                        .config_path
                        .as_ref()
                        .ok_or("配置路径不可用，未修改可信设备")?;
                    super::config::DesktopConfig::save_trusted_devices(path, devices.clone())
                        .map_err(|e| e.to_string())?;
                    Ok(devices)
                })();
                if let Ok(devices) = &candidate {
                    trusted_devices.clone_from(devices);
                    // Publish revocation synchronously after durable success. No handshake callback can restore it.
                    for (peer, (_, _, rights)) in &authorizations {
                        rights.send_modify(|a| {
                            a.inbound.trusted_device &=
                                super::trusted_devices::contains(devices, *peer)
                        });
                    }
                    auth_context.set_trusted(devices);
                    for (peer, (generation, _, rights)) in &authorizations {
                        let authorization = *rights.borrow();
                        if peers.transition(
                            *peer,
                            *generation,
                            PeerLifecycle::Connected(authorization),
                        ) {
                            emit_peer_state(
                                &events,
                                *peer,
                                *generation,
                                PeerLifecycle::Connected(authorization),
                            )
                            .await;
                        }
                    }
                }
                let _ = done.send(candidate);
            }
            Wake::Input(Some(SessionInput::AuthorizationChanged {
                peer,
                generation,
                transport,
            })) => {
                let Some((g, t, rights)) = authorizations.get(&peer) else {
                    continue;
                };
                if *g != generation
                    || *t != transport
                    || !connections.get(&peer).is_some_and(|(g, c)| {
                        *g == generation && c.stable_id() == transport && c.close_reason().is_none()
                    })
                {
                    continue;
                }
                rights.send_if_modified(|a| {
                    let old = *a;
                    a.inbound.trusted_device &= auth_context.trusts(peer);
                    old != *a
                });
                let authorization = *rights.borrow();
                if !peers.transition(peer, generation, PeerLifecycle::Connected(authorization)) {
                    continue;
                }
                emit_peer_state(
                    &events,
                    peer,
                    generation,
                    PeerLifecycle::Connected(authorization),
                )
                .await;
                if let Some(service) = &config.transfer
                    && let Err(error) = service.revoke_authorization(peer, authorization).await
                {
                    let _ = events
                        .send(SessionEvent::Diagnostic(format!(
                            "授权已撤销；任务中断状态保存失败：{error}"
                        )))
                        .await;
                }
                if authorization.outbound_authorized() {
                    if let Some(updates) = peer_connection_updates.get(&peer) {
                        updates.send_replace(
                            connections.get(&peer).map(|(_, c)| c.clone()).filter(|_| {
                                peer_capabilities
                                    .get(&peer)
                                    .is_some_and(|c| c & super::protocol::CAP_TCP_TUNNEL != 0)
                            }),
                        );
                    }
                    let ready = waiting_tunnels
                        .values()
                        .filter(|r: &&super::config::TunnelRule| r.peer_node_id == peer.to_hex())
                        .cloned()
                        .collect::<Vec<_>>();
                    for rule in ready {
                        start_tunnel_rule(
                            rule,
                            local_node,
                            &connections,
                            &peers,
                            &credentials,
                            credential_fallback,
                            &mut waiting_tunnels,
                            &peer_capabilities,
                            &mut peer_connection_updates,
                            &mut running_tunnels,
                            &mut tunnel_tasks,
                            &command_tx,
                            &events,
                        )
                        .await;
                    }
                } else {
                    if let Some(updates) = peer_connection_updates.get(&peer) {
                        updates.send_replace(None);
                    }
                    for (id, running) in &running_tunnels {
                        if running.rule.peer_node_id == peer.to_hex() {
                            running.shutdown.send_replace(true);
                            waiting_tunnels.insert(id.clone(), running.rule.clone());
                            let _ = events
                                .send(SessionEvent::TunnelState {
                                    rule_id: id.clone(),
                                    state: TunnelRuntimeState::WaitingAuthorization,
                                })
                                .await;
                        }
                    }
                }
            }
            Wake::Command(Some(SessionCommand::RetryCandidates { .. })) => {
                unreachable!("candidate retry normalized before dispatch")
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
                    let live = authorizations[&peer].2.live();
                    let events = events.clone();
                    peer_tasks.spawn(async move {
                        let result = live
                            .guard(false, async {
                                match direction {
                                    super::config::SpeedtestDirection::Both => {
                                        match service
                                            .start_speed(
                                                peer,
                                                super::protocol::SpeedDirection::Upload,
                                                seconds,
                                            )
                                            .await
                                        {
                                            Ok(upload) => {
                                                let _ = events
                                                    .send(SessionEvent::SpeedPhaseCompleted {
                                                        peer,
                                                        snapshot: upload,
                                                    })
                                                    .await;
                                                let download = service
                                                    .start_speed(
                                                        peer,
                                                        super::protocol::SpeedDirection::Download,
                                                        seconds,
                                                    )
                                                    .await;
                                                if let Ok(snapshot) = &download {
                                                    let _ = events
                                                        .send(SessionEvent::SpeedPhaseCompleted {
                                                            peer,
                                                            snapshot: snapshot.clone(),
                                                        })
                                                        .await;
                                                }
                                                download
                                            }
                                            Err(error) => Err(error),
                                        }
                                    }
                                    super::config::SpeedtestDirection::Upload
                                    | super::config::SpeedtestDirection::Download => {
                                        let wire_direction = match direction {
                                            super::config::SpeedtestDirection::Upload => {
                                                super::protocol::SpeedDirection::Upload
                                            }
                                            super::config::SpeedtestDirection::Download => {
                                                super::protocol::SpeedDirection::Download
                                            }
                                            super::config::SpeedtestDirection::Both => {
                                                unreachable!()
                                            }
                                        };
                                        let result = service
                                            .start_speed(peer, wire_direction, seconds)
                                            .await;
                                        if let Ok(snapshot) = &result {
                                            let _ = events
                                                .send(SessionEvent::SpeedPhaseCompleted {
                                                    peer,
                                                    snapshot: snapshot.clone(),
                                                })
                                                .await;
                                        }
                                        result
                                    }
                                }
                            })
                            .await;
                        if let Err(error) = result {
                            let _ = events
                                .send(SessionEvent::Diagnostic(error.to_string()))
                                .await;
                        }
                        let _ = events.send(SessionEvent::SpeedRequestEnded { peer }).await;
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
                let live = authorizations[&peer].2.live();
                let selection_workers = selection_workers.clone();
                let events = events.clone();
                peer_tasks.spawn(async move {
                    let _permit = permit;
                    let result = live
                        .guard(false, async {
                            match command {
                                SessionCommand::SendFile { source, .. } => {
                                    let _worker =
                                        selection_workers.clone().acquire_owned().await.map_err(
                                            |_| super::transfer_files::failure("扫描任务已关闭"),
                                        )?;
                                    service.select_file(peer, source).await?;
                                    let _ = events
                                        .send(SessionEvent::SelectionQueued { peer, count: 1 })
                                        .await;
                                    Ok(())
                                }
                                SessionCommand::SendDirectory { source, .. } => {
                                    let _worker =
                                        selection_workers.clone().acquire_owned().await.map_err(
                                            |_| super::transfer_files::failure("扫描任务已关闭"),
                                        )?;
                                    let ids = service.select_directory(peer, source).await?;
                                    let _ = events
                                        .send(SessionEvent::SelectionQueued {
                                            peer,
                                            count: ids.len(),
                                        })
                                        .await;
                                    Ok(())
                                }
                                SessionCommand::ResumeTask { id, .. } => {
                                    let record = service.task(id.clone()).await?;
                                    if record.direction() == super::task_model::TaskDirection::Send
                                    {
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
                        })
                        .await;
                    if let Err(error) = result {
                        let _ = events
                            .send(SessionEvent::Diagnostic(error.to_string()))
                            .await;
                    }
                });
            }
            Wake::Command(Some(SessionCommand::ConnectAuthenticated { peer, password })) => {
                if credentials.len() >= super::network_state::MAX_PEERS
                    && !credentials.contains_key(&peer)
                {
                    let _ = events
                        .send(SessionEvent::Diagnostic(
                            "连接凭据数量已达上限，请重启会话后重试".into(),
                        ))
                        .await;
                    continue;
                }
                let same_credential = credentials.get(&peer) == Some(&password);
                #[cfg(test)]
                let same_credential = same_credential
                    || (!credentials.contains_key(&peer)
                        && config.test_outgoing_password.as_ref() == Some(&password));
                let reuse_authorized = same_credential
                    && peers.state(peer).is_some_and(|state| {
                        (state.is_active() && !state.is_connected())
                            || (state.outbound_authorized()
                                && connections
                                    .get(&peer)
                                    .is_some_and(|(_, c)| c.close_reason().is_none()))
                    });
                credentials.insert(peer, password);
                if peers
                    .state(peer)
                    .is_some_and(|state| state.is_active() && !state.is_connected())
                {
                    // A pending lookup will read the new credential when it starts.
                    // A running exchange finishes first, then retries on a fresh transport.
                    // Neither path creates a competing punch token for the same attempt.
                    if !same_credential && peer_attempts.contains_key(&peer) {
                        credential_retries.insert(peer);
                    }
                    continue;
                }
                if !reuse_authorized {
                    if network.relay.is_some() {
                        deferred_candidates.remove(&peer);
                    }
                    if let Some((_, attempt)) = peer_attempts.remove(&peer) {
                        attempt.abort();
                    }
                    reconnect_probes.remove(&peer);
                    // Explicit credentials upgrade rights on a fresh transport; never copy
                    // the previous generation's authorization into a new exchange.
                    if let Some((generation, connection)) = connections.remove(&peer) {
                        if let Some((_, _, rights)) = authorizations.remove(&peer) {
                            rights.send_replace(RemoteAuthorization::default());
                        }
                        retire_peer_listeners(
                            peer,
                            &running_tunnels,
                            &mut waiting_tunnels,
                            &mut restart_after_tunnel_stop,
                        );
                        connection.close(0u32.into(), b"new explicit remote credential");
                        peer_capabilities.remove(&peer);
                        if let Some(service) = config.transfer.as_ref() {
                            service.set_peer_flow_support(peer, false);
                        }
                        if let Some(updates) = peer_connection_updates.get(&peer) {
                            updates.send_replace(None);
                        }
                        peers.transition(peer, generation, PeerLifecycle::Disconnected);
                        emit_peer_state(&events, peer, generation, PeerLifecycle::Disconnected)
                            .await;
                    }
                    if peers.state(peer).is_some_and(PeerLifecycle::is_active)
                        && let Some(generation) = peers.generation(peer)
                    {
                        pending_inbound.remove(&(peer, generation));
                        peers.transition(peer, generation, PeerLifecycle::Disconnected);
                    }
                }
                let _ = command_tx.try_send(SessionCommand::ConnectPeer(peer));
            }
            Wake::Command(Some(SessionCommand::ConnectShort { short_id, password })) => {
                if short_queries.len() >= MAX_PENDING_PEERS || short_queries.contains_key(&short_id)
                {
                    let _ = events
                        .send(SessionEvent::Diagnostic(
                            "短 ID 查询已在进行或达到上限".into(),
                        ))
                        .await;
                    continue;
                }
                if let Some(client) = signal.as_ref()
                    && client.request_short_lookup(short_id).await.is_ok()
                {
                    short_queries.insert(short_id, (password, time::Instant::now()));
                    let _ = events
                        .send(SessionEvent::Diagnostic("正在查询短设备 ID".into()))
                        .await;
                    continue;
                }
                let _ = events
                    .send(SessionEvent::Diagnostic(
                        "信令尚未就绪，无法查询短设备 ID".into(),
                    ))
                    .await;
            }
            Wake::Command(Some(SessionCommand::ConnectTrusted(peer))) => {
                let had_password = credentials.remove(&peer).is_some();
                if peers
                    .state(peer)
                    .is_some_and(|state| state.is_active() && !state.is_connected())
                {
                    if had_password && peer_attempts.contains_key(&peer) {
                        credential_retries.insert(peer);
                    }
                    continue;
                }
                let _ = command_tx.try_send(SessionCommand::ConnectPeer(peer));
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
                        // An explicit Connect can discover a restarted peer before Quinn's
                        // old connection idle timeout. Unchanged candidates preserve it.
                        if peers.state(peer).is_some_and(PeerLifecycle::is_connected)
                            && let Some(client) = signal.as_ref()
                        {
                            let message = if client.request_lookup(peer).await.is_ok() {
                                "已请求核对对端地址；现有连接在映射不变时继续使用"
                            } else {
                                "信令查询暂时不可用；现有直连仍保留，请稍后重试连接"
                            };
                            let _ = events.send(SessionEvent::Diagnostic(message.into())).await;
                            continue;
                        }
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
            Wake::Command(Some(
                command @ (SessionCommand::ReconfigureNetwork { .. }
                | SessionCommand::UpdateRemoteAuth { .. }),
            )) => {
                let mut auth_updated = None;
                match command {
                    SessionCommand::ReconfigureNetwork {
                        server,
                        relay_server,
                    } => {
                        signal_server = server;
                        credentials.clear();
                        if let Some(old) = &network.relay {
                            old.endpoints.close();
                        }
                        network.relay = relay_server.map(|server| {
                            crate::relay::client::Fallback::new(server, config.network.families)
                        });
                    }
                    SessionCommand::UpdateRemoteAuth { verifier, done } => {
                        credentials.clear();
                        remote_verifier = Some(verifier);
                        auth_updated = Some(done);
                    }
                    _ => unreachable!(),
                }
                short_queries.clear();
                credential_retries.clear();
                for (_, (_, _, rights)) in authorizations.drain() {
                    rights.send_replace(RemoteAuthorization::default());
                }
                peer_candidates.clear();
                reconnect_probes.clear();
                let signal_changed = auth_updated.is_none();
                if signal_changed {
                    signal_generation = signal_generation.wrapping_add(1);
                }
                // An explicit server change supersedes this generation's attempts
                // and authenticated peers. An involuntary outage below preserves them.
                for (_, (_, connection)) in connections.drain() {
                    connection.close(0u32.into(), b"desktop network reconfigured");
                }
                peer_attempts.clear();
                deferred_candidates.clear();
                peer_tasks.abort_all();
                while peer_tasks.join_next().await.is_some() {}
                if let Some(service) = &config.transfer {
                    let _ = service.interrupt_all().await;
                }
                pending_inbound.clear();
                queued_lookups.clear();
                peer_capabilities.clear();
                for update in peer_connection_updates.values() {
                    update.send_replace(None);
                }
                for peer in peer_connection_updates.keys() {
                    emit_peer_tunnels_starting(*peer, &running_tunnels, &events).await;
                }
                for (id, running) in &running_tunnels {
                    waiting_tunnels.insert(id.clone(), running.rule.clone());
                    restart_after_tunnel_stop.insert(id.clone());
                    running.shutdown.send_replace(true);
                }
                let tunnel_peers = running_tunnels
                    .values()
                    .filter_map(|running| NodeId::from_hex(&running.rule.peer_node_id).ok())
                    .collect::<HashSet<_>>();
                for peer in tunnel_peers {
                    let _ = command_tx.try_send(SessionCommand::ConnectPeer(peer));
                }
                for (peer, generation) in peers.active_peers() {
                    let state = PeerLifecycle::Failed(
                        if signal_changed {
                            "网络配置已更改，请重新连接"
                        } else {
                            "远程密码已更改，会话授权已撤销，请重新连接"
                        }
                        .into(),
                    );
                    if peers.transition(peer, generation, state.clone()) {
                        emit_peer_state(&events, peer, generation, state).await;
                    }
                }
                if signal_changed {
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
                for rule in waiting_tunnels.values() {
                    if let Ok(peer) = NodeId::from_hex(&rule.peer_node_id) {
                        let _ = command_tx.try_send(SessionCommand::ConnectPeer(peer));
                    }
                }
                if let Some(done) = auth_updated {
                    let _ = done.send(());
                }
            }
            Wake::Command(Some(SessionCommand::StartTunnel(rule_id))) => {
                let Some(rule) = tunnel_rules.get(&rule_id).cloned() else {
                    let _ = events
                        .send(SessionEvent::TunnelState {
                            rule_id,
                            state: TunnelRuntimeState::Error("转发规则不存在".into()),
                        })
                        .await;
                    continue;
                };
                start_tunnel_rule(
                    rule,
                    local_node,
                    &connections,
                    &peers,
                    &credentials,
                    credential_fallback,
                    &mut waiting_tunnels,
                    &peer_capabilities,
                    &mut peer_connection_updates,
                    &mut running_tunnels,
                    &mut tunnel_tasks,
                    &command_tx,
                    &events,
                )
                .await;
            }
            Wake::Command(Some(SessionCommand::StopTunnel(rule_id))) => {
                waiting_tunnels.remove(&rule_id);
                restart_after_tunnel_stop.remove(&rule_id);
                if let Some(running) = running_tunnels.get(&rule_id) {
                    running.shutdown.send_replace(true);
                } else {
                    let _ = events
                        .send(SessionEvent::TunnelState {
                            rule_id,
                            state: TunnelRuntimeState::Stopped,
                        })
                        .await;
                }
            }
            Wake::Command(Some(SessionCommand::RevokeTunnel {
                rule_id,
                delete,
                done,
            })) => {
                waiting_tunnels.remove(&rule_id);
                if delete {
                    tunnel_rules.remove(&rule_id);
                } else if let Some(rule) = tunnel_rules.get_mut(&rule_id) {
                    rule.enabled = false;
                }
                restart_after_tunnel_stop.remove(&rule_id);
                if let Some(running) = running_tunnels.get(&rule_id) {
                    running.shutdown.send_replace(true);
                    tunnel_stop_waiters.entry(rule_id).or_default().push(done);
                } else {
                    let _ = done.send(());
                }
            }
            Wake::Command(Some(SessionCommand::UpdateTunnelSettings {
                tunnel_rules: next_rules,
            })) => {
                let next_rules = next_rules
                    .into_iter()
                    .map(|rule| (rule.id.clone(), rule))
                    .collect::<HashMap<_, _>>();
                let to_stop = running_tunnels
                    .iter()
                    .filter(|(id, running)| next_rules.get(*id) != Some(&running.rule))
                    .map(|(id, running)| {
                        let restart = next_rules.get(id).is_some_and(|rule| rule.enabled);
                        (id.clone(), restart, running.shutdown.clone())
                    })
                    .collect::<Vec<_>>();
                for (id, restart, shutdown) in to_stop {
                    if restart {
                        restart_after_tunnel_stop.insert(id.clone());
                    } else {
                        restart_after_tunnel_stop.remove(&id);
                    }
                    shutdown.send_replace(true);
                }
                tunnel_rules = next_rules;
                let cancelled = waiting_tunnels
                    .iter()
                    .filter(|(id, waiting)| tunnel_rules.get(*id) != Some(*waiting))
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for id in cancelled {
                    waiting_tunnels.remove(&id);
                    let _ = events
                        .send(SessionEvent::TunnelState {
                            rule_id: id,
                            state: TunnelRuntimeState::Stopped,
                        })
                        .await;
                }
                let auto_start = tunnel_rules
                    .values()
                    .filter(|rule| rule.enabled && rule.auto_start)
                    .filter(|rule| !running_tunnels.contains_key(&rule.id))
                    .filter(|rule| !restart_after_tunnel_stop.contains(&rule.id))
                    .cloned()
                    .collect::<Vec<_>>();
                for rule in auto_start {
                    start_tunnel_rule(
                        rule,
                        local_node,
                        &connections,
                        &peers,
                        &credentials,
                        credential_fallback,
                        &mut waiting_tunnels,
                        &peer_capabilities,
                        &mut peer_connection_updates,
                        &mut running_tunnels,
                        &mut tunnel_tasks,
                        &command_tx,
                        &events,
                    )
                    .await;
                }
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
                    if peers
                        .state(node_id)
                        .is_some_and(|state| state.is_active() && !state.is_connected())
                        && let Some((current_token, _)) = peer_attempts.get(&node_id)
                    {
                        // A new lookup can arrive before the old auth failure callback.
                        // Retain its authenticated signaling candidates rather than losing
                        // the only matching punch token or cancelling an active transport.
                        if *current_token != token {
                            deferred_candidates.insert(node_id, (candidates, token));
                        }
                        continue;
                    }
                    let canonical = canonical_candidates(&candidates);
                    if network.relay.is_some()
                        && peers
                            .state(node_id)
                            .is_some_and(PeerLifecycle::is_connected)
                    {
                        // A real pairing may precede the old transport's close callback.
                        // Direct probes cannot confirm an unchanged blackhole candidate on
                        // a Relay path. Preserve the offer without replacing any live winner;
                        // only actual closure may consume it for a fresh generation.
                        deferred_candidates.insert(node_id, (candidates.clone(), token));
                    }
                    if peers
                        .state(node_id)
                        .is_some_and(PeerLifecycle::is_connected)
                        && peer_candidates
                            .get(&node_id)
                            .is_some_and(|(generation, old)| {
                                peers.is_current(node_id, *generation) && *old == canonical
                            })
                    {
                        let _ = events
                            .send(SessionEvent::Diagnostic(
                                "地址核对完毕，现有认证连接继续使用".into(),
                            ))
                            .await;
                        if candidates.len() <= MAX_CANDIDATES
                            && !network.reachable_candidates(&candidates).is_empty()
                            && connections
                                .get(&node_id)
                                .is_some_and(|(_, c)| c.close_reason().is_none())
                        {
                            let generation = peers.generation(node_id).unwrap();
                            let watches = reconnect_probes.entry(node_id).or_default();
                            if watches.len() >= MAX_RECONNECT_PROBES_PER_PEER {
                                watches.pop_front();
                            }
                            let receivers = network
                                .paths
                                .iter()
                                .filter(|path| !path.reachable_candidates(&candidates).is_empty())
                                .filter_map(|path| {
                                    path.punch_socket
                                        .register_peer_probe(&token, node_id, generation)
                                        .ok()
                                })
                                .collect::<Vec<_>>();
                            if !receivers.is_empty() {
                                watches.push_back(ReconnectProbe {
                                    generation,
                                    candidates,
                                    token,
                                    receivers,
                                    deadline: Box::pin(time::sleep(
                                        PEER_PUNCH_CONFIG.interval * PEER_PUNCH_CONFIG.attempts,
                                    )),
                                });
                            }
                            continue;
                        }
                    }
                    if peers
                        .state(node_id)
                        .is_some_and(PeerLifecycle::is_connected)
                        && (connections
                            .get(&node_id)
                            .is_some_and(|(_, connection)| connection.close_reason().is_some())
                            || peer_candidates
                                .get(&node_id)
                                .is_some_and(|(generation, old)| {
                                    peers.is_current(node_id, *generation) && *old != canonical
                                }))
                        && !network.reachable_candidates(&candidates).is_empty()
                    {
                        // Changed mapping or a closed transport whose callback is still queued.
                        // Retire only this generation; new Punch/QUIC/identity/capability
                        // checks remain mandatory. Old closure callbacks are fenced.
                        if let Some((generation, connection)) = connections.remove(&node_id) {
                            if let Some((_, _, rights)) = authorizations.remove(&node_id) {
                                rights.send_replace(RemoteAuthorization::default());
                            }
                            retire_peer_listeners(
                                node_id,
                                &running_tunnels,
                                &mut waiting_tunnels,
                                &mut restart_after_tunnel_stop,
                            );
                            connection.close(0u32.into(), b"peer mapping changed");
                            peer_capabilities.remove(&node_id);
                            if let Some(service) = config.transfer.as_ref() {
                                service.set_peer_flow_support(node_id, false);
                            }
                            if let Some(updates) = peer_connection_updates.get(&node_id) {
                                updates.send_replace(None);
                            }
                            emit_peer_tunnels_starting(node_id, &running_tunnels, &events).await;
                            if peers.transition(node_id, generation, PeerLifecycle::Disconnected) {
                                emit_peer_state(
                                    &events,
                                    node_id,
                                    generation,
                                    PeerLifecycle::Disconnected,
                                )
                                .await;
                            }
                        }
                        peer_candidates.remove(&node_id);
                        reconnect_probes.remove(&node_id);
                    }
                    if let Some((generation, attempt)) = start_peer_attempt(
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
                        auth_context.clone(),
                        remote_verifier.clone(),
                        credentials.get(&node_id).cloned().or_else(|| {
                            #[cfg(test)]
                            {
                                config.test_outgoing_password.clone()
                            }
                            #[cfg(not(test))]
                            {
                                None
                            }
                        }),
                    )
                    .await
                    {
                        peer_attempts.insert(node_id, (token, attempt));
                        peer_candidates.insert(node_id, (generation, canonical));
                    }
                }
                SignalMessage::ShortResolved { short_id, node_id } => {
                    if let Some((password, _)) = short_queries.remove(&short_id) {
                        let _ = events
                            .send(SessionEvent::ShortIdResolved {
                                short_id,
                                peer: node_id,
                            })
                            .await;
                        if let Some(peer) = node_id {
                            if resolved_short_ids.len() < super::network_state::MAX_PEERS
                                || resolved_short_ids.contains_key(&peer)
                            {
                                resolved_short_ids.insert(peer, short_id);
                            }
                            if peer != local_node
                                && (credentials.len() < super::network_state::MAX_PEERS
                                    || credentials.contains_key(&peer))
                            {
                                let _ = command_tx.try_send(match password {
                                    Some(password) => {
                                        SessionCommand::ConnectAuthenticated { peer, password }
                                    }
                                    None => SessionCommand::ConnectTrusted(peer),
                                });
                            }
                        } else {
                            let _ = events
                                .send(SessionEvent::Diagnostic(
                                    "短 ID 无法解析或查询暂时受限".into(),
                                ))
                                .await;
                        }
                    }
                }
                SignalMessage::Error { reason } => {
                    let detail = format!("信令查询失败：{reason}");
                    for (peer, generation) in peers.pending_peers() {
                        if peers.transition(peer, generation, PeerLifecycle::Failed(detail.clone()))
                        {
                            fail_peer_tunnels(
                                peer,
                                &detail,
                                &running_tunnels,
                                &mut forced_tunnel_errors,
                            );
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
                        if let Some(short_id) = client.short_id() {
                            let _ = events.send(SessionEvent::ShortIdRegistered(short_id)).await;
                        }
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
            Wake::Input(Some(SessionInput::Incoming(family, incoming))) => {
                let incoming = *incoming;
                let remote = incoming.remote_address();
                let Some((peer, generation)) = network
                    .path(family)
                    .and_then(|path| path.punch_socket.claim_authorized_peer(remote))
                    .or_else(|| pending_ipv6_route(remote, local_node, &peers, &peer_candidates))
                else {
                    incoming.refuse();
                    continue;
                };
                if !peers.is_current(peer, generation) || should_initiate_quic(local_node, peer) {
                    incoming.refuse();
                    continue;
                }
                let Some(waiting) = pending_inbound.get(&(peer, generation)) else {
                    incoming.refuse();
                    continue;
                };
                if let Err(error) = waiting.try_send(incoming) {
                    error.into_inner().refuse();
                }
            }
            Wake::Input(Some(SessionInput::PeerPath {
                peer,
                generation,
                detail,
            })) => {
                if peers.is_current(peer, generation)
                    && !peers.state(peer).is_some_and(PeerLifecycle::is_connected)
                {
                    let _ = events
                        .send(SessionEvent::PeerPath {
                            peer,
                            generation,
                            detail,
                        })
                        .await;
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
                capabilities,
                mut authorization,
                control,
                connection,
            })) => {
                pending_inbound.remove(&(peer, generation));
                if !transport_can_publish(&peers, peer, generation, &connection) {
                    continue;
                }
                let _ = events
                    .send(SessionEvent::PeerPath {
                        peer,
                        generation,
                        detail: format!(
                            "对端 {} 已认证 transport：{}",
                            peer.short(),
                            network.transport_label(&connection)
                        ),
                    })
                    .await;
                peer_attempts.remove(&peer);
                if credential_retries.remove(&peer) {
                    connection.close(
                        0u32.into(),
                        b"new explicit credential after pending attempt",
                    );
                    peers.transition(peer, generation, PeerLifecycle::Disconnected);
                    let retry = deferred_candidates.remove(&peer).map_or(
                        SessionCommand::ConnectPeer(peer),
                        |(candidates, token)| SessionCommand::RetryCandidates {
                            peer,
                            candidates,
                            token,
                        },
                    );
                    let _ = command_tx.try_send(retry);
                    continue;
                }
                if let Some((candidates, token)) = deferred_candidates.remove(&peer) {
                    let _ = command_tx.try_send(SessionCommand::RetryCandidates {
                        peer,
                        candidates,
                        token,
                    });
                }
                authorization.inbound.trusted_device &= auth_context.trusts(peer);
                let rights = super::remote_auth::AuthorizationPublisher::new(authorization);
                let live = rights.subscribe();
                let transport = connection.stable_id();
                if let Some((_, _, old)) =
                    authorizations.insert(peer, (generation, transport, rights.clone()))
                {
                    old.send_replace(RemoteAuthorization::default());
                }
                if let Some(control) = control {
                    let control_rights = rights.clone();
                    peer_tasks.spawn(async move {
                        (*control).run(control_rights).await;
                    });
                }
                let changed_inputs = input_tx.clone();
                let mut changed = live.clone();
                let changed_connection = connection.clone();
                peer_tasks.spawn(async move {
                    loop {
                        tokio::select! {
                            _ = changed_connection.closed() => break,
                            result = changed.changed() => {
                                if result.is_err() { break; }
                                if changed_inputs.send(SessionInput::AuthorizationChanged { peer, generation, transport }).await.is_err() { break; }
                            }
                        }
                    }
                });
                let live = rights.live();
                if !peers.transition(peer, generation, PeerLifecycle::Connected(authorization)) {
                    connection.close(0u32.into(), b"stale peer generation");
                    continue;
                }
                if let Some(short) = resolved_short_ids.get(&peer) {
                    let mut updated = trusted_devices.clone();
                    if let Some(device) = updated.iter_mut().find(|d| {
                        d.node_id == peer.to_hex()
                            && d.last_short_id.as_deref() != Some(short.to_string().as_str())
                    }) {
                        device.last_short_id = Some(short.to_string());
                        device.updated_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                            .max(device.trusted_at);
                        if let Some(path) = &config.config_path {
                            match super::config::DesktopConfig::save_trusted_devices(
                                path,
                                updated.clone(),
                            ) {
                                Ok(()) => {
                                    trusted_devices = updated;
                                    let _ = events
                                        .send(SessionEvent::TrustedDevicesChanged(
                                            trusted_devices.clone(),
                                        ))
                                        .await;
                                }
                                Err(error) => {
                                    let _ = events
                                        .send(SessionEvent::Diagnostic(format!(
                                            "可信设备 Short ID 备注未保存：{error}"
                                        )))
                                        .await;
                                }
                            }
                        }
                    }
                }
                if capabilities & super::protocol::CAP_TRUSTED_DEVICE_AUTH == 0 {
                    let _ = events
                        .send(SessionEvent::Diagnostic(
                            "对端不支持可信设备授权；本次仅使用密码认证".into(),
                        ))
                        .await;
                }
                reconnect_probes.remove(&peer);
                connections.insert(peer, (generation, connection.clone()));
                peer_capabilities.insert(peer, capabilities);
                if let Some(service) = config.transfer.as_ref() {
                    service.set_peer_flow_support(
                        peer,
                        capabilities & super::protocol::CAP_FILE_FLOW != 0,
                    );
                }
                if capabilities & super::protocol::CAP_TCP_TUNNEL == 0 {
                    let incompatible_rules = running_tunnels
                        .iter()
                        .filter(|(_, running)| running.rule.peer_node_id == peer.to_hex())
                        .map(|(id, running)| (id.clone(), running.shutdown.clone()))
                        .collect::<Vec<_>>();
                    for (rule_id, stop) in incompatible_rules {
                        let detail =
                            format!("对端设备 {} 不支持 TCP 隧道，请升级桌面端", peer.short());
                        forced_tunnel_errors.insert(rule_id.clone(), detail.clone());
                        stop.send_replace(true);
                        let _ = events
                            .send(SessionEvent::TunnelError { rule_id, detail })
                            .await;
                    }
                }
                peer_connection_updates
                    .entry(peer)
                    .or_insert_with(|| watch::channel(None).0)
                    .send_replace(
                        (authorization.outbound_authorized()
                            && capabilities & super::protocol::CAP_TCP_TUNNEL != 0)
                            .then(|| connection.clone()),
                    );
                emit_peer_state(
                    &events,
                    peer,
                    generation,
                    PeerLifecycle::Connected(authorization),
                )
                .await;
                emit_lifecycle(&events, NetworkLifecycle::Connected { peer }).await;
                if authorization.outbound_authorized() {
                    let ready = waiting_tunnels
                        .keys()
                        .filter_map(|id| tunnel_rules.get(id))
                        .filter(|r| {
                            r.enabled && NodeId::from_hex(&r.peer_node_id).ok() == Some(peer)
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for rule in ready {
                        start_tunnel_rule(
                            rule,
                            local_node,
                            &connections,
                            &peers,
                            &credentials,
                            credential_fallback,
                            &mut waiting_tunnels,
                            &peer_capabilities,
                            &mut peer_connection_updates,
                            &mut running_tunnels,
                            &mut tunnel_tasks,
                            &command_tx,
                            &events,
                        )
                        .await;
                    }
                }
                if let Some(service) = config.transfer.clone() {
                    let transfer_connection = connection.clone();
                    let transfer_events = events.clone();
                    let allowed_forward_targets = allowed_forward_targets.subscribe();
                    peer_tasks.spawn(async move {
                        if service
                            .serve_peer_with_speed_and_targets(
                                transfer_connection,
                                peer,
                                local_node,
                                live,
                                allowed_forward_targets,
                            )
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
                } else {
                    let tunnel_connection = connection.clone();
                    let allowed_forward_targets = allowed_forward_targets.subscribe();
                    peer_tasks.spawn(async move {
                        if let Err(error) = super::tunnel::serve_peer(
                            tunnel_connection,
                            peer,
                            live,
                            allowed_forward_targets,
                        )
                        .await
                        {
                            debug!(peer = %peer.short(), %error, "TCP tunnel peer service ended");
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
                if peers.is_current(peer, generation) {
                    peer_attempts.remove(&peer);
                    let candidate = deferred_candidates.remove(&peer);
                    let credential_retry = credential_retries.remove(&peer);
                    if candidate.is_some() || credential_retry {
                        peers.transition(peer, generation, PeerLifecycle::Failed(detail));
                        let retry = candidate.map_or(
                            SessionCommand::ConnectPeer(peer),
                            |(candidates, token)| SessionCommand::RetryCandidates {
                                peer,
                                candidates,
                                token,
                            },
                        );
                        let _ = command_tx.try_send(retry);
                        continue;
                    }
                }
                if peers.transition(peer, generation, PeerLifecycle::Failed(detail.clone())) {
                    peer_candidates.remove(&peer);
                    fail_peer_tunnels(peer, &detail, &running_tunnels, &mut forced_tunnel_errors);
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
                    if let Some((_, _, rights)) = authorizations.remove(&peer) {
                        rights.send_replace(RemoteAuthorization::default());
                    }
                    peer_capabilities.remove(&peer);
                    if let Some(service) = config.transfer.as_ref() {
                        service.set_peer_flow_support(peer, false);
                    }
                    if let Some(updates) = peer_connection_updates.get(&peer) {
                        updates.send_replace(None);
                    }
                    emit_peer_tunnels_starting(peer, &running_tunnels, &events).await;
                    for (id, running) in &running_tunnels {
                        if running.rule.peer_node_id == peer.to_hex() {
                            waiting_tunnels.insert(id.clone(), running.rule.clone());
                            restart_after_tunnel_stop.insert(id.clone());
                            running.shutdown.send_replace(true);
                        }
                    }
                    let affected_rules = running_tunnels
                        .values()
                        .filter(|running| running.rule.peer_node_id == peer.to_hex())
                        .map(|running| running.rule.id.clone())
                        .collect::<Vec<_>>();
                    for rule_id in &affected_rules {
                        let _ = events
                            .send(SessionEvent::TunnelError {
                                rule_id: rule_id.clone(),
                                detail: format!("对端 {} 已断开：{detail}", peer.short()),
                            })
                            .await;
                    }
                    if !affected_rules.is_empty() {
                        let _ = command_tx.try_send(SessionCommand::ConnectPeer(peer));
                    }
                    peer_candidates.remove(&peer);
                    let relay_retry = if network.relay.is_some() {
                        reconnect_probes.remove(&peer); // retire old token/source routes first
                        deferred_candidates.remove(&peer)
                    } else {
                        None
                    };
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
                    if let Some((candidates, token)) = relay_retry {
                        let _ = command_tx.try_send(SessionCommand::RetryCandidates {
                            peer,
                            candidates,
                            token,
                        });
                    }
                }
            }
            Wake::ReconnectProbe(peer, index, ready) => {
                let Some(probe) = reconnect_probes
                    .get_mut(&peer)
                    .and_then(|w| w.remove(index))
                else {
                    continue;
                };
                let ReconnectProbe {
                    generation,
                    candidates,
                    token,
                    receivers,
                    ..
                } = probe;
                drop(receivers); // Synchronously revoke the old generation's source/token route.
                if !ready
                    || !peers.is_current(peer, generation)
                    || !matches!(
                        peers.state(peer),
                        Some(PeerLifecycle::Connected(_) | PeerLifecycle::Disconnected)
                    )
                {
                    continue;
                }
                reconnect_probes.remove(&peer);
                if let Some((_, old)) = connections.remove(&peer) {
                    if let Some((_, _, rights)) = authorizations.remove(&peer) {
                        rights.send_replace(RemoteAuthorization::default());
                    }
                    retire_peer_listeners(
                        peer,
                        &running_tunnels,
                        &mut waiting_tunnels,
                        &mut restart_after_tunnel_stop,
                    );
                    old.close(0u32.into(), b"peer requested fresh authenticated transport");
                    peer_capabilities.remove(&peer);
                    if let Some(service) = config.transfer.as_ref() {
                        service.set_peer_flow_support(peer, false);
                    }
                    if let Some(updates) = peer_connection_updates.get(&peer) {
                        updates.send_replace(None);
                    }
                    emit_peer_tunnels_starting(peer, &running_tunnels, &events).await;
                    peers.transition(peer, generation, PeerLifecycle::Disconnected);
                    emit_peer_state(&events, peer, generation, PeerLifecycle::Disconnected).await;
                }
                let canonical = canonical_candidates(&candidates);
                if let Some((generation, attempt)) = start_peer_attempt(
                    peer,
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
                    auth_context.clone(),
                    remote_verifier.clone(),
                    credentials.get(&peer).cloned().or_else(|| {
                        #[cfg(test)]
                        {
                            config.test_outgoing_password.clone()
                        }
                        #[cfg(not(test))]
                        {
                            None
                        }
                    }),
                )
                .await
                {
                    peer_attempts.insert(peer, (token, attempt));
                    peer_candidates.insert(peer, (generation, canonical));
                }
            }
            Wake::QueueChanged => {}
            Wake::Maintenance => {
                reconnect_probes.retain(|peer, watches| {
                    watches.retain(|watch| {
                        peers.is_current(*peer, watch.generation) && !watch.deadline.is_elapsed()
                    });
                    !watches.is_empty()
                });
                let expired = short_queries
                    .iter()
                    .filter(|(_, (_, started))| {
                        started.elapsed() >= super::network_state::PEER_LOOKUP_TIMEOUT
                    })
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>();
                for short_id in expired {
                    short_queries.remove(&short_id);
                    let _ = events
                        .send(SessionEvent::ShortIdResolved {
                            short_id,
                            peer: None,
                        })
                        .await;
                }
                for (peer, generation) in peers.expired_lookups(time::Instant::now()) {
                    let state = PeerLifecycle::Failed("目标离线或候选等待超时，请重试连接".into());
                    if peers.transition(peer, generation, state.clone()) {
                        for (id, rule) in &waiting_tunnels {
                            if rule.peer_node_id == peer.to_hex() {
                                let _ = events
                                    .send(SessionEvent::TunnelState {
                                        rule_id: id.clone(),
                                        state: TunnelRuntimeState::Error(
                                            "目标离线或候选等待超时，请重试连接".into(),
                                        ),
                                    })
                                    .await;
                            }
                        }
                        fail_peer_tunnels(
                            peer,
                            "目标离线或候选等待超时，请重试连接",
                            &running_tunnels,
                            &mut forced_tunnel_errors,
                        );
                        queued_lookups.retain(|entry| *entry != (peer, generation));
                        emit_peer_state(&events, peer, generation, state).await;
                    }
                }
            }
            Wake::Input(None) => session_shutdown = true,
            Wake::Shutdown => session_shutdown = true,
            Wake::EventsClosed => session_shutdown = true,
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
            Wake::TunnelTask(Some(Ok((rule_id, result)))) => {
                running_tunnels.remove(&rule_id);
                if let Some(waiters) = tunnel_stop_waiters.remove(&rule_id) {
                    for done in waiters {
                        let _ = done.send(());
                    }
                }
                let result = forced_tunnel_errors.remove(&rule_id).map_or(result, Err);
                let state = match result {
                    Ok(()) if waiting_tunnels.contains_key(&rule_id) => {
                        TunnelRuntimeState::WaitingAuthorization
                    }
                    Ok(()) => TunnelRuntimeState::Stopped,
                    Err(detail) => TunnelRuntimeState::Error(detail),
                };
                let failed = matches!(state, TunnelRuntimeState::Error(_));
                let _ = events
                    .send(SessionEvent::TunnelState {
                        rule_id: rule_id.clone(),
                        state,
                    })
                    .await;
                let should_restart = restart_after_tunnel_stop.remove(&rule_id)
                    || waiting_tunnels
                        .get(&rule_id)
                        .and_then(|r| NodeId::from_hex(&r.peer_node_id).ok())
                        .is_some_and(|peer| {
                            peers
                                .state(peer)
                                .is_some_and(PeerLifecycle::outbound_authorized)
                        });
                if should_restart
                    && !failed
                    && let Some(rule) = tunnel_rules.get(&rule_id).cloned()
                {
                    start_tunnel_rule(
                        rule,
                        local_node,
                        &connections,
                        &peers,
                        &credentials,
                        credential_fallback,
                        &mut waiting_tunnels,
                        &peer_capabilities,
                        &mut peer_connection_updates,
                        &mut running_tunnels,
                        &mut tunnel_tasks,
                        &command_tx,
                        &events,
                    )
                    .await;
                }
            }
            Wake::TunnelTask(Some(Err(error))) => {
                warn!(%error, "本机转发 task 异常退出");
            }
            Wake::TunnelTask(None) => {}
        }
        if !session_shutdown && let Some(service) = config.transfer.as_ref() {
            let ready_connections = connections
                .iter()
                .filter(|(peer, (_, connection))| {
                    peers
                        .state(**peer)
                        .is_some_and(PeerLifecycle::outbound_authorized)
                        && connection.close_reason().is_none()
                })
                .map(|(peer, (_, connection))| (*peer, connection.clone()))
                .collect();
            for scheduled in service.dispatch_ready(&ready_connections) {
                let live = authorizations[&scheduled.entry.peer].2.live();
                let connection = ready_connections[&scheduled.entry.peer].clone();
                let service = service.clone();
                let events = events.clone();
                // Same structured owner as receive/RPC workers: shutdown aborts
                // and drains every executor before persisted interruption recovery.
                peer_tasks.spawn(async move {
                    if let Err(error) = live
                        .guard(false, service.execute_queued(scheduled, connection))
                        .await
                    {
                        let _ = events
                            .send(SessionEvent::Diagnostic(error.to_string()))
                            .await;
                    }
                });
            }
        }
    }

    for (_, (_, _, rights)) in authorizations.drain() {
        rights.send_replace(RemoteAuthorization::default());
    }
    if let Some(task) = connect_task.take() {
        task.abort();
    }
    drop(signal);
    for running in running_tunnels.values() {
        running.shutdown.send_replace(true);
    }
    if time::timeout(Duration::from_secs(3), async {
        while tunnel_tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tunnel_tasks.abort_all();
        while tunnel_tasks.join_next().await.is_some() {}
    }
    running_tunnels.clear();
    for (_, (_, connection)) in connections.drain() {
        connection.close(0u32.into(), b"desktop session shutdown");
    }
    network.close();
    session_tasks.abort_all();
    peer_tasks.abort_all();
    while peer_tasks.join_next().await.is_some() {}
    while session_tasks.join_next().await.is_some() {}
    let _ = time::timeout(Duration::from_secs(1), network.wait_idle()).await;
}

fn retire_peer_listeners(
    peer: NodeId,
    running: &HashMap<String, RunningTunnel>,
    waiting: &mut HashMap<String, super::config::TunnelRule>,
    restart: &mut HashSet<String>,
) {
    for (id, tunnel) in running {
        if tunnel.rule.peer_node_id == peer.to_hex() {
            waiting.insert(id.clone(), tunnel.rule.clone());
            restart.insert(id.clone());
            tunnel.shutdown.send_replace(true);
        }
    }
}

async fn emit_peer_tunnels_starting(
    peer: NodeId,
    running: &HashMap<String, RunningTunnel>,
    events: &SessionEvents,
) {
    for (rule_id, tunnel) in running {
        if NodeId::from_hex(&tunnel.rule.peer_node_id).ok() == Some(peer)
            && !*tunnel.shutdown.borrow()
        {
            let _ = events
                .send(SessionEvent::TunnelState {
                    rule_id: rule_id.clone(),
                    state: TunnelRuntimeState::Starting,
                })
                .await;
        }
    }
}

fn fail_peer_tunnels(
    peer: NodeId,
    detail: &str,
    running: &HashMap<String, RunningTunnel>,
    errors: &mut HashMap<String, String>,
) {
    for (id, tunnel) in running {
        if NodeId::from_hex(&tunnel.rule.peer_node_id).ok() == Some(peer) {
            errors.insert(id.clone(), format!("对端连接失败：{detail}"));
            tunnel.shutdown.send_replace(true);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_tunnel_rule(
    rule: super::config::TunnelRule,
    local_node: NodeId,
    connections: &HashMap<NodeId, (u64, quinn::Connection)>,
    peers: &PeerRegistry,
    _credentials: &HashMap<NodeId, SecretPassword>,
    _credential_fallback: bool,
    waiting_tunnels: &mut HashMap<String, super::config::TunnelRule>,
    peer_capabilities: &HashMap<NodeId, u64>,
    peer_connection_updates: &mut HashMap<NodeId, watch::Sender<Option<quinn::Connection>>>,
    running_tunnels: &mut HashMap<String, RunningTunnel>,
    tunnel_tasks: &mut JoinSet<TunnelTaskResult>,
    command_tx: &mpsc::Sender<SessionCommand>,
    events: &SessionEvents,
) {
    if running_tunnels.contains_key(&rule.id) {
        return;
    }
    let rule_id = rule.id.clone();
    let _ = events
        .send(SessionEvent::TunnelState {
            rule_id: rule_id.clone(),
            state: TunnelRuntimeState::Starting,
        })
        .await;

    let peer = match NodeId::from_hex(&rule.peer_node_id) {
        Ok(peer) if peer != local_node => peer,
        Ok(_) => {
            let _ = events
                .send(SessionEvent::TunnelState {
                    rule_id,
                    state: TunnelRuntimeState::Error("转发规则不能绑定本机 Node ID".into()),
                })
                .await;
            return;
        }
        Err(error) => {
            let _ = events
                .send(SessionEvent::TunnelState {
                    rule_id,
                    state: TunnelRuntimeState::Error(format!("对端 Node ID 无效：{error}")),
                })
                .await;
            return;
        }
    };
    if !rule.enabled {
        let _ = events
            .send(SessionEvent::TunnelState {
                rule_id,
                state: TunnelRuntimeState::Error("本机转发规则已停用".into()),
            })
            .await;
        return;
    }
    if peer_capabilities
        .get(&peer)
        .is_some_and(|capabilities| capabilities & super::protocol::CAP_TCP_TUNNEL == 0)
    {
        let _ = events
            .send(SessionEvent::TunnelState {
                rule_id,
                state: TunnelRuntimeState::Error(format!(
                    "对端设备 {} 不支持 TCP 隧道，请升级桌面端",
                    peer.short()
                )),
            })
            .await;
        return;
    }

    let outbound_authorized = peers
        .state(peer)
        .is_some_and(PeerLifecycle::outbound_authorized)
        && connections
            .get(&peer)
            .is_some_and(|(_, c)| c.close_reason().is_none());
    if !outbound_authorized {
        let _ = command_tx.try_send(SessionCommand::ConnectPeer(peer));
        waiting_tunnels.insert(rule_id.clone(), rule.clone());
        let _ = events
            .send(SessionEvent::TunnelState {
                rule_id,
                state: TunnelRuntimeState::WaitingAuthorization,
            })
            .await;
        return;
    }
    waiting_tunnels.remove(&rule_id);
    let listener = match tokio::net::TcpListener::bind(rule.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = events
                .send(SessionEvent::TunnelState {
                    rule_id,
                    state: TunnelRuntimeState::Error(format!("监听 {} 失败：{error}", rule.listen)),
                })
                .await;
            return;
        }
    };
    let connection_updates = peer_connection_updates
        .entry(peer)
        .or_insert_with(|| watch::channel(None).0);
    if let Some((_, connection)) = connections.get(&peer).filter(|_| outbound_authorized) {
        connection_updates.send_replace(Some(connection.clone()));
    } else if let Err(error) = command_tx.try_send(SessionCommand::ConnectPeer(peer)) {
        let _ = events
            .send(SessionEvent::TunnelState {
                rule_id,
                state: TunnelRuntimeState::Error(format!("连接请求未排入队列：{error}")),
            })
            .await;
        return;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection_updates = connection_updates.subscribe();
    let mut state_updates = connection_updates.clone();
    let (errors_tx, mut errors_rx) = mpsc::unbounded_channel();
    let task_events = events.clone();
    let task_rule_id = rule_id.clone();
    let target = rule.target;
    tunnel_tasks.spawn(async move {
        let forward = crate::tunnel::forward_on_authenticated_session(
            listener,
            target,
            connection_updates,
            shutdown_rx,
            errors_tx,
            |tcp, connection, target| async move {
                super::tunnel::open_tunnel(tcp, &connection, target).await
            },
        );
        tokio::pin!(forward);
        let availability = |updates: &watch::Receiver<Option<quinn::Connection>>| {
            updates
                .borrow()
                .as_ref()
                .is_some_and(|connection| connection.close_reason().is_none())
        };
        let mut ready = availability(&state_updates);
        if ready {
            let _ = task_events
                .send(SessionEvent::TunnelState {
                    rule_id: task_rule_id.clone(),
                    state: TunnelRuntimeState::Running,
                })
                .await;
        }
        let deadline = time::sleep(TUNNEL_PEER_WAIT_TIMEOUT);
        tokio::pin!(deadline);
        let result = loop {
            tokio::select! {
                result = &mut forward => break result.map_err(|error| error.to_string()),
                _ = &mut deadline, if !ready => break Err("等待对端认证连接超时；本机监听已关闭，请重试启动".into()),
                changed = state_updates.changed() => {
                    if changed.is_err() { break Err("对端会话已结束".into()); }
                    ready = availability(&state_updates);
                    deadline.as_mut().reset(time::Instant::now() + TUNNEL_PEER_WAIT_TIMEOUT);
                    let state = if ready { TunnelRuntimeState::Running } else { TunnelRuntimeState::Starting };
                    let _ = task_events.send(SessionEvent::TunnelState { rule_id: task_rule_id.clone(), state }).await;
                },
                Some(detail) = errors_rx.recv() => {
                    let _ = task_events
                        .send(SessionEvent::TunnelError {
                            rule_id: task_rule_id.clone(),
                            detail,
                        })
                        .await;
                }
            }
        };
        (task_rule_id, result)
    });
    running_tunnels.insert(
        rule_id.clone(),
        RunningTunnel {
            rule,
            shutdown: shutdown_tx,
        },
    );
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
            SignalingClient::connect_desktop_with_events(&signal_server, &identity, candidates)
                .await;
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
    events: &SessionEvents,
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

async fn emit_lifecycle(events: &SessionEvents, lifecycle: NetworkLifecycle) {
    let _ = events.send(SessionEvent::Lifecycle(lifecycle)).await;
}

async fn emit_peer_state(
    events: &SessionEvents,
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

/// A signed IPv6 candidate is only a routing hint for a bounded pending attempt,
/// never an identity or authorization. Full TLS-bound Ed25519 authentication of
/// the expected NodeId follows. IPv4 and unknown/ambiguous sources still need a probe.
fn pending_ipv6_route(
    remote: SocketAddr,
    local: NodeId,
    peers: &PeerRegistry,
    candidates: &HashMap<NodeId, (u64, Vec<Candidate>)>,
) -> Option<(NodeId, u64)> {
    if !remote.is_ipv6() || !crate::net::family::usable_address(remote) {
        return None;
    }
    let mut matches = candidates
        .iter()
        .filter_map(|(peer, (generation, addresses))| {
            (!should_initiate_quic(local, *peer)
                && peers.is_current(*peer, *generation)
                && matches!(
                    peers.state(*peer),
                    Some(PeerLifecycle::Punching | PeerLifecycle::Authenticating)
                )
                && addresses.iter().any(|candidate| candidate.addr == remote))
            .then_some((*peer, *generation))
        });
    let matched = matches.next()?;
    matches.next().is_none().then_some(matched)
}

async fn accept_incoming_loop(
    endpoint: quinn::Endpoint,
    family: AddressFamily,
    inputs: mpsc::Sender<SessionInput>,
) {
    while let Some(incoming) = endpoint.accept().await {
        if inputs
            .send(SessionInput::Incoming(family, Box::new(incoming)))
            .await
            .is_err()
        {
            return;
        }
    }
}

fn canonical_candidates(candidates: &[Candidate]) -> Vec<Candidate> {
    let mut result = candidates
        .iter()
        .copied()
        .filter(|c| c.kind != CandidateKind::Relay)
        .collect::<Vec<_>>();
    result.sort_by_key(|c| (c.kind, c.addr));
    result.dedup();
    result
}

#[allow(clippy::too_many_arguments)]
async fn start_peer_attempt(
    peer: NodeId,
    candidates: Vec<Candidate>,
    token: PunchToken,
    local_node: NodeId,
    identity: Identity,
    network: &DesktopNetwork,
    events: &SessionEvents,
    inputs: &mpsc::Sender<SessionInput>,
    semaphore: &Arc<Semaphore>,
    peers: &mut PeerRegistry,
    pending_inbound: &mut HashMap<(NodeId, u64), mpsc::Sender<quinn::Incoming>>,
    tasks: &mut JoinSet<()>,
    auth: AuthContext,
    verifier: Option<RemoteVerifier>,
    password: Option<SecretPassword>,
) -> Option<(u64, tokio::task::AbortHandle)> {
    if peer == local_node {
        return None;
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
                return None;
            }
        },
    };
    let generation = generation?;
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
        return None;
    };

    let filtered: Vec<Candidate> = candidates
        .into_iter()
        .filter(|candidate| candidate.kind != CandidateKind::Relay)
        .collect::<Vec<_>>();
    let reachable = network.reachable_candidates(&filtered);
    let _ = events
        .send(SessionEvent::PeerPath {
            peer,
            generation,
            detail: format!(
                "对端 {} 候选：IPv6 {} / IPv4 {}；本机可用路径 {}",
                peer.short(),
                filtered.iter().filter(|c| c.addr.is_ipv6()).count(),
                filtered.iter().filter(|c| c.addr.is_ipv4()).count(),
                network
                    .paths
                    .iter()
                    .map(|p| p.family.to_string())
                    .collect::<Vec<_>>()
                    .join(" / ")
            ),
        })
        .await;
    if reachable.is_empty() && network.relay.is_none() {
        let detail = "对端候选地址与本机 UDP 地址族不匹配".to_owned();
        peers.transition(peer, generation, PeerLifecycle::Failed(detail.clone()));
        emit_peer_state(
            events,
            peer,
            generation,
            PeerLifecycle::Failed(detail.clone()),
        )
        .await;
        return None;
    }

    if !peers.transition(peer, generation, PeerLifecycle::Punching) {
        return None;
    }
    emit_peer_state(events, peer, generation, PeerLifecycle::Punching).await;
    emit_lifecycle(events, NetworkLifecycle::Punching { peer }).await;
    let (inbound_tx, inbound_rx) = mpsc::channel(MAX_CANDIDATES);
    pending_inbound.insert((peer, generation), inbound_tx);
    let input_sender = inputs.clone();
    let relay = network.relay.clone().map(|mut relay| {
        let inputs = inputs.clone();
        relay.progress = Some(std::sync::Arc::new(move |detail| {
            let _ = inputs.try_send(SessionInput::PeerPath {
                peer,
                generation,
                detail: detail.to_owned(),
            });
        }));
        relay
    });
    let paths: Vec<_> = network
        .paths
        .iter()
        .filter_map(|path| {
            let candidates = path.reachable_candidates(&filtered);
            (!candidates.is_empty()).then(|| (path.clone(), candidates))
        })
        .collect();
    let attempt = tasks.spawn(async move {
        let result = run_peer_attempt(
            peer,
            generation,
            local_node,
            identity,
            paths,
            relay,
            token,
            inbound_rx,
            permit,
            input_sender.clone(),
            auth,
            verifier,
            password,
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
    Some((generation, attempt))
}

#[allow(clippy::too_many_arguments)]
async fn run_peer_attempt(
    peer: NodeId,
    generation: u64,
    local_node: NodeId,
    identity: Identity,
    paths: Vec<(NetworkPath, Vec<SocketAddr>)>,
    relay: Option<crate::relay::client::Fallback>,
    token: PunchToken,
    inbound: mpsc::Receiver<quinn::Incoming>,
    _pending_permit: tokio::sync::OwnedSemaphorePermit,
    inputs: mpsc::Sender<SessionInput>,
    auth: AuthContext,
    verifier: Option<RemoteVerifier>,
    password: Option<SecretPassword>,
) -> std::result::Result<(), String> {
    let _ = inputs
        .send(SessionInput::PeerProgress {
            peer,
            generation,
            state: PeerLifecycle::Authenticating,
        })
        .await;
    let mut guard = race_peer_paths(
        paths,
        token,
        peer,
        generation,
        local_node,
        identity,
        inbound,
        relay.clone(),
    )
    .await
    .map_err(|error| error.to_string())?;
    let connection = guard.connection();

    let _ = inputs
        .send(SessionInput::PeerProgress {
            peer,
            generation,
            state: PeerLifecycle::Negotiating,
        })
        .await;
    let capabilities =
        super::protocol::negotiate(connection, should_initiate_quic(local_node, peer))
            .await
            .map_err(|error| error.to_string())?;

    let _ = inputs
        .send(SessionInput::PeerProgress {
            peer,
            generation,
            state: PeerLifecycle::RemoteAuthPending,
        })
        .await;
    let authorization = match verifier {
        Some(verifier) => {
            auth.authorize_session(
                connection,
                should_initiate_quic(local_node, peer),
                local_node,
                peer,
                verifier,
                password,
                capabilities,
            )
            .await
        }
        None => Err(Error::Protocol("本机远程访问密码尚未初始化".into())),
    };
    let authorization = match authorization {
        Ok(authorization) => authorization,
        Err(error) => {
            connection.close(3u32.into(), b"remote authorization failed");
            return Err(error.to_string());
        }
    };
    // No business stream handler or listener availability is published before this point.
    if let Some(relay) = &relay {
        guard
            .retain_relay_endpoint(&relay.endpoints)
            .map_err(|e| e.to_string())?;
    }
    inputs
        .send(SessionInput::PeerConnected {
            peer,
            generation,
            capabilities,
            authorization: authorization.authorization,
            control: authorization.control.map(Box::new),
            connection: guard.release(),
        })
        .await
        .map_err(|_| "desktop session 已关闭".to_owned())
}

fn transport_can_publish(
    peers: &PeerRegistry,
    peer: NodeId,
    generation: u64,
    connection: &quinn::Connection,
) -> bool {
    if !peers.is_current(peer, generation)
        || peers.state(peer).is_some_and(PeerLifecycle::is_connected)
    {
        connection.close(0u32.into(), b"duplicate or stale peer generation");
        false
    } else {
        true
    }
}

#[allow(clippy::too_many_arguments)]
async fn race_peer_paths(
    paths: Vec<(NetworkPath, Vec<SocketAddr>)>,
    token: PunchToken,
    peer: NodeId,
    generation: u64,
    local: NodeId,
    identity: Identity,
    mut inbound: mpsc::Receiver<quinn::Incoming>,
    relay: Option<crate::relay::client::Fallback>,
) -> Result<ConnectionGuard> {
    let initiator = should_initiate_quic(local, peer);
    // Registration is synchronous and per path, before awaiting probes or any incoming connection.
    let mut routes = Vec::new();
    for (path, candidates) in paths {
        let receiver = path
            .punch_socket
            .register_peer_probe(&token, peer, generation)?;
        routes.push((path, candidates, receiver));
    }
    if initiator {
        let mut tasks = JoinSet::new();
        let has_v6 = routes
            .iter()
            .any(|(p, _, _)| p.family == AddressFamily::Ipv6);
        for (path, candidates, mut receiver) in routes {
            let identity = identity.clone();
            tasks.spawn(async move {
                if has_v6 && path.family == AddressFamily::Ipv4 {
                    time::sleep(crate::net::race::FAMILY_STAGGER).await;
                }
                let remote = if path.family == AddressFamily::Ipv6 {
                    match time::timeout(
                        crate::net::race::FAMILY_STAGGER,
                        punch_candidates(&path.punch_socket, &mut receiver, &candidates, &token),
                    )
                    .await
                    {
                        Ok(Ok(remote)) => remote,
                        _ => candidates[0], // IPv6 QUIC still verifies NodeId/TLS; a probe is optional.
                    }
                } else {
                    punch_candidates(&path.punch_socket, &mut receiver, &candidates, &token).await?
                };
                let mut ordered = vec![remote];
                for candidate in candidates {
                    if !ordered.contains(&candidate) {
                        ordered.push(candidate);
                    }
                }
                let mut dials = JoinSet::new();
                for (index, remote) in ordered.into_iter().enumerate() {
                    let identity = identity.clone();
                    let endpoint = path.endpoint.clone();
                    dials.spawn(async move {
                        time::sleep(crate::net::race::CANDIDATE_STAGGER * index as u32).await;
                        time::timeout(
                            crate::net::race::PATH_TIMEOUT,
                            PreparedTransport::dial(&endpoint, remote, &identity, peer),
                        )
                        .await
                        .map_err(|_| {
                            Error::Transport(format!("{remote} authenticated path timeout"))
                        })?
                    });
                }
                crate::net::race::select_prepared(dials).await
            });
        }
        if let Some(relay) = relay {
            tasks.spawn(async move { relay.prepare(identity, peer, token).await });
        }
        return crate::net::race::finish_prepared_guard(tasks).await;
    }
    let mut probes = JoinSet::new();
    for (path, candidates, mut receiver) in routes {
        probes.spawn(async move {
            let _ = punch_candidates(&path.punch_socket, &mut receiver, &candidates, &token).await;
            // Retain the token/source route even after a successful probe; Quinn's
            // incoming event is routed later by the generation-fenced actor.
            std::future::pending::<()>().await;
            drop(receiver);
        });
    }
    let mut authentication = JoinSet::new();
    let has_relay = relay.is_some();
    if let Some(relay) = relay {
        let relay_identity = identity.clone();
        authentication.spawn(async move { relay.wait(relay_identity, peer, token).await });
    }
    let deadline = time::sleep(if has_relay {
        crate::relay::RELAY_FALLBACK_DELAY
            + Duration::from_secs(3)
            + crate::relay::RELAY_ATTEMPT_TIMEOUT
            + APPLICATION_HANDSHAKE_TIMEOUT
    } else {
        QUIC_HANDSHAKE_TIMEOUT + APPLICATION_HANDSHAKE_TIMEOUT + Duration::from_secs(6)
    });
    tokio::pin!(deadline);
    let result = loop {
        tokio::select! {
            incoming = inbound.recv() => {
                let Some(incoming) = incoming else { break Err(Error::Transport("incoming generation retired".into())); };
                if authentication.len() >= MAX_CANDIDATES { incoming.refuse(); continue; }
                let identity = identity.clone();
                authentication.spawn(async move {
                    authenticate_incoming(incoming, &identity, peer).await.map(ConnectionGuard::new).map_err(Error::Transport)
                });
            }
            result = authentication.join_next(), if !authentication.is_empty() => {
                if let Some(Ok(Ok(winner))) = result { break Ok(winner); }
            }
            _ = &mut deadline => break Err(Error::Transport("all incoming paths timed out".into())),
        }
    };
    probes.abort_all();
    authentication.abort_all();
    while probes.join_next().await.is_some() {}
    while authentication.join_next().await.is_some() {}
    result
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

#[cfg(test)]
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
    let guard = ConnectionGuard::new(connection);
    let connection = guard.connection();
    let binding = ChannelBinding::from_connection(connection).map_err(|error| error.to_string())?;
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
    crate::transport::quic::await_identity_commit(&mut recv)
        .await
        .map_err(|e| e.to_string())?;
    Ok(guard.release())
}

#[cfg(test)]
fn test_password() -> SecretPassword {
    SecretPassword::new("Test9Pass".into()).unwrap()
}
#[cfg(test)]
fn test_verifier() -> RemoteVerifier {
    static VERIFIER: std::sync::OnceLock<RemoteVerifier> = std::sync::OnceLock::new();
    VERIFIER
        .get_or_init(|| RemoteVerifier::create(&test_password()).unwrap())
        .clone()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::discovery::signal::{
        SignalServerConfig, run_signal_server_on_borrowed, run_signal_server_on_with,
    };

    fn auth_config(server: SocketAddr) -> DesktopSessionConfig {
        let mut config = local_config(server);
        config.test_outgoing_password = None;
        config
    }
    async fn wait_failed(events: &mut mpsc::Receiver<SessionEvent>) {
        time::timeout(Duration::from_secs(20), async {
            while let Some(event) = events.recv().await {
                match event {
                    SessionEvent::PeerState {
                        state: PeerLifecycle::Connected(_),
                        ..
                    } => panic!("unauthorized peer was published"),
                    SessionEvent::PeerState {
                        state: PeerLifecycle::Failed(_),
                        ..
                    } => return,
                    _ => {}
                }
            }
            panic!("session ended before failure");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ipv6_desktop_responder_authenticates_password_without_any_punch_response() {
        use crate::net::{NetworkFamilies, family::ipv6_test_available};
        if !ipv6_test_available() {
            return;
        }
        let (signal, server) = start_local_server().await;
        let desktop = Identity::generate();
        let mut client = Identity::generate();
        while !should_initiate_quic(client.node_id(), desktop.node_id()) {
            client = Identity::generate();
        }
        let mut config = auth_config(signal);
        config.network.families = NetworkFamilies::Ipv6Only;
        let (handle, mut events) = spawn(desktop.clone(), config).unwrap();
        wait_signal_online(&mut events).await;
        // A normal Quinn client never interprets/responds to PunchToken packets.
        let endpoint = crate::transport::quic::client_endpoint("[::1]:0".parse().unwrap()).unwrap();
        let mut signaling = SignalingClient::connect_with_events(
            &signal.to_string(),
            &client,
            vec![Candidate::host(endpoint.local_addr().unwrap())],
        )
        .await
        .unwrap();
        let offer = signaling
            .resolve_peer(desktop.node_id(), Duration::from_secs(5))
            .await
            .unwrap();
        time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events.recv().await {
                if matches!(event, SessionEvent::PeerState { peer, state: PeerLifecycle::Authenticating, .. } if peer == client.node_id()) { return; }
            }
            panic!("desktop stopped before pending attempt");
        }).await.unwrap();
        let connection = crate::net::race::authenticated_race(
            offer
                .candidates
                .iter()
                .filter(|c| c.addr.is_ipv6())
                .map(|c| (endpoint.clone(), c.addr))
                .collect(),
            &client,
            desktop.node_id(),
        )
        .await
        .unwrap();
        let capabilities = super::super::protocol::negotiate(&connection, true)
            .await
            .unwrap();
        let authorization = AuthContext::default()
            .authorize_session(
                &connection,
                true,
                client.node_id(),
                desktop.node_id(),
                test_verifier(),
                Some(test_password()),
                capabilities,
            )
            .await
            .unwrap();
        assert_eq!(
            authorization.authorization.outbound,
            super::super::remote_auth::AuthorizationGrant::password(true)
        );
        assert!(!authorization.authorization.inbound_authorized());
        wait_grants(
            &mut events,
            client.node_id(),
            RemoteAuthorization {
                inbound: super::super::remote_auth::AuthorizationGrant::password(true),
                outbound: Default::default(),
            },
        )
        .await;
        assert!(
            inspect(&handle).await[&client.node_id()]
                .1
                .remote_address()
                .is_ipv6()
        );
        connection.close(0u32.into(), b"done");
        handle.shutdown();
        drop(handle);
        endpoint.close(0u32.into(), b"done");
        server.abort();
    }

    #[tokio::test]
    async fn ipv6_quic_completes_when_peer_never_answers_punch_probes() {
        use crate::net::{NetworkFamilies, family::ipv6_test_available};
        if !ipv6_test_available() {
            return;
        }
        let local = Identity::generate();
        let mut remote = Identity::generate();
        while !should_initiate_quic(local.node_id(), remote.node_id()) {
            remote = Identity::generate();
        }
        let peer = remote.node_id();
        // Ordinary Quinn endpoint ignores our PunchToken datagrams; only QUIC is answered.
        let endpoint = crate::transport::quic::server_endpoint("[::1]:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let (committed, mut commits) = mpsc::channel(1);
        let server_endpoint = endpoint.clone();
        let responder = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let guard = ConnectionGuard::new(connection);
            let binding = ChannelBinding::from_connection(guard.connection()).unwrap();
            let (mut send, mut recv) = guard.connection().accept_bi().await.unwrap();
            let outcome = handshake_responder(&mut send, &mut recv, &remote, &binding)
                .await
                .unwrap();
            let _ = send.finish();
            crate::transport::quic::await_identity_commit(&mut recv)
                .await
                .unwrap();
            committed.send(outcome.peer_node_id).await.unwrap();
            let _ = guard.connection().closed().await;
        });
        let network = prepare_desktop_network(&DesktopNetworkConfig {
            families: NetworkFamilies::Ipv6Only,
            stun_servers: Vec::new(),
            include_loopback: true,
            ..Default::default()
        })
        .await
        .unwrap();
        let (_tx, incoming) = mpsc::channel(1);
        let started = time::Instant::now();
        let connection = time::timeout(
            Duration::from_secs(3),
            race_peer_paths(
                vec![(network.paths[0].clone(), vec![address])],
                PunchToken::random(),
                peer,
                1,
                local.node_id(),
                local.clone(),
                incoming,
                None,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(connection.connection().remote_address().is_ipv6());
        assert_eq!(
            time::timeout(Duration::from_secs(2), commits.recv())
                .await
                .unwrap(),
            Some(local.node_id())
        );
        connection.connection().close(0u32.into(), b"done");
        network.close();
        endpoint.close(0u32.into(), b"done");
        responder.await.unwrap();
        network.wait_idle().await;
    }

    #[test]
    fn pending_ipv6_candidate_is_only_a_unique_current_generation_routing_hint() {
        let local = Identity::generate().node_id();
        let mut peer = Identity::generate().node_id();
        while should_initiate_quic(local, peer) {
            peer = Identity::generate().node_id();
        }
        let mut peers = PeerRegistry::default();
        let BeginPeerAttempt::Started(generation) = peers.begin_attempt(peer) else {
            panic!("start")
        };
        peers.transition(peer, generation, PeerLifecycle::Authenticating);
        let address = "[::1]:9000".parse().unwrap();
        let mut candidates = HashMap::from([(peer, (generation, vec![Candidate::host(address)]))]);
        assert_eq!(
            pending_ipv6_route(address, local, &peers, &candidates),
            Some((peer, generation))
        );
        assert_eq!(
            pending_ipv6_route("[::1]:9001".parse().unwrap(), local, &peers, &candidates),
            None
        );
        assert_eq!(
            pending_ipv6_route(
                "127.0.0.1:9000".parse().unwrap(),
                local,
                &peers,
                &candidates
            ),
            None
        );
        let mut other = Identity::generate().node_id();
        while should_initiate_quic(local, other) || other == peer || other == local {
            other = Identity::generate().node_id();
        }
        let BeginPeerAttempt::Started(other_generation) = peers.begin_attempt(other) else {
            panic!("other")
        };
        peers.transition(other, other_generation, PeerLifecycle::Authenticating);
        candidates.insert(other, (other_generation, vec![Candidate::host(address)]));
        assert_eq!(
            pending_ipv6_route(address, local, &peers, &candidates),
            None,
            "ambiguous source is not a routing hint"
        );
        candidates.remove(&other);
        candidates.get_mut(&peer).unwrap().0 += 1;
        assert_eq!(
            pending_ipv6_route(address, local, &peers, &candidates),
            None
        );
        candidates.get_mut(&peer).unwrap().0 = generation;
        peers.transition(
            peer,
            generation,
            PeerLifecycle::Connected(RemoteAuthorization::default()),
        );
        assert_eq!(
            pending_ipv6_route(address, local, &peers, &candidates),
            None
        );
        // A routing hint itself granted neither password nor trusted permission.
        assert_eq!(
            peers.state(peer),
            Some(&PeerLifecycle::Connected(RemoteAuthorization::default()))
        );
    }

    #[tokio::test]
    async fn ipv6_only_concurrent_desktop_requests_publish_one_verified_transport() {
        use crate::net::{NetworkFamilies, family::ipv6_test_available};
        if !ipv6_test_available() {
            return;
        }
        let (signal, server) = start_local_server().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let mut ca = local_config(signal);
        ca.network.families = NetworkFamilies::Ipv6Only;
        let cb = ca.clone();
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        for _ in 0..4 {
            ha.connect_peer(b.node_id()).unwrap();
            hb.connect_peer(a.node_id()).unwrap();
        }
        for (events, peer) in [(&mut ea, b.node_id()), (&mut eb, a.node_id())] {
            let count = time::timeout(Duration::from_secs(20), async {
                let mut committed = 0;
                loop {
                    match events.recv().await.expect("session alive") {
                        SessionEvent::PeerPath {
                            peer: id, detail, ..
                        } if id == peer && detail.contains("已认证 transport") => {
                            assert!(detail.contains("IPv6"));
                            committed += 1;
                        }
                        SessionEvent::PeerState {
                            peer: id,
                            state: PeerLifecycle::Connected(_),
                            ..
                        } if id == peer => break committed,
                        SessionEvent::PeerState {
                            state: PeerLifecycle::Failed(error),
                            ..
                        } => panic!("{error}"),
                        _ => {}
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(
                count, 1,
                "only one transport may enter authorization/business dispatch"
            );
        }
        let a_connections = inspect(&ha).await;
        let b_connections = inspect(&hb).await;
        assert_eq!(a_connections.len(), 1);
        assert_eq!(b_connections.len(), 1);
        assert!(a_connections[&b.node_id()].1.remote_address().is_ipv6());
        assert!(b_connections[&a.node_id()].1.remote_address().is_ipv6());
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
    }

    #[tokio::test]
    async fn trusted_auto_start_reconnects_ipv4_to_ipv6_with_new_generation_and_binding() {
        use super::super::{
            config::{AllowedForwardTarget, DesktopConfig, TunnelRule},
            remote_auth::AuthorizationGrant,
            trusted_devices::TrustedDevice,
        };
        use crate::net::{NetworkFamilies, family::ipv6_test_available};
        if !ipv6_test_available() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "p2p-trusted-family-switch-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("settings.json");
        let a = Identity::generate();
        let b = Identity::generate();
        security_config(
            &path,
            vec![TrustedDevice::new(a.node_id(), "peer".into(), None)],
        );
        let (signal, server) = start_local_server().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = reserve.local_addr().unwrap();
        drop(reserve);
        let mut rule = TunnelRule::new(
            "family recovery",
            b.node_id().to_hex(),
            listen.port(),
            target.local_addr().unwrap(),
        );
        rule.auto_start = true;
        let mut ca = auth_config(signal);
        ca.tunnel_rules = vec![rule.clone()];
        let mut cb = auth_config(signal);
        cb.network.families = NetworkFamilies::Ipv4Only;
        cb.config_path = Some(path.clone());
        cb.trusted_devices = super::super::config::SettingsDraft::from_config(
            DesktopConfig::load(&path).unwrap().unwrap(),
        )
        .trusted_devices;
        cb.allowed_forward_targets = vec![AllowedForwardTarget::new(
            "echo",
            target.local_addr().unwrap(),
            vec![a.node_id().to_hex()],
        )];
        let restart = cb.clone();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut eb).await;
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        let (old_generation, old_connection) = inspect(&ha).await[&b.node_id()].clone();
        assert!(old_connection.remote_address().is_ipv4());
        let old_binding = ChannelBinding::from_connection(&old_connection).unwrap();
        hb.shutdown();
        drop(hb);
        time::timeout(Duration::from_secs(10), async {
            while !inspect(&ha).await.is_empty() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(old_connection.close_reason().is_some());
        while ea.try_recv().is_ok() {}
        let mut cb = restart;
        cb.network.families = NetworkFamilies::Ipv6Only;
        cb.trusted_devices = super::super::config::SettingsDraft::from_config(
            DesktopConfig::load(&path).unwrap().unwrap(),
        )
        .trusted_devices;
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut eb).await;
        ha.connect_peer_trusted(b.node_id()).unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        let (generation, connection) = inspect(&ha).await[&b.node_id()].clone();
        assert_ne!(generation, old_generation);
        assert_ne!(connection.stable_id(), old_connection.stable_id());
        assert_ne!(
            ChannelBinding::from_connection(&connection).unwrap(),
            old_binding
        );
        assert!(connection.remote_address().is_ipv6());
        wait_grants(
            &mut eb,
            a.node_id(),
            RemoteAuthorization {
                inbound: AuthorizationGrant {
                    password: false,
                    trusted_device: true,
                },
                outbound: AuthorizationGrant::default(),
            },
        )
        .await;
        let mut tcp = tokio::net::TcpStream::connect(listen).await.unwrap();
        tcp.write_all(b"ipv6new").await.unwrap();
        let (mut destination, _) = time::timeout(Duration::from_secs(3), target.accept())
            .await
            .unwrap()
            .unwrap();
        let mut data = [0; 7];
        destination.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ipv6new");
        // Address-family recovery did not mutate either password verifier or persistent trust.
        assert_eq!(
            super::super::config::SettingsDraft::from_config(
                DesktopConfig::load(&path).unwrap().unwrap()
            )
            .trusted_devices
            .len(),
            1
        );
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb, tcp, destination));
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn relay_authenticated_late_generation_is_closed_by_the_actual_publication_gate() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let admission = crate::relay::server::Admission::new(Default::default()).unwrap();
        let server = tokio::spawn(crate::relay::server::run(socket, admission.clone()));
        let a = Identity::generate();
        let b = Identity::generate();
        let peer = b.node_id();
        let local = a.node_id();
        let token = PunchToken::random();
        assert!(admission.issue(token, local, peer));
        let responder = tokio::spawn(async move {
            crate::relay::client::prepare(&b, local, token, address)
                .await
                .unwrap()
                .wait_for_selection()
                .await
                .unwrap()
        });
        let mut guard = crate::relay::client::prepare(&a, peer, token, address)
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        let remote = responder.await.unwrap();
        let pool = crate::relay::client::EndpointPool::default();
        guard.retain_relay_endpoint(&pool).unwrap();
        let mut peers = PeerRegistry::default();
        let BeginPeerAttempt::Started(old) = peers.begin_attempt(peer) else {
            panic!()
        };
        peers.transition(peer, old, PeerLifecycle::Disconnected);
        let BeginPeerAttempt::Started(new) = peers.begin_attempt(peer) else {
            panic!()
        };
        assert!(!transport_can_publish(
            &peers,
            peer,
            old,
            guard.connection()
        ));
        assert_eq!(peers.generation(peer), Some(new));
        time::timeout(Duration::from_secs(2), remote.connection().closed())
            .await
            .unwrap();
        pool.close();
        drop((guard, remote));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_pairing_before_close_keeps_live_winner_then_reconnects_on_fresh_tls() {
        async fn deferred(handle: &DesktopSessionHandle, peer: NodeId) -> Option<PunchToken> {
            let (tx, rx) = oneshot::channel();
            handle
                .commands
                .send(SessionCommand::InspectDeferred(peer, tx))
                .await
                .unwrap();
            time::timeout(Duration::from_secs(2), rx)
                .await
                .unwrap()
                .unwrap()
        }
        let (signal, relay, server) = crate::relay::tests::signaling_fixture().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let blackhole_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ca = auth_config(signal);
        let mut cb = auth_config(signal);
        for (config, blackhole) in [(&mut ca, &blackhole_a), (&mut cb, &blackhole_b)] {
            config.network.families = crate::net::NetworkFamilies::Ipv4Only;
            config.network.relay_server = Some(relay.to_string());
            config.network.advertise_only = true;
            config.network.advertise = vec![blackhole.local_addr().unwrap()];
        }
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        let rights_a = wait_authorization(&mut ea, b.node_id()).await;
        let rights_b = wait_authorization(&mut eb, a.node_id()).await;
        let (old_generation, old) = inspect(&ha).await[&b.node_id()].clone();
        let old_b = inspect(&hb).await[&a.node_id()].1.clone();
        let binding = ChannelBinding::from_connection(&old).unwrap();
        ha.connect_peer(b.node_id()).unwrap(); // Actual server signs/registers/pairs; no synthetic token.
        time::timeout(Duration::from_secs(3), async {
            loop {
                if let (Some(a), Some(b)) = (
                    deferred(&ha, b.node_id()).await,
                    deferred(&hb, a.node_id()).await,
                ) && a == b
                {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            inspect(&ha).await[&b.node_id()].1.stable_id(),
            old.stable_id()
        );
        assert_eq!(
            inspect(&hb).await[&a.node_id()].1.stable_id(),
            old_b.stable_id()
        );
        assert!(old.close_reason().is_none()); // Signaling alone cannot replace a live winner.
        while ea.try_recv().is_ok() {}
        while eb.try_recv().is_ok() {}
        old_b.close(0u32.into(), b"force pairing-before-close ordering");
        assert_eq!(wait_authorization(&mut ea, b.node_id()).await, rights_a);
        assert_eq!(wait_authorization(&mut eb, a.node_id()).await, rights_b);
        let (generation, fresh) = inspect(&ha).await[&b.node_id()].clone();
        assert_ne!(generation, old_generation);
        assert_eq!(fresh.remote_address(), relay);
        assert_ne!(ChannelBinding::from_connection(&fresh).unwrap(), binding);
        assert_eq!(inspect(&ha).await.len(), 1);
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_password_grants_are_directional_fresh_and_wrong_password_never_connects() {
        use super::super::remote_auth::AuthorizationGrant;
        let (signal, relay, server) = crate::relay::tests::signaling_fixture().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let blackhole_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ca = auth_config(signal);
        let mut cb = auth_config(signal);
        for (config, blackhole) in [(&mut ca, &blackhole_a), (&mut cb, &blackhole_b)] {
            config.network.families = crate::net::NetworkFamilies::Ipv4Only;
            config.network.relay_server = Some(relay.to_string());
            config.network.advertise_only = true;
            config.network.advertise = vec![blackhole.local_addr().unwrap()];
        }
        let restart = cb.clone();
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        ha.connect_peer_trusted(b.node_id()).unwrap(); // No implicit trust from RelayReady.
        wait_failed(&mut ea).await;
        wait_failed(&mut eb).await;
        assert!(inspect(&ha).await.is_empty());
        ha.connect_peer_with_password(b.node_id(), SecretPassword::new("Wrong9".into()).unwrap())
            .unwrap();
        wait_failed(&mut ea).await;
        wait_failed(&mut eb).await;
        assert!(inspect(&ha).await.is_empty());
        assert!(inspect(&hb).await.is_empty());
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        let rights = wait_authorization(&mut ea, b.node_id()).await;
        assert_eq!(
            rights,
            RemoteAuthorization {
                inbound: AuthorizationGrant::default(),
                outbound: AuthorizationGrant::password(true)
            }
        );
        let rights = wait_authorization(&mut eb, a.node_id()).await;
        assert_eq!(
            rights,
            RemoteAuthorization {
                inbound: AuthorizationGrant::password(true),
                outbound: AuthorizationGrant::default()
            }
        );
        let (old_generation, old) = inspect(&ha).await[&b.node_id()].clone();
        assert_eq!(old.remote_address(), relay);
        let binding = ChannelBinding::from_connection(&old).unwrap();
        hb.shutdown();
        drop(hb);
        time::timeout(Duration::from_secs(10), async {
            while !inspect(&ha).await.is_empty() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        while ea.try_recv().is_ok() {}
        let (hb, mut eb) = spawn(b.clone(), restart).unwrap();
        wait_signal_online(&mut eb).await;
        ha.connect_peer_trusted(b.node_id()).unwrap(); // Previous Password grant does not survive.
        wait_failed(&mut ea).await;
        wait_failed(&mut eb).await;
        assert!(inspect(&ha).await.is_empty());
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        let rights = wait_authorization(&mut ea, b.node_id()).await;
        assert!(rights.outbound.password);
        let (generation, new) = inspect(&ha).await[&b.node_id()].clone();
        assert_ne!(generation, old_generation);
        assert_ne!(ChannelBinding::from_connection(&new).unwrap(), binding);
        assert_eq!(inspect(&ha).await.len(), 1);
        assert!(old.close_reason().is_some());
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_trusted_auto_start_direct_relay_direct_uses_fresh_tls_and_generation() {
        use super::super::{
            config::{AllowedForwardTarget, DesktopConfig, TunnelRule},
            remote_auth::AuthorizationGrant,
            trusted_devices::TrustedDevice,
        };
        use crate::net::NetworkFamilies;
        let root = std::env::temp_dir().join(format!(
            "p2p-trusted-relay-switch-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("settings.json");
        let mut a = Identity::generate();
        let mut b = Identity::generate();
        if a.node_id() > b.node_id() {
            std::mem::swap(&mut a, &mut b);
        }
        security_config(
            &path,
            vec![TrustedDevice::new(a.node_id(), "peer".into(), None)],
        );
        let (signal, relay, server) = crate::relay::tests::signaling_fixture().await;
        let blackhole_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = reserve.local_addr().unwrap();
        drop(reserve);
        let mut rule = TunnelRule::new(
            "family recovery",
            b.node_id().to_hex(),
            listen.port(),
            target.local_addr().unwrap(),
        );
        rule.auto_start = true;
        let mut ca = auth_config(signal);
        ca.tunnel_rules = vec![rule.clone()];
        ca.network.families = NetworkFamilies::Ipv4Only;
        ca.network.relay_server = Some(relay.to_string());
        ca.network.advertise_only = true;
        ca.network.advertise = vec![blackhole_a.local_addr().unwrap()];
        let mut cb = auth_config(signal);
        cb.network.families = NetworkFamilies::Ipv4Only;
        cb.network.relay_server = Some(relay.to_string());
        cb.config_path = Some(path.clone());
        cb.trusted_devices = super::super::config::SettingsDraft::from_config(
            DesktopConfig::load(&path).unwrap().unwrap(),
        )
        .trusted_devices;
        cb.allowed_forward_targets = vec![AllowedForwardTarget::new(
            "echo",
            target.local_addr().unwrap(),
            vec![a.node_id().to_hex()],
        )];
        let restart = cb.clone();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut eb).await;
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        let (old_generation, old_connection) = inspect(&ha).await[&b.node_id()].clone();
        assert!(old_connection.remote_address().is_ipv4());
        let old_binding = ChannelBinding::from_connection(&old_connection).unwrap();
        hb.shutdown();
        drop(hb);
        time::timeout(Duration::from_secs(10), async {
            while !inspect(&ha).await.is_empty() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(old_connection.close_reason().is_some());
        while ea.try_recv().is_ok() {}
        let mut cb = restart.clone();
        cb.network.advertise_only = true;
        cb.network.advertise = vec![blackhole_b.local_addr().unwrap()];
        cb.trusted_devices = super::super::config::SettingsDraft::from_config(
            DesktopConfig::load(&path).unwrap().unwrap(),
        )
        .trusted_devices;
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut eb).await;
        ha.connect_peer_trusted(b.node_id()).unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        let (generation, connection) = inspect(&ha).await[&b.node_id()].clone();
        assert_ne!(generation, old_generation);
        assert_ne!(connection.stable_id(), old_connection.stable_id());
        assert_ne!(
            ChannelBinding::from_connection(&connection).unwrap(),
            old_binding
        );
        assert_eq!(connection.remote_address(), relay);
        wait_grants(
            &mut eb,
            a.node_id(),
            RemoteAuthorization {
                inbound: AuthorizationGrant {
                    password: false,
                    trusted_device: true,
                },
                outbound: AuthorizationGrant::default(),
            },
        )
        .await;
        let mut tcp = tokio::net::TcpStream::connect(listen).await.unwrap();
        tcp.write_all(b"relay!!").await.unwrap();
        let (mut destination, _) = time::timeout(Duration::from_secs(3), target.accept())
            .await
            .unwrap()
            .unwrap();
        let mut data = [0; 7];
        destination.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"relay!!");
        // Address-family recovery did not mutate either password verifier or persistent trust.
        assert_eq!(
            super::super::config::SettingsDraft::from_config(
                DesktopConfig::load(&path).unwrap().unwrap()
            )
            .trusted_devices
            .len(),
            1
        );
        let relay_generation = generation;
        let relay_binding = ChannelBinding::from_connection(&connection).unwrap();
        hb.shutdown();
        drop(hb);
        time::timeout(Duration::from_secs(10), async {
            while !inspect(&ha).await.is_empty() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        drop((tcp, destination));
        while ea.try_recv().is_ok() {}
        let (hb, mut eb) = spawn(b.clone(), restart).unwrap();
        wait_signal_online(&mut eb).await;
        ha.connect_peer_trusted(b.node_id()).unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        let (generation, direct) = inspect(&ha).await[&b.node_id()].clone();
        assert_ne!(generation, relay_generation);
        assert_ne!(
            ChannelBinding::from_connection(&direct).unwrap(),
            relay_binding
        );
        assert_ne!(direct.remote_address(), relay);
        assert!(connection.close_reason().is_some());
        assert_eq!(inspect(&ha).await.len(), 1);
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn ipv6_and_ipv4_reconnect_routes_retire_together_and_old_generation_is_rejected() {
        use crate::net::family::{bind_udp, ipv6_test_available};
        if !ipv6_test_available() {
            return;
        }
        let network = prepare_desktop_network(&DesktopNetworkConfig {
            stun_servers: Vec::new(),
            include_loopback: true,
            ..Default::default()
        })
        .await
        .unwrap();
        let peer = Identity::generate().node_id();
        let old_token = PunchToken::random();
        let mut peers = PeerRegistry::default();
        let BeginPeerAttempt::Started(old_generation) = peers.begin_attempt(peer) else {
            panic!("start")
        };
        let mut receivers = Vec::new();
        let mut sources = Vec::new();
        for path in &network.paths {
            let mut receiver = path
                .punch_socket
                .register_peer_probe(&old_token, peer, old_generation)
                .unwrap();
            let source =
                tokio::net::UdpSocket::from_std(bind_udp(path.family.loopback(0)).unwrap())
                    .unwrap();
            source
                .send_to(
                    &crate::nat::punch::probe_packet(&old_token),
                    path.family.loopback(path.local_addr.port()),
                )
                .await
                .unwrap();
            assert_eq!(
                time::timeout(Duration::from_secs(2), receiver.recv())
                    .await
                    .unwrap(),
                Some(source.local_addr().unwrap())
            );
            receivers.push(receiver);
            sources.push(source);
        }
        assert!(peers.transition(
            peer,
            old_generation,
            PeerLifecycle::Failed("retired".into())
        ));
        let BeginPeerAttempt::Started(new_generation) = peers.begin_attempt(peer) else {
            panic!("restart")
        };
        for (path, source) in network.paths.iter().zip(&sources) {
            let (_, claimed_generation) = path
                .punch_socket
                .claim_authorized_peer(source.local_addr().unwrap())
                .unwrap();
            assert_eq!(claimed_generation, old_generation);
            assert!(!peers.is_current(peer, claimed_generation));
        }
        drop(receivers); // removes both families' token/source routes synchronously
        let token = PunchToken::random();
        for (path, source) in network.paths.iter().zip(&sources) {
            assert_eq!(
                path.punch_socket
                    .claim_authorized_peer(source.local_addr().unwrap()),
                None
            );
            let mut receiver = path
                .punch_socket
                .register_peer_probe(&token, peer, new_generation)
                .unwrap();
            let target = path.family.loopback(path.local_addr.port());
            source
                .send_to(&crate::nat::punch::probe_packet(&old_token), target)
                .await
                .unwrap();
            assert!(
                time::timeout(Duration::from_millis(30), receiver.recv())
                    .await
                    .is_err()
            );
            source
                .send_to(&crate::nat::punch::probe_packet(&token), target)
                .await
                .unwrap();
            assert!(
                time::timeout(Duration::from_secs(2), receiver.recv())
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                path.punch_socket
                    .claim_authorized_peer(source.local_addr().unwrap()),
                Some((peer, new_generation))
            );
        }
        network.close();
        network.wait_idle().await;
    }

    #[tokio::test]
    async fn reconnect_watch_only_accepts_matching_probe_and_expires_without_reconnecting() {
        use crate::nat::punch::probe_packet;
        use crate::transport::quic::endpoint_from_socket_with_punch_dispatcher;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let (endpoint, punch) = endpoint_from_socket_with_punch_dispatcher(socket).unwrap();
        let peer = Identity::generate().node_id();
        let token = PunchToken::random();
        let mut watches = HashMap::from([(
            peer,
            VecDeque::from([ReconnectProbe {
                generation: 7,
                candidates: Vec::new(),
                token,
                receivers: vec![punch.register_peer_probe(&token, peer, 7).unwrap()],
                deadline: Box::pin(time::sleep(Duration::from_secs(5))),
            }]),
        )]);
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&probe_packet(&PunchToken::random()), address)
            .await
            .unwrap();
        assert!(
            time::timeout(
                Duration::from_millis(100),
                std::future::poll_fn(|cx| poll_reconnect_probes(&mut watches, cx))
            )
            .await
            .is_err()
        );
        sender
            .send_to(&probe_packet(&token), address)
            .await
            .unwrap();
        assert_eq!(
            time::timeout(
                Duration::from_secs(2),
                std::future::poll_fn(|cx| { poll_reconnect_probes(&mut watches, cx) })
            )
            .await
            .unwrap(),
            (peer, 0, true)
        );
        assert_eq!(
            punch.claim_authorized_peer(sender.local_addr().unwrap()),
            Some((peer, 7))
        );
        watches.clear();
        assert_eq!(
            punch.claim_authorized_peer(sender.local_addr().unwrap()),
            None
        );
        let receiver = punch.register_peer_probe(&token, peer, 8).unwrap();
        watches.insert(
            peer,
            VecDeque::from([ReconnectProbe {
                generation: 8,
                candidates: Vec::new(),
                token,
                receivers: vec![receiver],
                deadline: Box::pin(time::sleep(Duration::ZERO)),
            }]),
        );
        assert_eq!(
            std::future::poll_fn(|cx| poll_reconnect_probes(&mut watches, cx)).await,
            (peer, 0, false)
        );
        watches.clear();
        endpoint.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    #[tokio::test]
    async fn unauthorized_file_directory_resume_and_speed_commands_cannot_start_business() {
        use super::super::{task_store::TaskStore, transfer::TransferService};
        let root =
            std::env::temp_dir().join(format!("p2p-auth-gate-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("receive")).unwrap();
        let (store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        let service = TransferService::new(store, root.join("receive"));
        let (address, server) = start_local_server().await;
        let mut config = auth_config(address);
        config.transfer = Some(service.clone());
        let (handle, mut events) = spawn(Identity::generate(), config).unwrap();
        wait_signal_online(&mut events).await;
        let peer = Identity::generate().node_id();
        let source = root.join("source.txt");
        std::fs::write(&source, b"sensitive").unwrap();
        handle.send_file(peer, source).unwrap();
        handle.send_directory(peer, root.join("receive")).unwrap();
        handle
            .resume_task(peer, super::super::task_model::TaskId::generate())
            .unwrap();
        handle
            .start_speed(peer, super::super::config::SpeedtestDirection::Upload, 30)
            .unwrap();
        time::timeout(Duration::from_secs(3), async {
            let mut rejected = 0;
            while rejected < 4 {
                if let Some(SessionEvent::Diagnostic(message)) = events.recv().await
                    && message.contains("远程访问尚未授权")
                {
                    rejected += 1;
                }
            }
        })
        .await
        .unwrap();
        assert!(service.snapshot().await.unwrap().is_empty());
        assert!(inspect(&handle).await.is_empty());
        assert_eq!(std::fs::read_dir(root.join("receive")).unwrap().count(), 0);
        handle.shutdown();
        drop(handle);
        server.abort();
        let _ = server.await;
        drop(service);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn wrong_password_never_publishes_business_connection_or_running_tunnel() {
        let (address, server) = start_local_server().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserve.local_addr().unwrap();
        drop(reserve);
        let mut config = auth_config(address);
        let mut rule = super::super::config::TunnelRule::new(
            "protected",
            b.node_id().to_hex(),
            local.port(),
            target.local_addr().unwrap(),
        );
        rule.auto_start = true;
        let rule_id = rule.id.clone();
        config.tunnel_rules.push(rule);
        let mut destination = auth_config(address);
        destination
            .allowed_forward_targets
            .push(super::super::config::AllowedForwardTarget::new(
                "protected",
                target.local_addr().unwrap(),
                vec![a.node_id().to_hex()],
            ));
        let (ha, mut ea) = spawn(a.clone(), config).unwrap();
        let (hb, mut eb) = spawn(b.clone(), destination).unwrap();
        // A restarted process has no peer password and must not bind or attempt authentication.
        wait_specific_tunnel_state(&mut ea, &rule_id, TunnelRuntimeState::WaitingAuthorization)
            .await;
        assert!(tokio::net::TcpStream::connect(local).await.is_err());
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        assert!(inspect(&ha).await.is_empty());
        assert!(inspect(&hb).await.is_empty());
        ha.connect_peer_with_password(b.node_id(), SecretPassword::new("Wrong9".into()).unwrap())
            .unwrap();
        wait_failed(&mut ea).await;
        wait_failed(&mut eb).await;
        assert!(inspect(&ha).await.is_empty());
        assert!(inspect(&hb).await.is_empty());
        assert!(
            time::timeout(Duration::from_secs(1), target.accept())
                .await
                .is_err()
        );
        // Allow all lifecycle notifications to settle, then verify the listener has actually gone.
        ha.revoke_tunnel_rule(rule_id, true).await.unwrap();
        assert!(tokio::net::TcpStream::connect(local).await.is_err());
        ha.shutdown();
        hb.shutdown();
        server.abort();
    }
    async fn wait_authorization(
        events: &mut mpsc::Receiver<SessionEvent>,
        peer: NodeId,
    ) -> RemoteAuthorization {
        time::timeout(Duration::from_secs(20), async {
            while let Some(event) = events.recv().await {
                match event {
                    SessionEvent::PeerState {
                        peer: id,
                        state: PeerLifecycle::Connected(auth),
                        ..
                    } if id == peer => return auth,
                    SessionEvent::PeerState {
                        state: PeerLifecycle::Failed(e),
                        ..
                    } => panic!("authorization failed: {e}"),
                    _ => {}
                }
            }
            panic!("session closed before authorization")
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn passwordless_auto_start_waits_without_binding_then_continues_after_explicit_auth() {
        let (address, server) = start_local_server().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserve.local_addr().unwrap();
        drop(reserve);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut rule = super::super::config::TunnelRule::new(
            "deferred",
            b.node_id().to_hex(),
            local.port(),
            target.local_addr().unwrap(),
        );
        rule.auto_start = true;
        let mut ca = auth_config(address);
        ca.tunnel_rules.push(rule.clone());
        let mut cb = auth_config(address);
        cb.allowed_forward_targets
            .push(super::super::config::AllowedForwardTarget::new(
                "target",
                target.local_addr().unwrap(),
                vec![a.node_id().to_hex()],
            ));
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::WaitingAuthorization)
            .await;
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        assert!(tokio::net::TcpStream::connect(local).await.is_err());
        assert!(inspect(&ha).await.is_empty());
        assert!(inspect(&hb).await.is_empty());
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        // The automatic no-password attempt may already have reported failure.
        // Verify this explicit password request's real grant before waiting on the listener.
        wait_grants(
            &mut ea,
            b.node_id(),
            RemoteAuthorization {
                inbound: crate::desktop::remote_auth::AuthorizationGrant::default(),
                outbound: crate::desktop::remote_auth::AuthorizationGrant::password(true),
            },
        )
        .await;
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        wait_grants(
            &mut eb,
            a.node_id(),
            RemoteAuthorization {
                inbound: crate::desktop::remote_auth::AuthorizationGrant::password(true),
                outbound: crate::desktop::remote_auth::AuthorizationGrant::password(false),
            },
        )
        .await;
        let mut tcp = tokio::net::TcpStream::connect(local).await.unwrap();
        tcp.write_all(b"request").await.unwrap();
        let (mut destination, _) = time::timeout(Duration::from_secs(5), target.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = [0; 7];
        destination.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"request");
        destination.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        tcp.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        ha.revoke_tunnel_rule(rule.id, true).await.unwrap();
        assert!(tokio::net::TcpStream::connect(local).await.is_err());
        ha.shutdown();
        hb.shutdown();
        server.abort();
    }

    #[tokio::test]
    async fn stopping_or_reconfiguring_waiting_rules_cancels_their_deferred_start() {
        let (address, server) = start_local_server().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut reservations = Vec::new();
        let mut rules = Vec::new();
        for name in ["active", "stop", "disable", "delete", "no-auto"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut rule = super::super::config::TunnelRule::new(
                name,
                b.node_id().to_hex(),
                listener.local_addr().unwrap().port(),
                target.local_addr().unwrap(),
            );
            rule.auto_start = true;
            rules.push(rule);
            reservations.push(listener);
        }
        let mut ca = auth_config(address);
        ca.tunnel_rules = rules.clone();
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), auth_config(address)).unwrap();
        for rule in &rules {
            wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::WaitingAuthorization)
                .await;
        }
        drop(reservations);
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        let mut next = rules.clone();
        next[2].enabled = false;
        next[4].auto_start = false;
        next.remove(3);
        ha.update_tunnel_settings(Vec::new(), next).unwrap();
        ha.stop_tunnel_rule(rules[1].id.clone()).unwrap();
        assert!(inspect(&ha).await.is_empty()); // Command barrier before authentication.
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        // The automatic no-password attempt may already have reported failure.
        // Verify this explicit password request's real grant before waiting on the listener.
        wait_grants(
            &mut ea,
            b.node_id(),
            RemoteAuthorization {
                inbound: crate::desktop::remote_auth::AuthorizationGrant::default(),
                outbound: crate::desktop::remote_auth::AuthorizationGrant::password(true),
            },
        )
        .await;
        wait_specific_tunnel_state(&mut ea, &rules[0].id, TunnelRuntimeState::Running).await;
        for rule in &rules[1..] {
            assert!(
                tokio::net::TcpStream::connect(rule.listen).await.is_err(),
                "cancelled rule {} still listening",
                rule.name
            );
        }
        ha.revoke_tunnel_rule(rules[0].id.clone(), true)
            .await
            .unwrap();
        ha.shutdown();
        hb.shutdown();
        server.abort();
    }

    #[tokio::test]
    async fn one_way_auth_gates_commands_queue_and_remote_requests_then_both_passwords_enable_reverse_business()
     {
        directional_business_fixture(false).await;
    }
    #[tokio::test]
    async fn relay_one_way_auth_and_both_passwords_gate_bidirectional_files_and_tunnels() {
        directional_business_fixture(true).await;
    }
    async fn directional_business_fixture(relay_enabled: bool) {
        use super::super::{
            protocol::{self, Frame, Message},
            task_model::{TaskDirection, TaskState},
            task_store::TaskStore,
            transfer::TransferService,
        };
        let root = std::env::temp_dir().join(format!("p2p-directional-{}", rand::random::<u128>()));
        std::fs::create_dir_all(root.join("a-receive")).unwrap();
        std::fs::create_dir(root.join("b-receive")).unwrap();
        let (sa, _) = TaskStore::open(&root.join("a-state/tasks.json")).unwrap();
        let (sb, _) = TaskStore::open(&root.join("b-state/tasks.json")).unwrap();
        let service_a = TransferService::new(sa, root.join("a-receive"));
        let service_b = TransferService::new(sb, root.join("b-receive"));
        let a = Identity::generate();
        let b = Identity::generate();
        let pa = SecretPassword::new("Local9A".into()).unwrap();
        let pb = SecretPassword::new("Local9B".into()).unwrap();
        let ta = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tb = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reserve = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = reserve.local_addr().unwrap();
        drop(reserve);
        let mut signal_config = SignalServerConfig::for_tests();
        if relay_enabled {
            signal_config.relay = Some(crate::relay::server::RelayServerConfig {
                listen: vec![relay],
                ..Default::default()
            });
        }
        let (address, server) = start_local_server_with(signal_config).await;
        let blackhole_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ca = auth_config(address);
        ca.remote_auth = Some(RemoteVerifier::create(&pa).unwrap());
        ca.transfer = Some(service_a.clone());
        let mut cb = auth_config(address);
        cb.remote_auth = Some(RemoteVerifier::create(&pb).unwrap());
        cb.transfer = Some(service_b.clone());
        ca.allowed_forward_targets
            .push(super::super::config::AllowedForwardTarget::new(
                "a",
                ta.local_addr().unwrap(),
                vec![b.node_id().to_hex()],
            ));
        cb.allowed_forward_targets
            .push(super::super::config::AllowedForwardTarget::new(
                "b",
                tb.local_addr().unwrap(),
                vec![a.node_id().to_hex()],
            ));
        if relay_enabled {
            for (config, blackhole) in [(&mut ca, &blackhole_a), (&mut cb, &blackhole_b)] {
                config.network.families = crate::net::NetworkFamilies::Ipv4Only;
                config.network.relay_server = Some(relay.to_string());
                config.network.advertise_only = true;
                config.network.advertise = vec![blackhole.local_addr().unwrap()];
            }
        }
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        let short_a = time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(SessionEvent::ShortIdRegistered(id)) = ea.recv().await {
                    break id;
                }
            }
        })
        .await
        .unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        ha.connect_peer_with_password(b.node_id(), pb).unwrap();
        assert_eq!(
            wait_authorization(&mut ea, b.node_id()).await,
            RemoteAuthorization {
                inbound: crate::desktop::remote_auth::AuthorizationGrant::password(false),
                outbound: crate::desktop::remote_auth::AuthorizationGrant::password(true)
            }
        );
        assert_eq!(
            wait_authorization(&mut eb, a.node_id()).await,
            RemoteAuthorization {
                inbound: crate::desktop::remote_auth::AuthorizationGrant::password(true),
                outbound: crate::desktop::remote_auth::AuthorizationGrant::password(false)
            }
        );
        let conn_a = inspect(&ha).await[&b.node_id()].1.clone();
        let conn_b = inspect(&hb).await[&a.node_id()].1.clone();
        if relay_enabled {
            assert_eq!(conn_b.remote_address(), relay);
        }
        // Reject forged peer requests despite an authenticated, live QUIC transport.
        let (mut send, mut recv) = conn_b.open_bi().await.unwrap();
        let forged_request = protocol::write(
            &mut send,
            &Frame {
                request_id: 0,
                message: Message::TunnelOpen {
                    target: ta.local_addr().unwrap(),
                },
            },
        )
        .await;
        // The unauthorized stream can be rejected before the request's final
        // bytes are written. Accept only the exact authorization STOP code;
        // other transport errors still fail this business-boundary test.
        if let Err(error) = forged_request {
            let crate::error::Error::Io(error) = error else {
                panic!("unexpected forged-request error: {error}");
            };
            assert_eq!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<quinn::WriteError>()),
                Some(&quinn::WriteError::Stopped(4u32.into())),
            );
        }
        assert!(
            time::timeout(Duration::from_secs(5), protocol::read(&mut recv))
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            time::timeout(Duration::from_millis(100), ta.accept())
                .await
                .is_err()
        );
        let source_b = root.join("reverse.bin");
        std::fs::write(&source_b, b"reverse").unwrap();
        hb.send_file(a.node_id(), source_b.clone()).unwrap();
        hb.start_speed(
            a.node_id(),
            super::super::config::SpeedtestDirection::Upload,
            30,
        )
        .unwrap();
        time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    eb.recv().await,
                    Some(SessionEvent::SpeedRequestEnded { .. })
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(
            service_b
                .snapshot()
                .await
                .unwrap()
                .iter()
                .all(|r| r.direction() != TaskDirection::Send)
        );
        // Restored/prepared queue entries also obey the outgoing gate.
        let queued = service_b.select_file(a.node_id(), source_b).await.unwrap();
        time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            service_b.task(queued.clone()).await.unwrap().state(),
            TaskState::Queued
        );
        assert_eq!(
            std::fs::read_dir(root.join("a-receive")).unwrap().count(),
            0
        );
        let source_a = root.join("forward.bin");
        std::fs::write(&source_a, b"forward").unwrap();
        let (cleanup_reached, cleanup_release) = service_a.gate_test_send_cleanup();
        ha.send_file(b.node_id(), source_a).unwrap();
        time::timeout(Duration::from_secs(10), async {
            while !service_a
                .snapshot()
                .await
                .unwrap()
                .iter()
                .any(|r| r.direction() == TaskDirection::Send && r.state() == TaskState::Completed)
            {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(root.join("b-receive/forward.bin")).unwrap(),
            b"forward"
        );
        // Completed is durable state, not proof that the stream's cleanup permit
        // has been released. Force that ordering and retain the file/speed gate.
        time::timeout(Duration::from_secs(5), cleanup_reached)
            .await
            .unwrap()
            .unwrap();
        assert!(!service_a.test_speed_idle(b.node_id()));
        assert!(
            service_a
                .start_speed(
                    b.node_id(),
                    super::super::protocol::SpeedDirection::Upload,
                    30
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("文件或测速正在进行")
        );
        cleanup_release.send(()).unwrap();
        time::timeout(Duration::from_secs(5), async {
            while !(service_a.test_speed_idle(b.node_id())
                && service_b.test_speed_idle(a.node_id())
                && service_a.set_test_speed_duration(b.node_id(), Duration::from_millis(100))
                && service_b.set_test_speed_duration(a.node_id(), Duration::from_millis(100)))
            {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        ha.start_speed(
            b.node_id(),
            super::super::config::SpeedtestDirection::Both,
            30,
        )
        .unwrap();
        time::timeout(Duration::from_secs(15), async {
            let mut phases = 0;
            let mut diagnostics = Vec::new();
            while phases < 2 {
                match ea.recv().await.unwrap() {
                    SessionEvent::SpeedPhaseCompleted { snapshot, .. } => {
                        assert!(snapshot.bytes > 0);
                        phases += 1;
                    }
                    SessionEvent::Diagnostic(message) => diagnostics.push(message),
                    SessionEvent::SpeedRequestEnded { .. } => {
                        panic!("speed request ended after {phases}/2 phases: {diagnostics:?}")
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        let (mut send_a, mut recv_a) = conn_a.open_bi().await.unwrap();
        protocol::write(
            &mut send_a,
            &Frame {
                request_id: 0,
                message: Message::TunnelOpen {
                    target: tb.local_addr().unwrap(),
                },
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            protocol::read(&mut recv_a).await.unwrap().message,
            Message::TunnelReady
        ));
        drop(tb.accept().await.unwrap());
        drop((send_a, recv_a));
        // B separately proves A's password; A proves its current-process B credential again.
        hb.connect_short_id(short_a, pa).unwrap();
        assert_eq!(
            wait_authorization(&mut ea, b.node_id()).await,
            RemoteAuthorization::BOTH
        );
        assert_eq!(
            wait_authorization(&mut eb, a.node_id()).await,
            RemoteAuthorization::BOTH
        );
        assert_ne!(
            inspect(&hb).await[&a.node_id()].1.stable_id(),
            conn_b.stable_id()
        );
        time::timeout(Duration::from_secs(10), async {
            while service_b.task(queued.clone()).await.unwrap().state() != TaskState::Completed {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(root.join("a-receive/reverse.bin")).unwrap(),
            b"reverse"
        );
        let new_b = inspect(&hb).await[&a.node_id()].1.clone();
        let (mut send, mut recv) = new_b.open_bi().await.unwrap();
        protocol::write(
            &mut send,
            &Frame {
                request_id: 0,
                message: Message::TunnelOpen {
                    target: ta.local_addr().unwrap(),
                },
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            protocol::read(&mut recv).await.unwrap().message,
            Message::TunnelReady
        ));
        drop(ta.accept().await.unwrap());
        drop((send, recv));
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb, service_a, service_b));
        server.abort();
        time::timeout(Duration::from_secs(5), async {
            loop {
                if std::fs::remove_dir_all(&root).is_ok() {
                    break;
                }
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn short_id_connect_authenticates_then_rotation_revokes_and_old_password_fails() {
        let (address, server) = start_local_server().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let (ha, mut ea) = spawn(a.clone(), auth_config(address)).unwrap();
        let short_a = time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(SessionEvent::ShortIdRegistered(id)) = ea.recv().await {
                    break id;
                }
            }
        })
        .await
        .unwrap();
        wait_signal_online(&mut ea).await;
        let (hb, mut eb) = spawn(b.clone(), auth_config(address)).unwrap();
        let short_b = time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(SessionEvent::ShortIdRegistered(id)) = eb.recv().await {
                    break id;
                }
            }
        })
        .await
        .unwrap();
        wait_signal_online(&mut eb).await;
        assert_ne!(short_a, short_b);
        ha.connect_short_id(short_b, test_password()).unwrap();
        wait_connected(&mut ea, &[b.node_id()]).await;
        wait_connected(&mut eb, &[a.node_id()]).await;
        let old = inspect(&ha).await[&b.node_id()].1.clone();
        let changed = SecretPassword::new("Changed9".into()).unwrap();
        hb.update_remote_auth(RemoteVerifier::create(&changed).unwrap())
            .await
            .unwrap();
        assert!(inspect(&hb).await.is_empty());
        time::timeout(Duration::from_secs(5), old.closed())
            .await
            .unwrap();
        // Wait until the old generation is retired on A; its authorization cannot carry over.
        time::timeout(Duration::from_secs(5), async {
            loop {
                if inspect(&ha).await.is_empty() {
                    break;
                }
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        while ea.try_recv().is_ok() {}
        while eb.try_recv().is_ok() {}
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        wait_failed(&mut ea).await;
        wait_failed(&mut eb).await;
        assert!(inspect(&ha).await.is_empty());
        while eb.try_recv().is_ok() {}
        ha.connect_peer_with_password(b.node_id(), changed).unwrap();
        wait_connected(&mut ea, &[b.node_id()]).await;
        wait_connected(&mut eb, &[a.node_id()]).await;
        assert_ne!(
            inspect(&ha).await[&b.node_id()].1.stable_id(),
            old.stable_id()
        );
        ha.shutdown();
        hb.shutdown();
        server.abort();
    }
    async fn start_local_server() -> (SocketAddr, JoinHandle<()>) {
        start_local_server_with(SignalServerConfig::for_tests()).await
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
            remote_auth: Some(test_verifier()),
            trusted_devices: Vec::new(),
            config_path: None,
            test_outgoing_password: Some(test_password()),
            allowed_forward_targets: Vec::new(),
            tunnel_rules: Vec::new(),
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
                    state: PeerLifecycle::Connected(_),
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

    async fn wait_tunnel_state(
        events: &mut mpsc::Receiver<SessionEvent>,
        rule_id: &str,
    ) -> TunnelRuntimeState {
        time::timeout(Duration::from_secs(8), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::TunnelState {
                    rule_id: current,
                    state,
                } = event
                    && current == rule_id
                    && state != TunnelRuntimeState::Starting
                {
                    return state;
                }
            }
            panic!("session stopped before tunnel state was reported");
        })
        .await
        .expect("tunnel startup/stop should report promptly")
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
        // Keep one registered listener across epochs. Releasing the port lets
        // parallel fixtures reuse it; cloning/re-registering its socket can spin
        // on accept errors on Windows. Only the server and client tasks restart.
        let reserved = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let signal_server = reserved.local_addr().unwrap();
        let initial = Arc::clone(&reserved);
        let server = tokio::spawn(async move {
            run_signal_server_on_borrowed(
                &initial,
                SignalServerConfig {
                    idle_timeout: Duration::from_millis(250),
                    ..SignalServerConfig::for_tests()
                },
            )
            .await
            .unwrap();
        });
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

        let restarted_server = tokio::spawn(async move {
            run_signal_server_on_borrowed(&reserved, SignalServerConfig::for_tests())
                .await
                .unwrap();
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
        handle
            .reconfigure_network(new_address.to_string(), None)
            .unwrap();
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

    #[tokio::test]
    async fn closing_ui_event_receiver_runs_session_shutdown() {
        let (address, server) = start_local_server().await;
        let (handle, mut events) = spawn(Identity::generate(), local_config(address)).unwrap();
        wait_signal_online(&mut events).await;
        drop(events);
        time::timeout(Duration::from_secs(3), async {
            while handle.is_running() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("closing the UI event receiver must join the session runtime");
        drop(handle);
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

    async fn wait_specific_tunnel_state(
        events: &mut mpsc::Receiver<SessionEvent>,
        id: &str,
        wanted: TunnelRuntimeState,
    ) {
        let expected = format!("expected {wanted:?} for {id}");
        // Reconnect now includes an Argon2id job; use the healthy peer establishment
        // budget, and still fail immediately on a terminal protocol/runtime error.
        time::timeout(Duration::from_secs(20), async {
            while let Some(event) = events.recv().await {
                if wanted == TunnelRuntimeState::Running {
                    if let SessionEvent::PeerState {
                        state: PeerLifecycle::Failed(ref detail),
                        ..
                    } = event
                    {
                        panic!("tunnel peer failed while waiting for Running: {detail}");
                    }
                    if let SessionEvent::TunnelState {
                        ref rule_id,
                        state: TunnelRuntimeState::Error(ref detail),
                    } = event
                        && rule_id == id
                    {
                        panic!("tunnel failed while waiting for Running: {detail}");
                    }
                }
                if let SessionEvent::TunnelState { rule_id, state } = event
                    && rule_id == id
                    && state == wanted
                {
                    return;
                }
            }
            panic!("session ended before expected tunnel state");
        })
        .await
        .expect(&expected);
    }

    #[tokio::test]
    async fn offline_rule_waits_without_a_listener_and_reports_lookup_failure() {
        let (signal, server) = start_local_server().await;
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut rule = super::super::config::TunnelRule::new(
            "offline",
            Identity::generate().node_id().to_hex(),
            port,
            "127.0.0.1:22".parse().unwrap(),
        );
        rule.auto_start = true;
        let mut config = local_config(signal);
        config.tunnel_rules.push(rule.clone());
        let (handle, mut events) = spawn(Identity::generate(), config).unwrap();
        wait_specific_tunnel_state(&mut events, &rule.id, TunnelRuntimeState::Starting).await;
        wait_specific_tunnel_state(
            &mut events,
            &rule.id,
            TunnelRuntimeState::WaitingAuthorization,
        )
        .await;
        assert!(tokio::net::TcpStream::connect(rule.listen).await.is_err());
        time::timeout(Duration::from_secs(25), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::TunnelState { rule_id, state } = event
                    && rule_id == rule.id
                {
                    assert_ne!(
                        state,
                        TunnelRuntimeState::Running,
                        "offline listener must never report Running"
                    );
                    if let TunnelRuntimeState::Error(detail) = state {
                        assert!(
                            detail.contains("离线") || detail.contains("超时"),
                            "{detail}"
                        );
                        return;
                    }
                }
            }
            panic!("offline lookup must end with Error");
        })
        .await
        .unwrap();
        assert!(tokio::net::TcpStream::connect(rule.listen).await.is_err());
        drop(handle);
        server.abort();
    }

    #[tokio::test]
    async fn authenticated_transfer_dispatch_checks_peer_and_live_target_revocation() {
        use super::super::{
            config::AllowedForwardTarget,
            protocol::{self, Frame, Message},
            task_store::TaskStore,
            transfer::TransferService,
        };
        let root = std::env::temp_dir().join(format!("p2p-tunnel-auth-{}", rand::random::<u128>()));
        std::fs::create_dir_all(root.join("receive")).unwrap();
        let (store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        let (signal, server) = start_local_server().await;
        let owner = Identity::generate();
        let a = Identity::generate();
        let b = Identity::generate();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut tcp, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = tcp.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let grant = AllowedForwardTarget::new("echo", target, vec![a.node_id().to_hex()]);
        let mut config = local_config(signal);
        config.transfer = Some(TransferService::new(store, root.join("receive")));
        config.allowed_forward_targets = vec![grant.clone()];
        let (owner_handle, mut owner_events) = spawn(owner.clone(), config).unwrap();
        let (a_handle, mut a_events) = spawn(a.clone(), local_config(signal)).unwrap();
        let (b_handle, mut b_events) = spawn(b.clone(), local_config(signal)).unwrap();
        wait_signal_online(&mut owner_events).await;
        wait_signal_online(&mut a_events).await;
        wait_signal_online(&mut b_events).await;
        a_handle.connect_peer(owner.node_id()).unwrap();
        b_handle.connect_peer(owner.node_id()).unwrap();
        wait_connected(&mut a_events, &[owner.node_id()]).await;
        wait_connected(&mut b_events, &[owner.node_id()]).await;
        let a_connection = inspect(&a_handle).await.remove(&owner.node_id()).unwrap().1;
        let b_connection = inspect(&b_handle).await.remove(&owner.node_id()).unwrap().1;
        async fn open(
            connection: &quinn::Connection,
            target: SocketAddr,
        ) -> (quinn::SendStream, quinn::RecvStream, Message) {
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            protocol::write(
                &mut send,
                &Frame {
                    request_id: 0,
                    message: Message::TunnelOpen { target },
                },
            )
            .await
            .unwrap();
            let message = time::timeout(Duration::from_secs(2), protocol::read(&mut recv))
                .await
                .unwrap()
                .unwrap()
                .message;
            (send, recv, message)
        }
        let (mut established_send, mut established_recv, message) =
            open(&a_connection, target).await;
        assert_eq!(message, Message::TunnelReady);
        assert!(matches!(
            open(&b_connection, target).await.2,
            Message::TunnelError { .. }
        ));
        let mut disabled = grant.clone();
        disabled.enabled = false;
        owner_handle.restrict_forward_targets(&[disabled]);
        assert!(matches!(
            open(&a_connection, target).await.2,
            Message::TunnelError { .. }
        ));
        // Revocation does not kill already established streams.
        established_send.write_all(b"kept").await.unwrap();
        let mut echoed = [0; 4];
        established_recv.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"kept");
        owner_handle
            .update_tunnel_settings(vec![grant.clone()], Vec::new())
            .unwrap();
        assert_eq!(open(&a_connection, target).await.2, Message::TunnelReady);
        owner_handle.restrict_forward_targets(&[]);
        let mut unsaved = super::super::config::SettingsDraft::defaults(Some(root.join("receive")));
        unsaved.signal_host = "127.0.0.1".into();
        unsaved.signal_port = signal.port().to_string();
        unsaved.allowed_forward_targets = vec![grant.clone()];
        assert!(unsaved.save_atomic(&root.join("receive")).is_err());
        assert!(matches!(
            open(&a_connection, target).await.2,
            Message::TunnelError { .. }
        ));
        // Unsaved re-enable cannot restore grants revoked from the applied configuration.
        owner_handle.restrict_forward_targets(&[grant]);
        assert!(matches!(
            open(&a_connection, target).await.2,
            Message::TunnelError { .. }
        ));
        drop((a_handle, b_handle, owner_handle));
        echo_task.abort();
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn auto_started_bound_peer_tunnel_is_independent_and_reports_real_errors() {
        let (signal, server) = start_local_server().await;
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let listener_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_port = listener_probe.local_addr().unwrap().port();
        drop(listener_probe);
        let occupied_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied = occupied_listener.local_addr().unwrap();

        let mut auto_rule = super::super::config::TunnelRule::new(
            "echo",
            identity_b.node_id().to_hex(),
            listen_port,
            target,
        );
        auto_rule.auto_start = true;
        let conflict_rule = super::super::config::TunnelRule {
            id: "occupied-port".into(),
            name: "占用端口".into(),
            peer_node_id: identity_b.node_id().to_hex(),
            listen: occupied,
            target,
            enabled: true,
            auto_start: true,
        };

        let mut config_a = local_config(signal);
        config_a.tunnel_rules = vec![auto_rule.clone(), conflict_rule.clone()];
        let mut config_b = local_config(signal);
        config_b.allowed_forward_targets = vec![super::super::config::AllowedForwardTarget::new(
            "echo",
            target,
            vec![identity_a.node_id().to_hex()],
        )];
        let (handle_a, mut events_a) = spawn(identity_a.clone(), config_a).unwrap();
        let (handle_b, mut events_b) = spawn(identity_b.clone(), config_b).unwrap();

        let conflict_detail = time::timeout(Duration::from_secs(20), async {
            let mut conflict = None;
            let mut running = false;
            while let Some(event) = events_a.recv().await {
                if let SessionEvent::TunnelState { rule_id, state } = event {
                    if rule_id == conflict_rule.id {
                        if let TunnelRuntimeState::Error(detail) = state {
                            conflict = Some(detail);
                        }
                    } else if rule_id == auto_rule.id && state == TunnelRuntimeState::Running {
                        running = true;
                    }
                    if running && let Some(detail) = conflict.take() {
                        return detail;
                    }
                }
            }
            panic!("both rules must settle independently");
        })
        .await
        .unwrap();
        assert!(conflict_detail.contains("监听"), "{conflict_detail}");
        assert!(
            conflict_detail.contains("Address already in use") || conflict_detail.contains("10048"),
            "{conflict_detail}"
        );
        wait_connected(&mut events_b, &[identity_a.node_id()]).await;

        let mut local = tokio::net::TcpStream::connect(auto_rule.listen)
            .await
            .unwrap();
        local.write_all(b"bound to configured peer").await.unwrap();
        let mut echoed = [0; 24];
        local.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"bound to configured peer");
        local.shutdown().await.unwrap();
        let mut tail = Vec::new();
        local.read_to_end(&mut tail).await.unwrap();

        inspect(&handle_a)
            .await
            .get(&identity_b.node_id())
            .unwrap()
            .1
            .close(0u32.into(), b"test reconnect");
        wait_specific_tunnel_state(&mut events_a, &auto_rule.id, TunnelRuntimeState::Starting)
            .await;
        wait_specific_tunnel_state(&mut events_a, &auto_rule.id, TunnelRuntimeState::Running).await;

        handle_b
            .update_tunnel_settings(Vec::new(), Vec::new())
            .unwrap();
        let mut denied = tokio::net::TcpStream::connect(auto_rule.listen)
            .await
            .unwrap();
        denied.write_all(b"no longer authorized").await.unwrap();
        let mut discarded = Vec::new();
        let _ = denied.read_to_end(&mut discarded).await;
        assert!(
            discarded.is_empty(),
            "unauthorized target must not return data"
        );
        time::timeout(Duration::from_secs(3), async {
            while let Some(event) = events_a.recv().await {
                if let SessionEvent::TunnelError { rule_id, detail } = event
                    && rule_id == auto_rule.id
                {
                    assert!(detail.contains("不在允许转发的列表里"), "{detail}");
                    return;
                }
            }
            panic!("unauthorized target should produce a detailed tunnel error");
        })
        .await
        .unwrap();

        assert!(matches!(
            handle_a.start_tunnel_rule(auto_rule.id.clone()),
            Ok(())
        ));
        assert_eq!(
            auto_rule.peer_node_id,
            identity_b.node_id().to_hex(),
            "the runtime uses the rule's peer binding"
        );
        handle_a.stop_tunnel_rule(auto_rule.id.clone()).unwrap();
        assert_eq!(
            wait_tunnel_state(&mut events_a, &auto_rule.id).await,
            TunnelRuntimeState::Stopped
        );

        assert!(
            tokio::net::TcpStream::connect(auto_rule.listen)
                .await
                .is_err()
        );
        for delete in [false, true] {
            handle_a
                .update_tunnel_settings(Vec::new(), vec![auto_rule.clone()])
                .unwrap();
            wait_specific_tunnel_state(&mut events_a, &auto_rule.id, TunnelRuntimeState::Running)
                .await;
            time::timeout(
                Duration::from_secs(2),
                handle_a.revoke_tunnel_rule(auto_rule.id.clone(), delete),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(
                tokio::net::TcpStream::connect(auto_rule.listen)
                    .await
                    .is_err(),
                "acknowledged revoke must release listener"
            );
            let rebound = TcpListener::bind(auto_rule.listen)
                .await
                .expect("local port must be reusable");
            drop(rebound);
            wait_specific_tunnel_state(&mut events_a, &auto_rule.id, TunnelRuntimeState::Stopped)
                .await;
        }

        handle_a.shutdown();
        handle_b.shutdown();
        drop((handle_a, handle_b));
        echo_task.abort();
        server.abort();
        let _ = server.await;
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
    #[tokio::test]
    async fn explicit_mapping_refresh_preserves_unchanged_authenticated_connection() {
        let (addr, server) = start_local_server().await;
        let ia = Identity::generate();
        let ib = Identity::generate();
        let (a, mut ea) = spawn(ia.clone(), local_config(addr)).unwrap();
        let (b, mut eb) = spawn(ib.clone(), local_config(addr)).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        a.connect_peer(ib.node_id()).unwrap();
        wait_connected(&mut ea, &[ib.node_id()]).await;
        wait_connected(&mut eb, &[ia.node_id()]).await;
        let ca = inspect(&a).await[&ib.node_id()].1.clone();
        let cb = inspect(&b).await[&ia.node_id()].1.clone();
        while ea.try_recv().is_ok() {}
        while eb.try_recv().is_ok() {}
        a.connect_peer(ib.node_id()).unwrap();
        for events in [&mut ea, &mut eb] {
            time::timeout(Duration::from_secs(3),async {
                loop { if matches!(events.recv().await.unwrap(),SessionEvent::Diagnostic(s) if s=="地址核对完毕，现有认证连接继续使用") { break; } }
            }).await.expect("must observe processed unchanged candidate response, not just queued Connect");
        }
        assert_eq!(
            inspect(&a).await[&ib.node_id()].1.stable_id(),
            ca.stable_id()
        );
        assert_eq!(
            inspect(&b).await[&ia.node_id()].1.stable_id(),
            cb.stable_id()
        );
        let send = async {
            let mut s = ca.open_uni().await.unwrap();
            s.write_all(b"unchanged mapping live").await.unwrap();
            s.finish().unwrap();
            s.stopped().await.unwrap();
        };
        let receive = async {
            let mut r = cb.accept_uni().await.unwrap();
            assert_eq!(r.read_to_end(128).await.unwrap(), b"unchanged mapping live");
        };
        time::timeout(Duration::from_secs(3), async {
            tokio::join!(send, receive);
        })
        .await
        .unwrap();
        assert!(ca.close_reason().is_none());
        assert!(cb.close_reason().is_none());
        a.shutdown();
        b.shutdown();
        drop((a, b));
        server.abort();
        let _ = server.await;
    }
    fn security_config(
        path: &std::path::Path,
        devices: Vec<super::super::trusted_devices::TrustedDevice>,
    ) {
        super::super::config::DesktopConfig::save_remote_auth(path, test_verifier()).unwrap();
        super::super::config::DesktopConfig::save_trusted_devices(path, devices).unwrap();
    }
    async fn wait_grants(
        events: &mut mpsc::Receiver<SessionEvent>,
        peer: NodeId,
        expected: RemoteAuthorization,
    ) {
        time::timeout(Duration::from_secs(20), async {
            loop {
                if let SessionEvent::PeerState {
                    peer: id,
                    state: PeerLifecycle::Connected(auth),
                    ..
                } = events
                    .recv()
                    .await
                    .expect("session closed before expected grants")
                    && id == peer
                    && auth == expected
                {
                    return;
                }
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn explicit_trust_requires_inbound_password_and_failed_save_cannot_grant() {
        use super::super::{config::DesktopConfig, remote_auth::AuthorizationGrant};
        let root = std::env::temp_dir().join(format!(
            "p2p-explicit-trust-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("settings.json");
        let client_path = root.join("client.json");
        security_config(&path, vec![]);
        security_config(&client_path, vec![]);
        let (signal, server) = start_local_server().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let mut cb = auth_config(signal);
        cb.config_path = Some(path.clone());
        let mut ca = auth_config(signal);
        ca.config_path = Some(client_path.clone());
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        let expected_a = RemoteAuthorization {
            inbound: AuthorizationGrant::default(),
            outbound: AuthorizationGrant::password(true),
        };
        let expected_b = RemoteAuthorization {
            inbound: AuthorizationGrant::password(true),
            outbound: AuthorizationGrant::default(),
        };
        wait_grants(&mut ea, b.node_id(), expected_a).await;
        wait_grants(&mut eb, a.node_id(), expected_b).await;
        let client_generation = inspect(&ha).await[&b.node_id()].0;
        let error = ha
            .change_trusted_device(TrustedDeviceChange::Trust {
                peer: b.node_id(),
                generation: client_generation,
                display_name: "家里 Ubuntu".into(),
            })
            .await
            .unwrap_err();
        assert!(error.contains("本机密码"));
        assert!(
            super::super::config::SettingsDraft::from_config(
                DesktopConfig::load(&client_path).unwrap().unwrap()
            )
            .trusted_devices
            .is_empty()
        );
        assert!(
            super::super::config::SettingsDraft::from_config(
                DesktopConfig::load(&path).unwrap().unwrap()
            )
            .trusted_devices
            .is_empty()
        );
        let (generation, connection) = inspect(&hb).await[&a.node_id()].clone();
        assert!(
            hb.change_trusted_device(TrustedDeviceChange::Trust {
                peer: a.node_id(),
                generation: generation.wrapping_add(1),
                display_name: "stale".into()
            })
            .await
            .is_err()
        );
        let backup = root.join("saved.json");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(
            hb.change_trusted_device(TrustedDeviceChange::Trust {
                peer: a.node_id(),
                generation,
                display_name: "device".into()
            })
            .await
            .is_err()
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        assert!(
            super::super::config::SettingsDraft::from_config(
                DesktopConfig::load(&path).unwrap().unwrap()
            )
            .trusted_devices
            .is_empty()
        );
        let devices = change_trusted_device(
            Some(&hb),
            &path,
            TrustedDeviceChange::Trust {
                peer: a.node_id(),
                generation,
                display_name: "家里 Ubuntu".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(devices[0].node_id, a.node_id().to_hex());
        let mixed_b = RemoteAuthorization {
            inbound: AuthorizationGrant {
                password: true,
                trusted_device: true,
            },
            outbound: AuthorizationGrant::default(),
        };
        let mixed_a = RemoteAuthorization {
            inbound: AuthorizationGrant::default(),
            outbound: mixed_b.inbound,
        };
        wait_grants(&mut ea, b.node_id(), mixed_a).await;
        wait_grants(&mut eb, a.node_id(), mixed_b).await;
        hb.change_trusted_device(TrustedDeviceChange::Rename {
            peer: a.node_id(),
            display_name: "renamed".into(),
        })
        .await
        .unwrap();
        assert_eq!(
            inspect(&hb).await[&a.node_id()].1.stable_id(),
            connection.stable_id()
        );
        change_trusted_device(
            Some(&hb),
            &path,
            TrustedDeviceChange::Revoke { peer: a.node_id() },
        )
        .await
        .unwrap();
        wait_grants(&mut ea, b.node_id(), expected_a).await;
        wait_grants(&mut eb, a.node_id(), expected_b).await;
        assert!(connection.close_reason().is_none());
        hb.change_trusted_device(TrustedDeviceChange::Trust {
            peer: a.node_id(),
            generation,
            display_name: "retained".into(),
        })
        .await
        .unwrap();
        let verifier =
            RemoteVerifier::create(&SecretPassword::new("Change9".into()).unwrap()).unwrap();
        DesktopConfig::save_remote_auth(&path, verifier.clone()).unwrap();
        hb.update_remote_auth(verifier).await.unwrap();
        assert_eq!(
            super::super::config::SettingsDraft::from_config(
                DesktopConfig::load(&path).unwrap().unwrap()
            )
            .trusted_devices[0]
                .node_id,
            a.node_id().to_hex()
        );
        assert!(
            hb.change_trusted_device(TrustedDeviceChange::Trust {
                peer: a.node_id(),
                generation,
                display_name: "closed".into()
            })
            .await
            .is_err()
        );
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn dead_session_allows_durable_rename_revoke_but_never_trust_or_restart_grant() {
        use super::super::{
            config::{DesktopConfig, SettingsDraft},
            remote_auth::AuthorizationGrant,
            trusted_devices::TrustedDevice,
        };
        let root =
            std::env::temp_dir().join(format!("p2p-dead-trust-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("settings.json");
        let a = Identity::generate();
        let b = Identity::generate();
        let other = Identity::generate().node_id();
        security_config(
            &path,
            vec![
                TrustedDevice::new(a.node_id(), "same name".into(), Some("100000124".into())),
                TrustedDevice::new(other, "same name".into(), Some("100000124".into())),
            ],
        );
        let load = || SettingsDraft::from_config(DesktopConfig::load(&path).unwrap().unwrap());
        let (signal, server) = start_local_server().await;
        let mut cb = auth_config(signal);
        cb.config_path = Some(path.clone());
        cb.trusted_devices = load().trusted_devices;
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        let (ha, mut ea) = spawn(a.clone(), auth_config(signal)).unwrap();
        wait_signal_online(&mut eb).await;
        wait_signal_online(&mut ea).await;
        ha.connect_peer_trusted(b.node_id()).unwrap();
        let only_trust = AuthorizationGrant {
            password: false,
            trusted_device: true,
        };
        wait_grants(
            &mut ea,
            b.node_id(),
            RemoteAuthorization {
                inbound: AuthorizationGrant::default(),
                outbound: only_trust,
            },
        )
        .await;
        wait_grants(
            &mut eb,
            a.node_id(),
            RemoteAuthorization {
                inbound: only_trust,
                outbound: AuthorizationGrant::default(),
            },
        )
        .await;
        let generation = inspect(&hb).await[&a.node_id()].0;
        let error = hb
            .change_trusted_device(TrustedDeviceChange::Trust {
                peer: a.node_id(),
                generation,
                display_name: "same name".into(),
            })
            .await
            .unwrap_err();
        assert!(
            error.contains("本机密码"),
            "Trusted-only must fail the password gate: {error}"
        );
        hb.shutdown();
        ha.shutdown();
        time::timeout(Duration::from_secs(5), async {
            while hb.is_running() || ha.is_running() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sessions must close their command channels");
        // Keep the closed handle, exactly as the shell does after network exit.
        let renamed = change_trusted_device(
            Some(&hb),
            &path,
            TrustedDeviceChange::Rename {
                peer: a.node_id(),
                display_name: "renamed offline".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(renamed[0].display_name, "renamed offline");
        assert_eq!(load().trusted_devices, renamed);
        let saved = std::fs::read(&path).unwrap();
        assert!(
            change_trusted_device(
                Some(&hb),
                &path,
                TrustedDeviceChange::Trust {
                    peer: Identity::generate().node_id(),
                    generation,
                    display_name: "new offline".into(),
                }
            )
            .await
            .is_err()
        );
        assert!(
            change_trusted_device(
                None,
                &path,
                TrustedDeviceChange::Trust {
                    peer: a.node_id(),
                    generation,
                    display_name: "no session".into(),
                }
            )
            .await
            .is_err()
        );
        assert!(
            change_trusted_device(
                Some(&hb),
                &path,
                TrustedDeviceChange::Rename {
                    peer: a.node_id(),
                    display_name: "\n".into(),
                }
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), saved);
        #[cfg(unix)]
        {
            let link = root.join("linked.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(
                change_trusted_device(
                    Some(&hb),
                    &link,
                    TrustedDeviceChange::Revoke { peer: a.node_id() }
                )
                .await
                .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), saved);
        }
        std::fs::write(&path, b"invalid config").unwrap();
        assert!(
            change_trusted_device(
                Some(&hb),
                &path,
                TrustedDeviceChange::Revoke { peer: a.node_id() }
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"invalid config");
        std::fs::write(&path, &saved).unwrap();
        let revoked = change_trusted_device(
            Some(&hb),
            &path,
            TrustedDeviceChange::Revoke { peer: a.node_id() },
        )
        .await
        .unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].node_id, other.to_hex());
        assert_eq!(load().trusted_devices, revoked);
        let renamed = change_trusted_device(
            None,
            &path,
            TrustedDeviceChange::Rename {
                peer: other,
                display_name: "no session rename".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(load().trusted_devices, renamed);
        drop((ha, hb));
        // New real QUIC/Ed25519 sessions load the edited file: no password and
        // no trusted identity for A must fail, despite matching display metadata.
        let mut cb = auth_config(signal);
        cb.config_path = Some(path.clone());
        cb.trusted_devices = load().trusted_devices;
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        let (ha, mut ea) = spawn(a.clone(), auth_config(signal)).unwrap();
        wait_signal_online(&mut eb).await;
        wait_signal_online(&mut ea).await;
        ha.connect_peer_trusted(b.node_id()).unwrap();
        time::timeout(Duration::from_secs(20), async {
            while let Some(event) = ea.recv().await {
                match event {
                    SessionEvent::PeerState {
                        peer,
                        state: PeerLifecycle::Failed(detail),
                        ..
                    } if peer == b.node_id() => {
                        assert!(
                            detail.contains("认证失败"),
                            "expected authentication denial, got: {detail}"
                        );
                        return;
                    }
                    SessionEvent::PeerState {
                        peer,
                        state: PeerLifecycle::Connected(auth),
                        ..
                    } if peer == b.node_id() => {
                        panic!("revoked peer reauthorized after restart: {auth:?}")
                    }
                    _ => {}
                }
            }
            panic!("restarted session closed before authorization failure");
        })
        .await
        .expect("passwordless revoked peer must fail on a fresh transport");
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn restart_auto_start_uses_fresh_identity_bound_trust_and_revoke_closes_running_tunnel() {
        use super::super::{
            config::{AllowedForwardTarget, DesktopConfig, TunnelRule},
            remote_auth::AuthorizationGrant,
            trusted_devices::TrustedDevice,
        };
        let root = std::env::temp_dir().join(format!(
            "p2p-trusted-restart-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("settings.json");
        let a = Identity::generate();
        let b = Identity::generate();
        security_config(
            &path,
            vec![TrustedDevice::new(
                a.node_id(),
                "device".into(),
                Some("100000124".into()),
            )],
        );
        let (signal, server) = start_local_server().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let mut rule = TunnelRule::new(
            "trusted echo",
            b.node_id().to_hex(),
            listen.port(),
            target.local_addr().unwrap(),
        );
        rule.auto_start = true;
        let mut ca = auth_config(signal);
        ca.tunnel_rules = vec![rule.clone()];
        let mut cb = auth_config(signal);
        cb.config_path = Some(path.clone());
        cb.trusted_devices = DesktopConfig::load(&path)
            .unwrap()
            .map(super::super::config::SettingsDraft::from_config)
            .unwrap()
            .trusted_devices;
        cb.allowed_forward_targets = vec![AllowedForwardTarget::new(
            "echo",
            target.local_addr().unwrap(),
            vec![a.node_id().to_hex()],
        )];
        // Spawn the persisted owner first, then boot the passwordless auto-start client.
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut eb).await;
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        let only_trust = AuthorizationGrant {
            password: false,
            trusted_device: true,
        };
        wait_grants(
            &mut eb,
            a.node_id(),
            RemoteAuthorization {
                inbound: only_trust,
                outbound: AuthorizationGrant::default(),
            },
        )
        .await;
        let connection = inspect(&hb).await[&a.node_id()].1.clone();
        let mut tcp = tokio::net::TcpStream::connect(listen).await.unwrap();
        tcp.write_all(b"request").await.unwrap();
        let (mut destination, _) = time::timeout(Duration::from_secs(3), target.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = [0; 7];
        destination.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"request");
        hb.change_trusted_device(TrustedDeviceChange::Revoke { peer: a.node_id() })
            .await
            .unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::WaitingAuthorization)
            .await;
        time::timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::TcpStream::connect(listen).await.is_err() {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut tail = Vec::new();
        let result = time::timeout(Duration::from_secs(3), tcp.read_to_end(&mut tail)).await;
        assert!(result.is_ok());
        assert!(tail.is_empty());
        assert!(connection.close_reason().is_none()); // Unrelated reverse rights are not killed by closing the whole transport.
        assert!(
            super::super::config::SettingsDraft::from_config(
                DesktopConfig::load(&path).unwrap().unwrap()
            )
            .trusted_devices
            .is_empty()
        );
        // Explicit password reconnect restores the listener; removed trust never follows it.
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        wait_specific_tunnel_state(&mut ea, &rule.id, TunnelRuntimeState::Running).await;
        wait_grants(
            &mut eb,
            a.node_id(),
            RemoteAuthorization {
                inbound: AuthorizationGrant::password(true),
                outbound: AuthorizationGrant::default(),
            },
        )
        .await;
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn revoking_trusted_file_direction_keeps_reverse_password_transfer_alive() {
        use super::super::{
            remote_auth::AuthorizationGrant, task_model::TaskState, task_store::TaskStore,
            transfer::TransferService, trusted_devices::TrustedDevice,
        };
        let root =
            std::env::temp_dir().join(format!("p2p-trusted-files-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(root.join("a-receive")).unwrap();
        std::fs::create_dir_all(root.join("b-receive")).unwrap();
        let (a_store, _) = TaskStore::open(&root.join("a-state/tasks.json")).unwrap();
        let (b_store, _) = TaskStore::open(&root.join("b-state/tasks.json")).unwrap();
        let a_service = TransferService::new(a_store, root.join("a-receive"));
        let b_service = TransferService::new(b_store, root.join("b-receive"));
        let a = Identity::generate();
        let b = Identity::generate();
        let device = TrustedDevice::new(a.node_id(), "device".into(), None);
        let path = root.join("settings.json");
        security_config(&path, vec![device.clone()]);
        let (signal, server) = start_local_server().await;
        let mut ca = auth_config(signal);
        ca.transfer = Some(a_service.clone());
        let mut cb = auth_config(signal);
        cb.transfer = Some(b_service.clone());
        cb.trusted_devices = vec![device];
        cb.config_path = Some(path);
        let (ha, mut ea) = spawn(a.clone(), ca).unwrap();
        let (hb, mut eb) = spawn(b.clone(), cb).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        hb.connect_peer_with_password(a.node_id(), test_password())
            .unwrap();
        let trusted = AuthorizationGrant {
            password: false,
            trusted_device: true,
        };
        wait_grants(
            &mut ea,
            b.node_id(),
            RemoteAuthorization {
                inbound: AuthorizationGrant::password(true),
                outbound: trusted,
            },
        )
        .await;
        wait_grants(
            &mut eb,
            a.node_id(),
            RemoteAuthorization {
                inbound: trusted,
                outbound: AuthorizationGrant::password(true),
            },
        )
        .await;
        let (a_reached, a_wait) = oneshot::channel();
        let (a_release, a_resume) = oneshot::channel();
        *a_service.first_chunk_gate.lock().unwrap() = Some((a_reached, a_resume));
        let (b_reached, b_wait) = oneshot::channel();
        let (b_release, b_resume) = oneshot::channel();
        *b_service.first_chunk_gate.lock().unwrap() = Some((b_reached, b_resume));
        let bytes = vec![0x5a; 1024 * 1024];
        std::fs::write(root.join("trusted.bin"), &bytes).unwrap();
        std::fs::write(root.join("password.bin"), &bytes).unwrap();
        ha.send_file(b.node_id(), root.join("trusted.bin")).unwrap();
        hb.send_file(a.node_id(), root.join("password.bin"))
            .unwrap();
        time::timeout(Duration::from_secs(10), async {
            a_wait.await.unwrap();
            b_wait.await.unwrap();
        })
        .await
        .unwrap();
        hb.change_trusted_device(TrustedDeviceChange::Revoke { peer: a.node_id() })
            .await
            .unwrap();
        wait_grants(
            &mut ea,
            b.node_id(),
            RemoteAuthorization {
                inbound: AuthorizationGrant::password(true),
                outbound: AuthorizationGrant::default(),
            },
        )
        .await;
        a_release.send(()).unwrap();
        time::timeout(Duration::from_secs(10), async {
            loop {
                let tasks = a_service.snapshot().await.unwrap();
                let remote = b_service.snapshot().await.unwrap();
                let kept = tasks.iter().any(|t| {
                    t.direction() == super::super::task_model::TaskDirection::Receive
                        && t.state() == TaskState::Completed
                });
                let revoked = remote.iter().any(|t| {
                    t.direction() == super::super::task_model::TaskDirection::Receive
                        && t.state() == TaskState::Interrupted
                });
                if kept && revoked {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(b_release.send(()).is_err());
        assert_eq!(
            std::fs::read(root.join("a-receive/password.bin")).unwrap(),
            bytes
        );
        assert!(!root.join("b-receive/trusted.bin").exists());
        assert!(inspect(&ha).await[&b.node_id()].1.close_reason().is_none());
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
        drop((a_service, b_service));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn explicit_passwordless_reconnect_does_not_reuse_old_in_memory_password() {
        let (signal, server) = start_local_server().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let (ha, mut ea) = spawn(a.clone(), auth_config(signal)).unwrap();
        let (hb, mut eb) = spawn(b.clone(), auth_config(signal)).unwrap();
        wait_signal_online(&mut ea).await;
        wait_signal_online(&mut eb).await;
        ha.connect_peer_with_password(b.node_id(), test_password())
            .unwrap();
        wait_authorization(&mut ea, b.node_id()).await;
        wait_authorization(&mut eb, a.node_id()).await;
        inspect(&ha).await[&b.node_id()]
            .1
            .close(0u32.into(), b"test fresh passwordless session");
        ha.connect_peer_trusted(b.node_id()).unwrap();
        wait_failed(&mut ea).await;
        wait_failed(&mut eb).await;
        assert!(inspect(&ha).await.is_empty());
        assert!(inspect(&hb).await.is_empty());
        ha.shutdown();
        hb.shutdown();
        drop((ha, hb));
        server.abort();
    }
}
