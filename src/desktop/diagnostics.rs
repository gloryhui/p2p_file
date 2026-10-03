//! Typed, bounded connection evidence. Raw errors, endpoints and credentials
//! never enter this model; exports are generated from an explicit whitelist.
use super::network_state::{MAX_PEERS, NetworkLifecycle, PeerLifecycle};
use crate::{identity::NodeId, net::AddressFamily};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

const MAX_STAGES: usize = 8;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Unknown,
    Lookup,
    Punch,
    Identity,
    Negotiate,
    Password,
    Ready,
    Disconnected,
    Failed,
}
impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "未知",
            Self::Lookup => "等待对端候选",
            Self::Punch => "UDP / QUIC 建连",
            Self::Identity => "设备身份认证",
            Self::Negotiate => "能力协商",
            Self::Password => "访问授权",
            Self::Ready => "设备会话已连接",
            Self::Disconnected => "已断开",
            Self::Failed => "失败",
        }
    }
    fn suggestion(self) -> &'static str {
        match self {
            Self::Unknown => "在主界面连接设备，取得本次连接的阶段数据。",
            Self::Lookup => "确认双方使用同一信令服务且对端已上线；核对设备 ID 后在主界面重试。",
            Self::Punch => {
                "检查双方 UDP 防火墙和可用 IPv4/IPv6；必要时配置 Relay，再在主界面重试。"
            }
            Self::Identity => {
                "核对真实设备身份；不要以信令登记或 Relay 分配代替身份认证，重新连接设备。"
            }
            Self::Negotiate => "确认双方软件版本支持桌面协议与所需能力，更新后重新连接。",
            Self::Password => "核对对方访问密码或由接收方明确授权可信设备，再在主界面重新连接。",
            Self::Ready => "按发/收权限操作；若连接断开，检查网络后在主界面重试。",
            Self::Disconnected | Self::Failed => {
                "查看最近失败阶段并按对应建议排查，在主界面重试连接。"
            }
        }
    }
    fn terminal(self) -> bool {
        matches!(self, Self::Disconnected | Self::Failed)
    }
}
#[derive(Clone, Copy)]
enum Signal {
    Unconfigured,
    Preparing,
    Connecting,
    Online,
    Retrying(u32, Duration),
    Failed,
}
impl Signal {
    fn label(self) -> String {
        match self {
            Self::Unconfigured => "未配置".into(),
            Self::Preparing => "准备 UDP 网络".into(),
            Self::Connecting => "连接信令中".into(),
            Self::Online => "信令在线（不代表业务认证）".into(),
            Self::Retrying(attempt, delay) => format!(
                "等待重连：第 {attempt} 次，退避 {:.1}s",
                delay.as_secs_f64()
            ),
            Self::Failed => "网络准备或信令失败".into(),
        }
    }
}
struct Peer {
    generation: u64,
    stage: Stage,
    since: Instant,
    started: Option<Instant>,
    finished: Option<Instant>,
    route: Option<(bool, AddressFamily)>,
    candidates: Option<(usize, usize)>,
    rights: Option<(bool, bool)>,
    failure: Option<Stage>,
    history: VecDeque<(Stage, Duration)>,
}
impl Peer {
    fn new(generation: u64, now: Instant, failure: Option<Stage>) -> Self {
        Self {
            generation,
            stage: Stage::Unknown,
            since: now,
            started: None,
            finished: None,
            route: None,
            candidates: None,
            rights: None,
            failure,
            history: VecDeque::new(),
        }
    }
}
pub(super) struct Diagnostics {
    signal: Signal,
    signal_since: Instant,
    signal_finished: Option<Instant>,
    signal_failure: Option<&'static str>,
    families: Option<(bool, bool)>,
    relay: Option<bool>,
    peers: HashMap<NodeId, Peer>,
    retired: u64,
}
impl Diagnostics {
    pub fn new(now: Instant) -> Self {
        Self {
            signal: Signal::Unconfigured,
            signal_since: now,
            signal_finished: None,
            signal_failure: None,
            families: None,
            relay: None,
            peers: HashMap::new(),
            retired: 0,
        }
    }
    pub fn reset(&mut self, now: Instant) {
        *self = Self::new(now);
        self.signal = Signal::Preparing;
    }
    pub fn network_families(&mut self, ipv4: bool, ipv6: bool, relay: bool) {
        self.families = Some((ipv4, ipv6));
        self.relay = Some(relay);
        if matches!(self.signal, Signal::Preparing) {
            self.signal = Signal::Connecting;
        }
    }
    pub fn network(&mut self, state: &NetworkLifecycle, now: Instant) {
        match state {
            NetworkLifecycle::Unconfigured => self.signal = Signal::Unconfigured,
            NetworkLifecycle::ConnectingSignal => {
                self.signal = if self.families.is_none() {
                    Signal::Preparing
                } else {
                    Signal::Connecting
                };
                self.signal_since = now;
                self.signal_finished = None;
            }
            NetworkLifecycle::SignalOnline => {
                self.signal = Signal::Online;
                self.signal_finished.get_or_insert(now);
            }
            NetworkLifecycle::ReconnectingSignal { attempt, delay } => {
                if delay.is_zero() {
                    self.signal = Signal::Connecting;
                    self.signal_since = now;
                    self.signal_finished = None;
                } else {
                    self.signal = Signal::Retrying(*attempt, *delay);
                    self.signal_finished.get_or_insert(now);
                }
                self.signal_failure = Some("信令连接或登记/心跳");
            }
            NetworkLifecycle::Failed { .. } => {
                self.signal = Signal::Failed;
                self.signal_finished = Some(now);
                self.signal_failure = Some(if self.families.is_some() {
                    "信令连接或登记"
                } else {
                    "UDP 网络准备"
                });
            }
            NetworkLifecycle::Disconnected { peer: None, .. } => {
                self.signal = Signal::Failed;
                self.signal_finished = Some(now);
                self.signal_failure = Some("信令断开");
            }
            _ => {} // Peer activity cannot promote or demote signaling evidence.
        }
    }
    fn entry(&mut self, id: NodeId, generation: u64, now: Instant) -> Option<&mut Peer> {
        if let Some(old) = self.peers.get(&id) {
            if generation < old.generation {
                return None;
            }
            if generation > old.generation {
                let failure = old.failure;
                self.peers.insert(id, Peer::new(generation, now, failure));
            }
        } else {
            if generation <= self.retired {
                return None;
            }
            if self.peers.len() >= MAX_PEERS {
                let oldest = self
                    .peers
                    .iter()
                    .filter(|(_, p)| p.stage.terminal())
                    .min_by_key(|(_, p)| p.generation)
                    .map(|(id, p)| (*id, p.generation));
                let (id, retired) = oldest?;
                self.peers.remove(&id);
                self.retired = self.retired.max(retired);
            }
            self.peers.insert(id, Peer::new(generation, now, None));
        }
        self.peers.get_mut(&id)
    }
    pub fn candidates(
        &mut self,
        id: NodeId,
        generation: u64,
        ipv4: usize,
        ipv6: usize,
        now: Instant,
    ) {
        if let Some(peer) = self.entry(id, generation, now)
            && !peer.stage.terminal()
        {
            peer.candidates = Some((ipv4, ipv6));
        }
    }
    pub fn transport(
        &mut self,
        id: NodeId,
        generation: u64,
        relay: bool,
        family: AddressFamily,
        now: Instant,
    ) {
        if let Some(peer) = self.entry(id, generation, now)
            && !peer.stage.terminal()
        {
            peer.route = Some((relay, family));
        }
    }
    pub fn peer(&mut self, id: NodeId, generation: u64, state: &PeerLifecycle, now: Instant) {
        let Some(peer) = self.entry(id, generation, now) else {
            return;
        };
        let stage = match state {
            PeerLifecycle::PeerPending => Stage::Lookup,
            PeerLifecycle::Punching => Stage::Punch,
            PeerLifecycle::Authenticating => Stage::Identity,
            PeerLifecycle::Negotiating => Stage::Negotiate,
            PeerLifecycle::RemoteAuthPending => Stage::Password,
            PeerLifecycle::Connected(_) => Stage::Ready,
            PeerLifecycle::Disconnected => Stage::Disconnected,
            PeerLifecycle::Failed(_) => Stage::Failed,
        };
        peer.rights = match state {
            PeerLifecycle::Connected(a) => Some((a.inbound_authorized(), a.outbound_authorized())),
            _ => None,
        };
        if stage == peer.stage {
            return;
        }
        if peer.stage != Stage::Unknown {
            peer.history
                .push_back((peer.stage, now.saturating_duration_since(peer.since)));
            if peer.history.len() > MAX_STAGES {
                peer.history.pop_front();
            }
        }
        if stage.terminal() {
            if !peer.stage.terminal() {
                peer.failure = Some(peer.stage);
            }
            peer.finished.get_or_insert(now);
            peer.route = None;
        } else if stage != Stage::Ready && peer.started.is_none() {
            peer.started = Some(now);
        }
        if stage == Stage::Ready {
            peer.finished.get_or_insert(now);
        }
        peer.stage = stage;
        peer.since = now;
    }
    pub fn text(&self, now: Instant) -> String {
        let mut lines = vec![
            "P2P File 连接诊断 v1（脱敏摘要）".to_owned(),
            format!("信令：{}", self.signal.label()),
        ];
        let signal_time = if matches!(self.signal, Signal::Unconfigured) {
            "未知".into()
        } else {
            format!(
                "{:.1}s",
                self.signal_finished
                    .unwrap_or(now)
                    .saturating_duration_since(self.signal_since)
                    .as_secs_f64()
            )
        };
        lines.push(format!("本次网络准备/信令尝试耗时：{signal_time}"));
        lines.push(format!(
            "信令最近失败阶段：{}",
            self.signal_failure.unwrap_or("未知 / 尚未观察到失败")
        ));
        lines.push(match self.families {
            Some((v4, v6)) => format!("本机 UDP：IPv4 {}；IPv6 {}", available(v4), available(v6)),
            None => "本机 UDP：IPv4 未知；IPv6 未知".into(),
        });
        lines.push(format!(
            "Relay 配置：{}",
            self.relay.map_or("未知", |r| if r {
                "已配置；分配不等于认证"
            } else {
                "未配置"
            })
        ));
        if !matches!(self.signal, Signal::Online) {
            lines.push("建议：核对设置中的信令主机/端口（TLS 启用时核对 CA/主机名），检查网络、防火墙和服务运行状态；恢复后会自动重连。".into());
        }
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.sort_by_key(|p| p.generation);
        if peers.is_empty() {
            lines.push("设备连接：未知 / 本次运行尚无连接阶段数据".into());
        }
        for (index, peer) in peers.into_iter().enumerate() {
            lines.push(format!(
                "连接 {}（本摘要序号）：{}",
                index + 1,
                peer.stage.label()
            ));
            lines.push(match peer.route {
                Some((relay, family)) => format!(
                    "当前已验证传输：{} {family}；业务权限另列",
                    if relay { "Relay" } else { "Direct" }
                ),
                None => "当前已验证传输：未知 / 尚无可用传输".into(),
            });
            lines.push(match peer.candidates {
                Some((v4, v6)) => format!("对端候选：IPv4 {v4}；IPv6 {v6}"),
                None => "对端候选：未知".into(),
            });
            lines.push(match peer.rights {
                Some((receive, send)) => format!(
                    "本机会话权限：接收 {}；发送 {}",
                    allowed(receive),
                    allowed(send)
                ),
                None => "本机会话权限：未知 / 尚未获得业务授权状态".into(),
            });
            lines.push(format!(
                "本次连接尝试耗时：{}",
                peer.started
                    .map_or("未知（未观察到起始阶段）".to_owned(), |start| format!(
                        "{:.1}s",
                        peer.finished
                            .unwrap_or(now)
                            .saturating_duration_since(start)
                            .as_secs_f64()
                    ))
            ));
            lines.push(format!(
                "最近失败阶段：{}",
                peer.failure.map_or("未知 / 尚未观察到失败", Stage::label)
            ));
            for (stage, elapsed) in &peer.history {
                lines.push(format!(
                    "已观察阶段：{} {:.1}s",
                    stage.label(),
                    elapsed.as_secs_f64()
                ));
            }
            lines.push(format!(
                "建议：{}",
                peer.failure
                    .filter(|_| peer.stage.terminal())
                    .unwrap_or(peer.stage)
                    .suggestion()
            ));
        }
        lines.push("耗时取本地收到阶段事件的单调时钟：从首次非终态至首次会话连接/失败/断开，连接后不累计在线时长；未观察到起点时显示未知。".into());
        lines.push("摘要只输出固定阶段、路径类型、地址族、数量和耗时；不含密码、令牌、原始错误、IP、设备标识、主机名、文件名或路径。".into());
        lines.join("\n") + "\n"
    }
}
fn available(value: bool) -> &'static str {
    if value { "可用" } else { "不可用" }
}
fn allowed(value: bool) -> &'static str {
    if value { "已授权" } else { "未授权" }
}

pub(super) fn export(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{desktop::remote_auth::RemoteAuthorization, identity::Identity};
    #[test]
    fn paths_do_not_grant_business_rights_and_attempt_time_stops_at_connection() {
        let now = Instant::now();
        let peer = Identity::generate().node_id();
        let mut model = Diagnostics::new(now);
        assert!(model.text(now).contains("IPv4 未知；IPv6 未知"));
        model.reset(now);
        model.network_families(true, false, true);
        model.network(
            &NetworkLifecycle::SignalOnline,
            now + Duration::from_secs(2),
        );
        model.peer(peer, 1, &PeerLifecycle::PeerPending, now);
        model.peer(
            peer,
            1,
            &PeerLifecycle::Punching,
            now + Duration::from_secs(1),
        );
        model.candidates(peer, 1, 2, 0, now);
        model.transport(
            peer,
            1,
            true,
            AddressFamily::Ipv4,
            now + Duration::from_secs(2),
        );
        let text = model.text(now + Duration::from_secs(3));
        assert!(text.contains("Relay IPv4"));
        assert!(text.contains("尚未获得业务授权状态"));
        assert!(!text.contains("设备会话已连接"));
        model.peer(
            peer,
            1,
            &PeerLifecycle::Connected(RemoteAuthorization::BOTH),
            now + Duration::from_secs(4),
        );
        let later = model.text(now + Duration::from_secs(200));
        assert!(later.contains("本次连接尝试耗时：4.0s"));
        assert!(later.contains("本机会话权限：接收 已授权；发送 已授权"));
        model.peer(
            peer,
            1,
            &PeerLifecycle::Disconnected,
            now + Duration::from_secs(201),
        );
        assert_eq!(model.peers[&peer].route, None);
        assert!(
            model
                .text(now + Duration::from_secs(300))
                .contains("本次连接尝试耗时：4.0s")
        );
    }
    #[test]
    fn failure_stages_generations_unknown_start_and_sensitive_errors_are_fenced() {
        let now = Instant::now();
        let id = Identity::generate().node_id();
        let sensitive = format!(
            "password=S3cret token=hidden /Users/private/file 203.0.113.55 {}",
            id.to_hex()
        );
        let mut model = Diagnostics::new(now);
        model.peer(id, 1, &PeerLifecycle::Authenticating, now);
        model.peer(
            id,
            1,
            &PeerLifecycle::Failed(sensitive.clone()),
            now + Duration::from_secs(2),
        );
        assert!(model.text(now).contains("最近失败阶段：设备身份认证"));
        model.peer(
            id,
            2,
            &PeerLifecycle::Punching,
            now + Duration::from_secs(3),
        );
        model.transport(
            id,
            2,
            false,
            AddressFamily::Ipv6,
            now + Duration::from_secs(4),
        );
        model.peer(
            id,
            1,
            &PeerLifecycle::Failed(sensitive.clone()),
            now + Duration::from_secs(5),
        );
        model.transport(id, 1, true, AddressFamily::Ipv4, now);
        model.candidates(id, 1, 7, 0, now);
        assert_eq!(model.peers[&id].stage, Stage::Punch);
        assert_eq!(model.peers[&id].route, Some((false, AddressFamily::Ipv6)));
        assert!(model.peers[&id].candidates.is_none());
        model.network(&NetworkLifecycle::Failed { detail: sensitive }, now);
        let output = model.text(now);
        for private in [
            "S3cret",
            "hidden",
            "/Users/private",
            "203.0.113.55",
            &id.to_hex(),
            &id.short(),
        ] {
            assert!(!output.contains(private));
        }
        model.reset(now); // Session epoch replacement discards all old evidence.
        assert!(model.peers.is_empty());
        assert!(model.families.is_none());
        model.peer(
            id,
            1,
            &PeerLifecycle::Connected(RemoteAuthorization::BOTH),
            now,
        );
        assert!(model.text(now).contains("未知（未观察到起始阶段）"));
    }
    #[test]
    fn reconnect_clock_excludes_online_time_and_history_is_bounded() {
        let now = Instant::now();
        let mut model = Diagnostics::new(now);
        model.reset(now);
        model.network_families(true, true, false);
        model.network(
            &NetworkLifecycle::SignalOnline,
            now + Duration::from_secs(2),
        );
        model.network(
            &NetworkLifecycle::ReconnectingSignal {
                attempt: 1,
                delay: Duration::from_secs(1),
            },
            now + Duration::from_secs(500),
        );
        assert!(model.text(now).contains("网络准备/信令尝试耗时：2.0s"));
        model.network(
            &NetworkLifecycle::ReconnectingSignal {
                attempt: 1,
                delay: Duration::ZERO,
            },
            now + Duration::from_secs(501),
        );
        model.network(
            &NetworkLifecycle::SignalOnline,
            now + Duration::from_secs(504),
        );
        assert!(model.text(now).contains("网络准备/信令尝试耗时：3.0s"));
        let first = Identity::generate().node_id();
        for n in 1..=MAX_PEERS + 3 {
            let id = if n == 1 {
                first
            } else {
                Identity::generate().node_id()
            };
            model.peer(
                id,
                n as u64,
                &PeerLifecycle::Failed("raw private error".into()),
                now,
            );
        }
        assert_eq!(model.peers.len(), MAX_PEERS);
        model.transport(first, 1, true, AddressFamily::Ipv4, now);
        assert!(!model.peers.contains_key(&first));
        let id = Identity::generate().node_id();
        for n in 0..40 {
            model.peer(
                id,
                100,
                if n % 2 == 0 {
                    &PeerLifecycle::Punching
                } else {
                    &PeerLifecycle::Authenticating
                },
                now + Duration::from_secs(n),
            );
        }
        assert_eq!(model.peers[&id].history.len(), MAX_STAGES);
        assert!(model.text(now).len() < 32 * 1024);
    }
    #[test]
    fn diagnostic_export_never_overwrites_an_existing_file() {
        let dir = std::env::temp_dir().join(format!("p2p-diagnostic-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("report.txt");
        let text = Diagnostics::new(Instant::now()).text(Instant::now());
        export(&path, &text).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert_eq!(
            export(&path, "replacement").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
