#[cfg(unix)]
use std::fs::File;
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const APP_DIR_NAME: &str = "p2p_file";
const CONFIG_SCHEMA_VERSION: u32 = 4;
const LEGACY_CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("系统没有提供{0}目录")]
    DirectoryUnavailable(&'static str),
    #[error("配置文件损坏且原文件已保留：{0}")]
    Corrupt(String),
    #[error("设置无效：{0}")]
    Invalid(String),
    #[error("接收目录不可用：{0}")]
    ReceiveDirectoryUnavailable(String),
    #[error("接收目录没有写权限：{0}")]
    ReceiveDirectoryPermission(String),
    #[error("所选路径不是 UTF-8，当前设置格式不能安全保存该路径")]
    UnsupportedPathEncoding,
    #[error("文件系统操作失败：{0}")]
    Io(#[from] io::Error),
    #[error("JSON 配置读写失败：{0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub downloads_dir: Option<PathBuf>,
}

impl AppPaths {
    pub fn discover() -> Result<Self, ConfigError> {
        let config_base = dirs::config_dir().ok_or(ConfigError::DirectoryUnavailable("配置"))?;
        let data_base =
            dirs::data_local_dir().ok_or(ConfigError::DirectoryUnavailable("应用数据"))?;
        let downloads_dir = dirs::download_dir().filter(|path| {
            path.is_absolute()
                && path.to_str().is_some()
                && fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
        });

        Ok(Self {
            config_dir: config_base.join(APP_DIR_NAME),
            // On macOS dirs::config_dir and data_local_dir both resolve to
            // Library/Application Support. Keep identity/lock material in a
            // dedicated child directory so settings and key files stay separate.
            data_dir: data_base.join(APP_DIR_NAME).join("data"),
            downloads_dir,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }

    pub fn identity_file(&self) -> PathBuf {
        self.data_dir.join("identity.key")
    }

    pub fn instance_lock_file(&self) -> PathBuf {
        self.data_dir.join("instance.lock")
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedtestDirection {
    #[default]
    Both,
    Upload,
    Download,
}

impl SpeedtestDirection {
    pub fn label(self) -> &'static str {
        match self {
            Self::Both => "双向",
            Self::Upload => "仅上传",
            Self::Download => "仅下载",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingsDraft {
    pub signal_host: String,
    pub signal_port: String,
    pub receive_directory: Option<PathBuf>,
    pub send_concurrency: u8,
    pub speedtest_seconds: u16,
    pub speedtest_direction: SpeedtestDirection,
    pub allowed_forward_targets: Vec<AllowedForwardTarget>,
    pub tunnel_rules: Vec<TunnelRule>,
    pub remote_auth: Option<super::remote_auth::RemoteVerifier>,
}

/// A local TCP service that authenticated peers may reach through this device.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedForwardTarget {
    /// Empty grants no access (including migrated schema v2 entries).
    #[serde(default)]
    pub allowed_peers: Vec<String>,
    pub id: String,
    pub name: String,
    pub target: std::net::SocketAddr,
    pub enabled: bool,
}

/// A local TCP listener bound to one specific authenticated peer.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelRule {
    pub id: String,
    pub name: String,
    pub peer_node_id: String,
    pub listen: std::net::SocketAddr,
    pub target: std::net::SocketAddr,
    pub enabled: bool,
    pub auto_start: bool,
}

impl AllowedForwardTarget {
    pub fn new(
        name: impl Into<String>,
        target: std::net::SocketAddr,
        allowed_peers: Vec<String>,
    ) -> Self {
        Self {
            id: new_rule_id(),
            name: name.into(),
            allowed_peers,
            target,
            enabled: true,
        }
    }
}

impl TunnelRule {
    pub fn new(
        name: impl Into<String>,
        peer_node_id: impl Into<String>,
        listen_port: u16,
        target: std::net::SocketAddr,
    ) -> Self {
        Self {
            id: new_rule_id(),
            name: name.into(),
            peer_node_id: peer_node_id.into(),
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], listen_port)),
            target,
            enabled: true,
            auto_start: false,
        }
    }
}

impl SettingsDraft {
    pub fn enabled_forward_targets(&self) -> Vec<AllowedForwardTarget> {
        self.allowed_forward_targets
            .iter()
            .filter(|entry| entry.enabled)
            .cloned()
            .collect()
    }
}

fn new_rule_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

impl SettingsDraft {
    pub fn defaults(downloads_dir: Option<PathBuf>) -> Self {
        Self {
            signal_host: String::new(),
            signal_port: String::new(),
            receive_directory: downloads_dir,
            send_concurrency: 1,
            speedtest_seconds: 30,
            speedtest_direction: SpeedtestDirection::Both,
            allowed_forward_targets: Vec::new(),
            tunnel_rules: Vec::new(),
            remote_auth: None,
        }
    }

    pub(super) fn from_config(config: DesktopConfig) -> Self {
        // Upload was the previous default. Treat that legacy value as the new default
        // so upgraded installations start with bidirectional testing.
        let speedtest_direction = match config.speedtest_direction {
            SpeedtestDirection::Upload => SpeedtestDirection::Both,
            direction => direction,
        };
        Self {
            signal_host: config
                .signal
                .as_ref()
                .map(|s| s.host.clone())
                .unwrap_or_default(),
            signal_port: config
                .signal
                .as_ref()
                .map(|s| s.port.to_string())
                .unwrap_or_default(),
            receive_directory: config.receive_directory,
            send_concurrency: config.send_concurrency,
            speedtest_seconds: config.speedtest_seconds,
            speedtest_direction,
            allowed_forward_targets: config.allowed_forward_targets,
            tunnel_rules: config.tunnel_rules,
            remote_auth: config.remote_auth,
        }
    }

    pub fn to_config(&self) -> Result<DesktopConfig, ConfigError> {
        let host = self.signal_host.as_str();
        validate_signal_host(host)?;
        let port = parse_signal_port(&self.signal_port)?;
        validate_send_concurrency(self.send_concurrency)?;
        validate_speedtest_seconds(self.speedtest_seconds)?;

        let receive_directory = self
            .receive_directory
            .as_ref()
            .ok_or_else(|| ConfigError::Invalid("请先选择接收目录".into()))?;
        if !receive_directory.is_absolute() {
            return Err(ConfigError::Invalid("接收目录必须是绝对路径".into()));
        }
        if receive_directory.to_str().is_none() {
            return Err(ConfigError::UnsupportedPathEncoding);
        }

        let config = DesktopConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            signal: Some(SignalConfig {
                host: host.to_owned(),
                port,
            }),
            receive_directory: Some(receive_directory.clone()),
            send_concurrency: self.send_concurrency,
            speedtest_seconds: self.speedtest_seconds,
            speedtest_direction: self.speedtest_direction,
            allowed_forward_targets: self.allowed_forward_targets.clone(),
            tunnel_rules: self.tunnel_rules.clone(),
            remote_auth: self.remote_auth.clone(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        let config = self.to_config()?;
        validate_receive_directory(
            config
                .receive_directory
                .as_deref()
                .expect("validated receive directory"),
        )?;
        config.write_atomic(path)
    }
}

impl DesktopConfig {
    fn write_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ensure_private_app_dir(parent)?;

        match DesktopConfig::load(path) {
            Ok(Some(_)) | Ok(None) => {}
            Err(error) => {
                return Err(ConfigError::Corrupt(format!(
                    "拒绝覆盖未通过校验的原配置（{error}）"
                )));
            }
        }

        let bytes = serde_json::to_vec_pretty(self)?;
        let temp_path = write_config_temp(path, parent, &bytes)?;
        if let Err(error) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error.into());
        }
        sync_parent_dir(parent)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopConfig {
    schema_version: u32,
    signal: Option<SignalConfig>,
    receive_directory: Option<PathBuf>,
    send_concurrency: u8,
    speedtest_seconds: u16,
    speedtest_direction: SpeedtestDirection,
    #[serde(default)]
    allowed_forward_targets: Vec<AllowedForwardTarget>,
    #[serde(default)]
    tunnel_rules: Vec<TunnelRule>,
    #[serde(default)]
    remote_auth: Option<super::remote_auth::RemoteVerifier>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDesktopConfig {
    schema_version: u32,
    signal: SignalConfig,
    receive_directory: PathBuf,
    send_concurrency: u8,
    speedtest_seconds: u16,
    speedtest_direction: SpeedtestDirection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SignalConfig {
    host: String,
    port: u16,
}

impl DesktopConfig {
    pub fn has_network_config(&self) -> bool {
        self.signal.is_some()
    }
    pub fn save_remote_auth(
        path: &Path,
        verifier: super::remote_auth::RemoteVerifier,
    ) -> Result<(), ConfigError> {
        let mut config = match Self::load(path)? {
            Some(config) => config,
            None => Self {
                schema_version: CONFIG_SCHEMA_VERSION,
                signal: None,
                receive_directory: None,
                send_concurrency: 1,
                speedtest_seconds: 30,
                speedtest_direction: SpeedtestDirection::Both,
                allowed_forward_targets: Vec::new(),
                tunnel_rules: Vec::new(),
                remote_auth: None,
            },
        };
        config.remote_auth = Some(verifier);
        config.write_atomic(path)
    }
    pub fn load(path: &Path) -> Result<Option<Self>, ConfigError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(ConfigError::Corrupt("拒绝读取链接形式的配置文件".into()));
        }
        if !metadata.file_type().is_file() {
            return Err(ConfigError::Corrupt("配置路径不是普通文件".into()));
        }

        let bytes = fs::read(path)?;
        let version = serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|error| ConfigError::Corrupt(error.to_string()))?
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| ConfigError::Corrupt("缺少有效的 schema_version".into()))?;
        let config = match version {
            LEGACY_CONFIG_SCHEMA_VERSION => {
                let legacy: LegacyDesktopConfig = serde_json::from_slice(&bytes)
                    .map_err(|error| ConfigError::Corrupt(error.to_string()))?;
                if legacy.schema_version != LEGACY_CONFIG_SCHEMA_VERSION {
                    return Err(ConfigError::Corrupt("旧配置版本字段不一致".into()));
                }
                Self {
                    schema_version: CONFIG_SCHEMA_VERSION,
                    signal: Some(legacy.signal),
                    receive_directory: Some(legacy.receive_directory),
                    send_concurrency: legacy.send_concurrency,
                    speedtest_seconds: legacy.speedtest_seconds,
                    speedtest_direction: legacy.speedtest_direction,
                    allowed_forward_targets: Vec::new(),
                    tunnel_rules: Vec::new(),
                    remote_auth: None,
                }
            }
            2 | 3 | CONFIG_SCHEMA_VERSION => {
                let mut config = serde_json::from_slice::<Self>(&bytes)
                    .map_err(|error| ConfigError::Corrupt(error.to_string()))?;
                if version < CONFIG_SCHEMA_VERSION
                    && (config.signal.is_none() || config.receive_directory.is_none())
                {
                    return Err(ConfigError::Corrupt("旧配置缺少信令或接收目录".into()));
                }
                // v2 had target-only grants. Preserve rows, but require explicit peer authorization.
                if version == 2 {
                    for entry in &mut config.allowed_forward_targets {
                        entry.allowed_peers.clear();
                    }
                }
                config.schema_version = CONFIG_SCHEMA_VERSION;
                config
            }
            other => {
                return Err(ConfigError::Corrupt(format!(
                    "不支持的 schema_version {other}"
                )));
            }
        };
        config
            .validate()
            .map_err(|error| ConfigError::Corrupt(error.to_string()))?;
        Ok(Some(config))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::Invalid(format!(
                "不支持的 schema_version {}",
                self.schema_version
            )));
        }
        if let Some(signal) = &self.signal {
            validate_signal_host(&signal.host)?;
            if signal.port == 0 {
                return Err(ConfigError::Invalid("信令端口必须在 1..65535 内".into()));
            }
        }
        validate_send_concurrency(self.send_concurrency)?;
        validate_speedtest_seconds(self.speedtest_seconds)?;
        if let Some(directory) = &self.receive_directory {
            if !directory.is_absolute() {
                return Err(ConfigError::Invalid("接收目录必须是绝对路径".into()));
            }
            if directory.to_str().is_none() {
                return Err(ConfigError::UnsupportedPathEncoding);
            }
        }
        if let Some(verifier) = &self.remote_auth {
            verifier
                .validate()
                .map_err(|_| ConfigError::Invalid("不支持的远程认证版本".into()))?;
        }
        validate_forward_configuration(&self.allowed_forward_targets, &self.tunnel_rules)?;
        Ok(())
    }
}

pub(super) fn restore_saved_settings(config: DesktopConfig) -> (SettingsDraft, String, bool) {
    restore_saved_settings_with_validator(config, validate_receive_directory)
}

fn restore_saved_settings_with_validator(
    config: DesktopConfig,
    validate: impl FnOnce(&Path) -> Result<(), ConfigError>,
) -> (SettingsDraft, String, bool) {
    let settings = SettingsDraft::from_config(config);
    let note = match settings.receive_directory.as_deref() {
        Some(path) => match validate(path) {
            Ok(()) => "已加载已保存设置；端口转发规则已就绪".to_owned(),
            Err(error) => format!("已加载设置；{error}。可选择新的接收目录并保存"),
        },
        None => "已加载设置；请重新选择接收目录".to_owned(),
    };
    // The parsed JSON and settings fields are valid even if the saved directory
    // has since become unavailable. Keep remediation enabled so the user can
    // select a replacement instead of treating this runtime condition as JSON
    // corruption.
    (settings, note, true)
}

pub fn validate_signal_host(host: &str) -> Result<(), ConfigError> {
    if host.is_empty()
        || host.trim() != host
        || host.chars().any(char::is_whitespace)
        || host.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
        || host.contains(":://")
        || host.contains("://")
    {
        return Err(ConfigError::Invalid(
            "信令主机不能为空，且不能包含空白、URL 或路径".into(),
        ));
    }

    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let without_final_dot = host.strip_suffix('.').unwrap_or(host);
    if without_final_dot.is_empty() || without_final_dot.len() > 253 {
        return Err(ConfigError::Invalid("信令主机名长度无效".into()));
    }
    if without_final_dot
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(ConfigError::Invalid("数字地址不是合法 IPv4 地址".into()));
    }
    for label in without_final_dot.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(ConfigError::Invalid("信令主机名格式无效".into()));
        }
    }
    Ok(())
}

pub fn parse_signal_port(port: &str) -> Result<u16, ConfigError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::Invalid(
            "信令端口必须是 1..65535 的整数".into(),
        ));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| ConfigError::Invalid("信令端口必须是 1..65535 的整数".into()))?;
    if port == 0 {
        return Err(ConfigError::Invalid("信令端口不能为 0".into()));
    }
    Ok(port)
}

pub fn validate_send_concurrency(value: u8) -> Result<(), ConfigError> {
    if (1..=3).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::Invalid("发送并发数仅支持 1、2 或 3".into()))
    }
}

pub fn validate_speedtest_seconds(value: u16) -> Result<(), ConfigError> {
    if value == 30 || (60..=600).contains(&value) && value.is_multiple_of(60) {
        Ok(())
    } else {
        Err(ConfigError::Invalid(
            "测速时长仅支持 30 秒或 1 到 10 分钟（每分钟递增）".into(),
        ))
    }
}

fn validate_rule_id(id: &str) -> Result<(), ConfigError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ConfigError::Invalid("转发规则 ID 格式无效".into()));
    }
    Ok(())
}

fn validate_rule_name(name: &str) -> Result<(), ConfigError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(
            "转发规则名称不能为空、不能包含控制字符且最多 128 字节".into(),
        ));
    }
    Ok(())
}

fn validate_forward_target(target: std::net::SocketAddr) -> Result<(), ConfigError> {
    if target.port() == 0 || target.ip().is_unspecified() || target.ip().is_multicast() {
        return Err(ConfigError::Invalid(format!(
            "目标地址 {target} 必须使用具体 IP 和 1..65535 端口"
        )));
    }
    Ok(())
}

fn validate_forward_configuration(
    allowed: &[AllowedForwardTarget],
    rules: &[TunnelRule],
) -> Result<(), ConfigError> {
    let mut allowed_ids = HashSet::new();
    let mut enabled_targets = HashSet::new();
    for entry in allowed {
        validate_rule_id(&entry.id)?;
        validate_rule_name(&entry.name)?;
        validate_forward_target(entry.target)?;
        let mut peers = HashSet::new();
        for peer in &entry.allowed_peers {
            let peer = crate::identity::NodeId::from_hex(peer)
                .map_err(|error| ConfigError::Invalid(format!("授权设备 ID 无效：{error}")))?;
            if !peers.insert(peer) {
                return Err(ConfigError::Invalid("授权设备 ID 重复".into()));
            }
        }
        if !allowed_ids.insert(entry.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "允许服务规则 ID 重复：{}",
                entry.id
            )));
        }
        if entry.enabled && !enabled_targets.insert(entry.target) {
            return Err(ConfigError::Invalid(format!(
                "已启用的允许服务目标重复：{}",
                entry.target
            )));
        }
    }

    let mut rule_ids = HashSet::new();
    for rule in rules {
        validate_rule_id(&rule.id)?;
        validate_rule_name(&rule.name)?;
        crate::identity::NodeId::from_hex(&rule.peer_node_id)
            .map_err(|error| ConfigError::Invalid(format!("对端 Node ID 无效：{error}")))?;
        if !rule_ids.insert(rule.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "本机转发规则 ID 重复：{}",
                rule.id
            )));
        }
        if !rule.listen.ip().is_loopback() || rule.listen.port() == 0 {
            return Err(ConfigError::Invalid(format!(
                "本机监听地址 {} 必须是 127.0.0.1 或 ::1 且端口在 1..65535 内",
                rule.listen
            )));
        }
        validate_forward_target(rule.target)?;
    }
    Ok(())
}

pub(super) fn validate_receive_directory(path: &Path) -> Result<(), ConfigError> {
    validate_receive_directory_with(path, probe_receive_directory_write)
}

fn validate_receive_directory_with(
    path: &Path,
    probe_write: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), ConfigError> {
    let metadata = fs::metadata(path).map_err(|error| receive_directory_io_error(path, error))?;
    if !metadata.is_dir() {
        return Err(ConfigError::ReceiveDirectoryUnavailable(format!(
            "{} 不是目录",
            path.display()
        )));
    }
    probe_write(path).map_err(|error| receive_directory_io_error(path, error))?;
    Ok(())
}

fn receive_directory_io_error(path: &Path, error: io::Error) -> ConfigError {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
            ConfigError::ReceiveDirectoryPermission(format!("{}：{error}", path.display()))
        }
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => {
            ConfigError::ReceiveDirectoryUnavailable(format!("{}：{error}", path.display()))
        }
        _ => ConfigError::Io(error),
    }
}

fn probe_receive_directory_write(directory: &Path) -> io::Result<()> {
    for _ in 0..32 {
        let probe_path = directory.join(format!(
            ".p2p-file-write-probe-{:032x}.tmp",
            rand::random::<u128>()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        // Construct the cleanup guard before opening the file so unwinding
        // drops the file handle first (important on Windows), then removes it.
        let mut cleanup = ProbeFileCleanup::new(probe_path.clone());
        let mut file = match options.open(&probe_path) {
            Ok(file) => {
                cleanup.arm();
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };

        let write_result = file.write_all(b"p2p-file receive-directory probe\n");
        drop(file);
        let cleanup_result = cleanup.remove();
        return match (write_result, cleanup_result) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        };
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "无法创建唯一的接收目录写能力探针",
    ))
}

struct ProbeFileCleanup {
    path: PathBuf,
    armed: bool,
}

impl ProbeFileCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: false }
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn remove(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {
                self.armed = false;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for ProbeFileCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn ensure_private_app_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "应用目录必须是普通目录，不能是 symlink/reparse point",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_config_temp(target: &Path, parent: &Path, bytes: &[u8]) -> Result<PathBuf, ConfigError> {
    if target.file_name().is_none() {
        return Err(ConfigError::Invalid("配置路径没有文件名".into()));
    }
    for _ in 0..32 {
        let temp_path = parent.join(format!(".p2p-file-settings-{}.tmp", rand::random::<u128>()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&temp_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temp_path);
            return Err(error.into());
        }
        return Ok(temp_path);
    }
    Err(ConfigError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "无法创建唯一的临时配置文件",
    )))
}

fn sync_parent_dir(path: &Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "p2p_file_desktop_config_{tag}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    fn valid_draft(receive_directory: PathBuf) -> SettingsDraft {
        SettingsDraft {
            signal_host: "relay.example.test".into(),
            signal_port: "7000".into(),
            receive_directory: Some(receive_directory),
            send_concurrency: 1,
            speedtest_seconds: 30,
            speedtest_direction: SpeedtestDirection::Upload,
            allowed_forward_targets: Vec::new(),
            tunnel_rules: Vec::new(),
            remote_auth: None,
        }
    }

    #[test]
    fn security_only_initialization_migration_and_failed_rotation_preserve_settings() {
        let root =
            std::env::temp_dir().join(format!("p2p-auth-config-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        let path = root.join("settings.json");
        let password = super::super::remote_auth::SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = super::super::remote_auth::RemoteVerifier::create(&password).unwrap();
        DesktopConfig::save_remote_auth(&path, verifier.clone()).unwrap();
        let initial = DesktopConfig::load(&path).unwrap().unwrap();
        assert!(!initial.has_network_config());
        assert_eq!(initial.remote_auth, Some(verifier.clone()));
        let bytes = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(password.expose()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let receive = root.join("Downloads");
        fs::create_dir(&receive).unwrap();
        let mut draft = valid_draft(receive);
        draft.remote_auth = Some(verifier.clone());
        draft.save_atomic(&path).unwrap();
        let saved = DesktopConfig::load(&path).unwrap().unwrap();
        assert!(saved.has_network_config());
        let next = super::super::remote_auth::RemoteVerifier::create(
            &super::super::remote_auth::SecretPassword::new("Change9".into()).unwrap(),
        )
        .unwrap();
        DesktopConfig::save_remote_auth(&path, next.clone()).unwrap();
        let rotated = DesktopConfig::load(&path).unwrap().unwrap();
        assert_eq!(rotated.signal, saved.signal);
        assert_eq!(rotated.receive_directory, saved.receive_directory);
        assert_eq!(rotated.remote_auth, Some(next));
        // Schema 3 must retain identity-independent network/Tunnel settings, without inventing credentials.
        let mut old = serde_json::to_value(saved).unwrap();
        old["schema_version"] = 3.into();
        old.as_object_mut().unwrap().remove("remote_auth");
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let migrated = DesktopConfig::load(&path).unwrap().unwrap();
        assert!(migrated.remote_auth.is_none());
        assert_eq!(migrated.schema_version, 4);
        fs::write(&path, b"corrupt").unwrap();
        assert!(DesktopConfig::save_remote_auth(&path, verifier).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"corrupt");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn speedtest_defaults_to_bidirectional_and_reads_legacy_directions() {
        assert_eq!(
            SettingsDraft::defaults(None).speedtest_direction,
            SpeedtestDirection::Both
        );
        assert_eq!(SpeedtestDirection::default().label(), "双向");
        assert_eq!(
            serde_json::from_str::<SpeedtestDirection>("\"upload\"").unwrap(),
            SpeedtestDirection::Upload
        );
        let upgraded = SettingsDraft::from_config(DesktopConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            signal: Some(SignalConfig {
                host: "relay.example.test".into(),
                port: 7000,
            }),
            receive_directory: Some(PathBuf::from("/tmp/Downloads")),
            send_concurrency: 1,
            speedtest_seconds: 30,
            speedtest_direction: SpeedtestDirection::Upload,
            allowed_forward_targets: Vec::new(),
            tunnel_rules: Vec::new(),
            remote_auth: None,
        });
        assert_eq!(upgraded.speedtest_direction, SpeedtestDirection::Both);
    }

    #[test]
    fn native_app_directories_use_platform_standard_roots() {
        let paths = AppPaths::discover().unwrap();
        assert_eq!(
            paths.config_dir,
            dirs::config_dir().unwrap().join(APP_DIR_NAME)
        );
        assert_eq!(
            paths.data_dir,
            dirs::data_local_dir()
                .unwrap()
                .join(APP_DIR_NAME)
                .join("data")
        );
        assert_eq!(
            paths.downloads_dir,
            dirs::download_dir().filter(|path| {
                path.is_absolute()
                    && path.to_str().is_some()
                    && fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
            })
        );
        assert!(paths.config_dir.is_absolute());
        assert!(paths.data_dir.is_absolute());
        assert_ne!(paths.config_dir, paths.data_dir);
        #[cfg(target_os = "linux")]
        {
            let home = dirs::home_dir().unwrap();
            let expected_config = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .unwrap_or_else(|| home.join(".config"));
            let expected_data = std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .unwrap_or_else(|| home.join(".local/share"));
            assert_eq!(dirs::config_dir().unwrap(), expected_config);
            assert_eq!(dirs::data_local_dir().unwrap(), expected_data);
        }
        #[cfg(target_os = "windows")]
        {
            // These native calls use SHGetKnownFolderPath in dirs-sys on Windows.
            assert!(dirs::config_dir().unwrap().is_absolute());
            assert!(dirs::data_local_dir().unwrap().is_absolute());
        }
        #[cfg(target_os = "macos")]
        {
            let home = dirs::home_dir().unwrap();
            assert_eq!(
                dirs::config_dir().unwrap(),
                home.join("Library/Application Support")
            );
            assert_eq!(
                dirs::data_local_dir().unwrap(),
                home.join("Library/Application Support")
            );
        }
    }

    #[test]
    fn gui_identity_is_stable_in_private_app_data() {
        use crate::identity::Identity;

        let data_dir = temp_dir("identity").join("p2p_file");
        ensure_private_app_dir(&data_dir).unwrap();
        let key_path = data_dir.join("identity.key");
        let first = Identity::load_or_create(&key_path).unwrap();
        let second = Identity::load_or_create(&key_path).unwrap();
        assert_eq!(first.node_id(), second.node_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(data_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn accepts_ipv4_ipv6_and_dns_hostnames() {
        for host in [
            "192.0.2.1",
            "2001:db8::1",
            "relay.example.test",
            "localhost",
        ] {
            assert!(validate_signal_host(host).is_ok(), "{host}");
        }
    }

    #[test]
    fn rejects_urls_paths_whitespace_and_malformed_hosts() {
        for host in [
            "",
            " relay.example",
            "relay.example ",
            "relay name",
            "https://relay.test",
            "relay.test/path",
            "999.1.1.1",
            "-bad.test",
            "bad..test",
        ] {
            assert!(validate_signal_host(host).is_err(), "{host:?}");
        }
    }

    #[test]
    fn validates_port_concurrency_and_speedtest_range() {
        assert_eq!(parse_signal_port("1").unwrap(), 1);
        assert_eq!(parse_signal_port("65535").unwrap(), 65535);
        for port in ["", "0", "65536", " 7000", "7000 ", "7x"] {
            assert!(parse_signal_port(port).is_err(), "{port:?}");
        }
        for value in 1..=3 {
            assert!(validate_send_concurrency(value).is_ok());
        }
        assert!(validate_send_concurrency(0).is_err());
        assert!(validate_send_concurrency(4).is_err());
        for value in [30, 60, 120, 600] {
            assert!(validate_speedtest_seconds(value).is_ok());
        }
        for value in [0, 31, 90, 660] {
            assert!(validate_speedtest_seconds(value).is_err());
        }
    }

    #[test]
    fn settings_roundtrip_and_atomic_replacement() {
        let root = temp_dir("roundtrip");
        let receive = root.join("Downloads");
        fs::create_dir_all(&receive).unwrap();
        ensure_private_app_dir(&root.join("config")).unwrap();
        let config_file = root.join("config").join("settings.json");
        let mut draft = valid_draft(receive.clone());
        draft.allowed_forward_targets = vec![
            AllowedForwardTarget {
                allowed_peers: vec![crate::identity::Identity::generate().node_id().to_hex()],
                id: "ssh".into(),
                name: "SSH".into(),
                target: "127.0.0.1:22".parse().unwrap(),
                enabled: true,
            },
            AllowedForwardTarget {
                allowed_peers: vec![crate::identity::Identity::generate().node_id().to_hex()],
                id: "web".into(),
                name: "Web 管理".into(),
                target: "192.168.1.20:8080".parse().unwrap(),
                enabled: false,
            },
        ];
        draft.tunnel_rules = vec![TunnelRule {
            id: "home-ssh".into(),
            name: "家里 SSH".into(),
            peer_node_id: crate::identity::Identity::generate().node_id().to_hex(),
            listen: "127.0.0.1:2222".parse().unwrap(),
            target: "127.0.0.1:22".parse().unwrap(),
            enabled: true,
            auto_start: true,
        }];

        draft.save_atomic(&config_file).unwrap();
        let first = DesktopConfig::load(&config_file).unwrap().unwrap();
        assert_eq!(first.signal.as_ref().unwrap().host, "relay.example.test");
        assert_eq!(first.signal.as_ref().unwrap().port, 7000);
        assert_eq!(first.receive_directory, Some(receive.clone()));
        assert_eq!(first.allowed_forward_targets, draft.allowed_forward_targets);
        assert_eq!(first.tunnel_rules, draft.tunnel_rules);
        assert_eq!(
            draft.enabled_forward_targets(),
            vec![draft.allowed_forward_targets[0].clone()]
        );

        draft.send_concurrency = 3;
        draft.speedtest_seconds = 600;
        draft.speedtest_direction = SpeedtestDirection::Download;
        draft.save_atomic(&config_file).unwrap();
        let second = DesktopConfig::load(&config_file).unwrap().unwrap();
        assert_eq!(second.send_concurrency, 3);
        assert_eq!(second.speedtest_seconds, 600);
        assert_eq!(second.speedtest_direction, SpeedtestDirection::Download);
        assert_eq!(
            fs::read_dir(config_file.parent().unwrap()).unwrap().count(),
            1
        );
        assert_eq!(fs::read_dir(&receive).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_one_config_migrates_with_empty_forward_lists_and_is_rewritten_as_schema_two() {
        let root = temp_dir("schema_migration");
        fs::create_dir_all(&root).unwrap();
        let receive = root.join("Downloads");
        fs::create_dir(&receive).unwrap();
        let config_file = root.join("settings.json");
        let legacy = serde_json::json!({
            "schema_version": 1,
            "signal": { "host": "relay.example.test", "port": 7000 },
            "receive_directory": receive,
            "send_concurrency": 1,
            "speedtest_seconds": 30,
            "speedtest_direction": "upload"
        });
        fs::write(&config_file, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let config = DesktopConfig::load(&config_file).unwrap().unwrap();
        let (settings, _, can_save) = restore_saved_settings_with_validator(config, |_| Ok(()));
        assert!(can_save);
        assert!(settings.allowed_forward_targets.is_empty());
        assert!(settings.tunnel_rules.is_empty());
        settings.save_atomic(&config_file).unwrap();

        let migrated: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_file).unwrap()).unwrap();
        assert_eq!(migrated["schema_version"], CONFIG_SCHEMA_VERSION);
        assert_eq!(migrated["allowed_forward_targets"], serde_json::json!([]));
        assert_eq!(migrated["tunnel_rules"], serde_json::json!([]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_duplicate_enabled_targets_and_non_loopback_tunnel_listeners() {
        let root = temp_dir("forward_validation");
        fs::create_dir_all(&root).unwrap();
        let mut draft = valid_draft(root.clone());
        let target = "127.0.0.1:22".parse().unwrap();
        draft.allowed_forward_targets = vec![
            AllowedForwardTarget {
                allowed_peers: vec![crate::identity::Identity::generate().node_id().to_hex()],
                id: "one".into(),
                name: "One".into(),
                target,
                enabled: true,
            },
            AllowedForwardTarget {
                allowed_peers: vec![crate::identity::Identity::generate().node_id().to_hex()],
                id: "two".into(),
                name: "Two".into(),
                target,
                enabled: true,
            },
        ];
        assert!(matches!(draft.to_config(), Err(ConfigError::Invalid(_))));

        draft.allowed_forward_targets[1].enabled = false;
        draft.tunnel_rules.push(TunnelRule {
            id: "lan-listener".into(),
            name: "LAN listener".into(),
            peer_node_id: crate::identity::Identity::generate().node_id().to_hex(),
            listen: "0.0.0.0:2222".parse().unwrap(),
            target,
            enabled: true,
            auto_start: false,
        });
        assert!(matches!(draft.to_config(), Err(ConfigError::Invalid(_))));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_v2_target_only_grants_migrate_without_authorizing_peers() {
        let root = temp_dir("v2-peer-migration");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("settings.json");
        let mut draft = valid_draft(root.clone());
        draft
            .allowed_forward_targets
            .push(AllowedForwardTarget::new(
                "ssh",
                "127.0.0.1:22".parse().unwrap(),
                vec![crate::identity::Identity::generate().node_id().to_hex()],
            ));
        let mut old = serde_json::to_value(draft.to_config().unwrap()).unwrap();
        old["schema_version"] = 2.into();
        old["allowed_forward_targets"][0]
            .as_object_mut()
            .unwrap()
            .remove("allowed_peers");
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let config = DesktopConfig::load(&path).unwrap().unwrap();
        assert_eq!(config.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(config.allowed_forward_targets.len(), 1);
        assert!(config.allowed_forward_targets[0].allowed_peers.is_empty());
        SettingsDraft::from_config(config)
            .save_atomic(&path)
            .unwrap();
        assert!(
            DesktopConfig::load(&path)
                .unwrap()
                .unwrap()
                .allowed_forward_targets[0]
                .allowed_peers
                .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_reports_disappeared_receive_directory_without_corrupting_or_overwriting_config() {
        let root = temp_dir("missing_receive");
        let receive = root.join("Downloads");
        fs::create_dir_all(&receive).unwrap();
        let config_file = root.join("settings").join("settings.json");
        valid_draft(receive.clone())
            .save_atomic(&config_file)
            .unwrap();
        let original_config = fs::read(&config_file).unwrap();

        fs::remove_dir_all(&receive).unwrap();
        let config = DesktopConfig::load(&config_file)
            .expect("a stale receive path must not make valid JSON corrupt")
            .expect("the saved configuration should still load");
        let (mut settings, note, can_save) = restore_saved_settings(config);

        assert!(note.contains("接收目录不可用"), "{note}");
        assert!(!note.contains("网络功能待接入"), "{note}");
        assert!(can_save, "a stale receive directory must remain repairable");
        assert_eq!(
            settings.receive_directory.as_deref(),
            Some(receive.as_path())
        );
        assert_eq!(fs::read(&config_file).unwrap(), original_config);

        let replacement = root.join("replacement");
        fs::create_dir(&replacement).unwrap();
        settings.receive_directory = Some(replacement.clone());
        settings.save_atomic(&config_file).unwrap();
        assert_eq!(
            DesktopConfig::load(&config_file)
                .unwrap()
                .unwrap()
                .receive_directory,
            Some(replacement)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn write_capability_failure_is_a_directory_diagnostic_and_preserves_config() {
        let root = temp_dir("write_failure");
        let receive = root.join("Downloads");
        fs::create_dir_all(&receive).unwrap();
        let config_file = root.join("settings").join("settings.json");
        valid_draft(receive.clone())
            .save_atomic(&config_file)
            .unwrap();
        let original_config = fs::read(&config_file).unwrap();

        let config = DesktopConfig::load(&config_file)
            .expect("a runtime write failure must not make valid JSON corrupt")
            .unwrap();
        let (settings, note, can_save) = restore_saved_settings_with_validator(config, |path| {
            validate_receive_directory_with(path, |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected write probe failure",
                ))
            })
        });

        assert!(note.contains("接收目录没有写权限"), "{note}");
        assert!(!note.contains("网络功能待接入"), "{note}");
        assert!(can_save, "a write failure must leave settings repairable");
        assert_eq!(
            settings.receive_directory.as_deref(),
            Some(receive.as_path())
        );
        assert_eq!(fs::read(&config_file).unwrap(), original_config);
        assert!(DesktopConfig::load(&config_file).unwrap().is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn receive_directory_file_path_is_unavailable_not_a_permission_failure() {
        let root = temp_dir("not_directory");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file");
        fs::write(&file, b"existing data").unwrap();

        assert!(matches!(
            validate_receive_directory(&file),
            Err(ConfigError::ReceiveDirectoryUnavailable(_))
        ));
        assert_eq!(fs::read(&file).unwrap(), b"existing data");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_config_is_reported_and_never_overwritten() {
        let root = temp_dir("corrupt");
        fs::create_dir_all(&root).unwrap();
        let receive = root.join("Downloads");
        fs::create_dir(&receive).unwrap();
        let config_file = root.join("settings.json");
        let original = b"{not valid json";
        fs::write(&config_file, original).unwrap();

        assert!(matches!(
            DesktopConfig::load(&config_file),
            Err(ConfigError::Corrupt(_))
        ));
        let error = valid_draft(receive).save_atomic(&config_file).unwrap_err();
        assert!(matches!(error, ConfigError::Corrupt(_)));
        assert_eq!(fs::read(&config_file).unwrap(), original);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_receive_paths_before_serialization() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/p2p-\xff".to_vec()));
        let draft = valid_draft(path);
        assert!(matches!(
            draft.to_config(),
            Err(ConfigError::UnsupportedPathEncoding)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn app_directories_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_dir("private");
        ensure_private_app_dir(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(path).unwrap();
    }
}
