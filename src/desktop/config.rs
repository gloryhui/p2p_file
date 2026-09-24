#[cfg(unix)]
use std::fs::File;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const APP_DIR_NAME: &str = "p2p_file";
const CONFIG_SCHEMA_VERSION: u32 = 1;

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
    Upload,
    Download,
}

impl SpeedtestDirection {
    pub fn label(self) -> &'static str {
        match self {
            Self::Upload => "发送",
            Self::Download => "接收",
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
}

impl SettingsDraft {
    pub fn defaults(downloads_dir: Option<PathBuf>) -> Self {
        Self {
            signal_host: String::new(),
            signal_port: String::new(),
            receive_directory: downloads_dir,
            send_concurrency: 1,
            speedtest_seconds: 30,
            speedtest_direction: SpeedtestDirection::Upload,
        }
    }

    pub(super) fn from_config(config: DesktopConfig) -> Self {
        Self {
            signal_host: config.signal.host,
            signal_port: config.signal.port.to_string(),
            receive_directory: Some(config.receive_directory),
            send_concurrency: config.send_concurrency,
            speedtest_seconds: config.speedtest_seconds,
            speedtest_direction: config.speedtest_direction,
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

        Ok(DesktopConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            signal: SignalConfig {
                host: host.to_owned(),
                port,
            },
            receive_directory: receive_directory.clone(),
            send_concurrency: self.send_concurrency,
            speedtest_seconds: self.speedtest_seconds,
            speedtest_direction: self.speedtest_direction,
        })
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), ConfigError> {
        let config = self.to_config()?;
        validate_receive_directory(&config.receive_directory)?;

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

        let bytes = serde_json::to_vec_pretty(&config)?;
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
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|error| ConfigError::Corrupt(error.to_string()))?;
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
        validate_signal_host(&self.signal.host)?;
        if self.signal.port == 0 {
            return Err(ConfigError::Invalid("信令端口必须在 1..65535 内".into()));
        }
        validate_send_concurrency(self.send_concurrency)?;
        validate_speedtest_seconds(self.speedtest_seconds)?;
        if !self.receive_directory.is_absolute() {
            return Err(ConfigError::Invalid("接收目录必须是绝对路径".into()));
        }
        if self.receive_directory.to_str().is_none() {
            return Err(ConfigError::UnsupportedPathEncoding);
        }
        Ok(())
    }
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

fn validate_receive_directory(path: &Path) -> Result<(), ConfigError> {
    let metadata = fs::metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::PermissionDenied => {
            ConfigError::ReceiveDirectoryPermission(path.display().to_string())
        }
        _ => ConfigError::ReceiveDirectoryUnavailable(format!("{}：{error}", path.display())),
    })?;
    if !metadata.is_dir() {
        return Err(ConfigError::ReceiveDirectoryUnavailable(format!(
            "{} 不是目录",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o222 == 0 {
            return Err(ConfigError::ReceiveDirectoryPermission(
                path.display().to_string(),
            ));
        }
    }
    #[cfg(windows)]
    if metadata.permissions().readonly() {
        return Err(ConfigError::ReceiveDirectoryPermission(
            path.display().to_string(),
        ));
    }
    Ok(())
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
        }
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

        draft.save_atomic(&config_file).unwrap();
        let first = DesktopConfig::load(&config_file).unwrap().unwrap();
        assert_eq!(first.signal.host, "relay.example.test");
        assert_eq!(first.signal.port, 7000);
        assert_eq!(first.receive_directory, receive);

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
