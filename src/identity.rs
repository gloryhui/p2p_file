//! 节点身份：Ed25519 长期密钥对，节点 ID 为公钥的 BLAKE3 摘要。
//!
//! 节点 ID 是**自证**的：任何人拿到公钥都能算出同一个 ID，因此只要事先知道
//! 对方的节点 ID，就能确认握手时对面拿出的公钥确实是本人的，不需要 CA。
//! QUIC 的 TLS 证书用自签名证书，信任链换成了「公钥 → 节点 ID」这一步。

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 公钥长度（Ed25519）。
pub const PUBLIC_KEY_LEN: usize = 32;
/// 节点 ID 长度（BLAKE3 摘要截断）。
pub const NODE_ID_LEN: usize = 16;
/// 密钥文件长度（Ed25519 私钥种子）。
pub const SECRET_KEY_LEN: usize = 32;

/// 节点 ID：公钥 BLAKE3 摘要的前 [`NODE_ID_LEN`] 字节。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    /// 由公钥推导节点 ID。
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let digest = blake3::hash(public_key.as_bytes());
        let mut bytes = [0u8; NODE_ID_LEN];
        bytes.copy_from_slice(&digest.as_bytes()[..NODE_ID_LEN]);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// 前 8 个十六进制字符，便于日志和 CLI 展示。
    pub fn short(&self) -> String {
        self.to_hex()[..8].to_string()
    }

    pub fn from_hex(text: &str) -> Result<Self> {
        let raw = hex::decode(text)
            .map_err(|err| Error::Identity(format!("节点 ID 不是合法十六进制: {err}")))?;
        let bytes: [u8; NODE_ID_LEN] = raw.as_slice().try_into().map_err(|_| {
            Error::Identity(format!(
                "节点 ID 应为 {NODE_ID_LEN} 字节（{} 个十六进制字符），实际 {} 字节",
                NODE_ID_LEN * 2,
                raw.len()
            ))
        })?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 让命令行可以直接把节点 ID 当参数解析（`--peer <NODE_ID>`）。
impl std::str::FromStr for NodeId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        Self::from_hex(text.trim())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

/// 本机身份：一个 Ed25519 密钥对。
///
/// 私钥只以 32 字节种子的形式存在于内存和密钥文件中。
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// 随机生成一个新身份。
    pub fn generate() -> Self {
        // 注意：ed25519-dalek 3.x 依赖 rand_core 0.10，而 `SigningKey::generate`
        // 要求 `CryptoRng`，`rand` 0.10 的 ThreadRng 只实现了 `TryCryptoRng`，
        // 所以这里直接取 32 字节随机种子构造。
        let seed: [u8; SECRET_KEY_LEN] = rand::random();
        Self::from_secret_bytes(&seed)
    }

    /// 由 32 字节私钥种子构造。
    pub fn from_secret_bytes(seed: &[u8; SECRET_KEY_LEN]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// 导出私钥种子。**不要**写入日志。
    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.signing_key.to_bytes()
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key().to_bytes()
    }

    pub fn node_id(&self) -> NodeId {
        NodeId::from_public_key(&self.public_key())
    }

    /// 对消息签名。
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// 用本机公钥校验签名。
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        verify_signature(&self.public_key(), message, signature)
    }

    /// 默认密钥文件路径：`$XDG_CONFIG_HOME/p2p_file/identity.key`，
    /// 回退到 `$HOME/.config/p2p_file/identity.key`。
    pub fn default_key_path() -> Result<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config")))
            .ok_or_else(|| {
                Error::Identity("无法确定配置目录：XDG_CONFIG_HOME 和 HOME 都未设置".into())
            })?;
        Ok(base.join("p2p_file").join("identity.key"))
    }

    /// 读取身份；文件不存在则生成并写入。
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(identity) => Ok(identity),
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate();
                let temp = write_key_temp(path, &identity.secret_bytes())?;
                match publish_key_no_replace(&temp, path)? {
                    true => Ok(identity),
                    false => Self::load(path),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// 从密钥文件读取身份。
    pub fn load(path: &Path) -> Result<Self> {
        reject_unsafe_key_target(path)?;
        let raw = fs::read(path)?;
        let seed: [u8; SECRET_KEY_LEN] = raw.as_slice().try_into().map_err(|_| {
            Error::Identity(format!(
                "密钥文件 {} 长度应为 {SECRET_KEY_LEN} 字节，实际 {} 字节",
                path.display(),
                raw.len()
            ))
        })?;
        Ok(Self::from_secret_bytes(&seed))
    }

    /// 把私钥安全地写入一个新文件，权限 0600（Unix），拒绝覆盖已有目标。
    pub fn save(&self, path: &Path) -> Result<()> {
        let temp = write_key_temp(path, &self.secret_bytes())?;
        if publish_key_no_replace(&temp, path)? {
            Ok(())
        } else {
            Err(Error::Identity(format!(
                "密钥文件已存在，拒绝覆盖: {}",
                path.display()
            )))
        }
    }
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn temp_key_path(path: &Path, nonce: u128) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| Error::Identity(format!("密钥路径没有有效文件名: {}", path.display())))?;
    let temp_name = format!(".{}.{}.tmp", file_name.to_string_lossy(), nonce);
    Ok(parent_dir(path).join(temp_name))
}

/// 从创建时就以安全权限写满临时 key，并把文件内容 sync 到稳定存储。
fn write_key_temp(path: &Path, secret: &[u8; SECRET_KEY_LEN]) -> Result<PathBuf> {
    fs::create_dir_all(parent_dir(path))?;

    for _ in 0..32 {
        let temp = temp_key_path(path, rand::random())?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = match options.open(&temp) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };

        let result = (|| {
            file.write_all(secret)?;
            file.sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        if let Err(err) = result {
            let _ = fs::remove_file(&temp);
            return Err(err.into());
        }
        return Ok(temp);
    }

    Err(Error::Identity("无法创建唯一的临时密钥文件".into()))
}

/// 以同目录 hard-link 提供 create-new/no-replace 发布；不回退到 rename。
///
/// 返回 true 表示本调用发布成功，false 表示正式路径已被其他调用占用。临时
/// 文件在两种结果下都会清理；正式路径只在完整 key 已 sync 后才出现。
fn publish_key_no_replace(temp: &Path, target: &Path) -> Result<bool> {
    match fs::hard_link(temp, target) {
        Ok(()) => {
            fs::remove_file(temp)?;
            sync_parent_dir(target)?;
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(temp)?;
            Ok(false)
        }
        Err(err) => {
            // Windows may report an occupied reparse point as PermissionDenied. Do not
            // follow it and do not turn any other error into an unsafe replacement.
            match fs::symlink_metadata(target) {
                Ok(_) => {
                    fs::remove_file(temp)?;
                    Ok(false)
                }
                Err(metadata_err) if metadata_err.kind() == std::io::ErrorKind::NotFound => {
                    let _ = fs::remove_file(temp);
                    Err(err.into())
                }
                Err(metadata_err) => {
                    let _ = fs::remove_file(temp);
                    Err(metadata_err.into())
                }
            }
        }
    }
}

/// 拒绝 symlink、Windows reparse point 和非普通文件。
///
/// `symlink_metadata` 本身不跟随链接；随后 `fs::read` 与此检查之间仍存在
/// 检查后替换竞态。标准库没有可移植的 no-follow read API，因此这里明确只承诺
/// 拒绝稳定存在的链接/异常目标；首次创建的 publish 路径不受该竞态影响。
fn reject_unsafe_key_target(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let is_link = metadata.file_type().is_symlink() || is_reparse_point(&metadata);
    if is_link {
        return Err(Error::Identity(format!(
            "拒绝从 symlink/reparse-point 加载密钥: {}",
            path.display()
        )));
    }
    if !metadata.file_type().is_file() {
        return Err(Error::Identity(format!(
            "密钥路径必须是普通文件: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    // Windows has no portable std equivalent for syncing a directory handle. The key
    // file is synced before publish; an uncommitted directory entry is retried safely.
    Ok(())
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 刻意不打印私钥。
        f.debug_struct("Identity")
            .field("node_id", &self.node_id())
            .finish_non_exhaustive()
    }
}

/// 用给定公钥校验签名。
pub fn verify_signature(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    public_key
        .verify(message, signature)
        .map_err(|err| Error::Identity(format!("签名校验失败: {err}")))
}

/// 由字节解析公钥。
pub fn public_key_from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).map_err(|err| Error::Identity(format!("公钥解析失败: {err}")))
}

/// 由字节解析签名（64 字节）。
pub fn signature_from_bytes(bytes: &[u8]) -> Result<Signature> {
    Signature::from_slice(bytes).map_err(|err| Error::Identity(format!("签名解析失败: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn test_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "p2p_file_identity_{tag}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn 节点_id_由公钥唯一确定() {
        let identity = Identity::generate();
        let again = Identity::from_secret_bytes(&identity.secret_bytes());
        assert_eq!(identity.node_id(), again.node_id());
        assert_eq!(identity.node_id().to_hex().len(), NODE_ID_LEN * 2);
    }

    #[test]
    fn 不同身份有不同节点_id() {
        assert_ne!(
            Identity::generate().node_id(),
            Identity::generate().node_id()
        );
    }

    #[test]
    fn 签名校验通过() {
        let identity = Identity::generate();
        let signature = identity.sign(b"hello p2p");
        assert!(identity.verify(b"hello p2p", &signature).is_ok());
    }

    #[test]
    fn 内容被篡改则校验失败() {
        let identity = Identity::generate();
        let signature = identity.sign(b"hello p2p");
        assert!(identity.verify(b"hello p2q", &signature).is_err());
    }

    #[test]
    fn 换一把公钥则校验失败() {
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let signature = mallory.sign(b"hello p2p");
        assert!(alice.verify(b"hello p2p", &signature).is_err());
    }

    #[test]
    fn 节点_id_十六进制往返() {
        let id = Identity::generate().node_id();
        assert_eq!(NodeId::from_hex(&id.to_hex()).unwrap(), id);
        assert!(NodeId::from_hex("zz").is_err());
        assert!(NodeId::from_hex("00").is_err());
    }

    #[test]
    fn 签名字节往返() {
        let identity = Identity::generate();
        let signature = identity.sign(b"payload");
        let parsed = signature_from_bytes(&signature.to_bytes()).unwrap();
        assert_eq!(parsed, signature);
        assert!(signature_from_bytes(&[0u8; 3]).is_err());
    }

    #[test]
    fn 密钥文件往返且权限为_0600() {
        let dir = std::env::temp_dir().join(format!("p2p_file_id_{}", std::process::id()));
        let path = dir.join("identity.key");
        let _ = fs::remove_dir_all(&dir);

        let identity = Identity::generate();
        identity.save(&path).unwrap();
        let loaded = Identity::load(&path).unwrap();
        assert_eq!(identity.node_id(), loaded.node_id());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 密钥文件长度不对时报错() {
        let path = std::env::temp_dir().join(format!("p2p_file_bad_{}.key", std::process::id()));
        fs::write(&path, b"too short").unwrap();
        assert!(Identity::load(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn 宽松_umask下新建密钥仍从第一刻就是_0600() {
        const CHILD: &str = "P2P_FILE_UMASK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let exe = std::env::current_exe().unwrap();
            let output = std::process::Command::new("sh")
                .args([
                    "-c",
                    "umask 000; exec \"$@\"",
                    "sh",
                    exe.to_str().unwrap(),
                    "--exact",
                    "identity::tests::宽松_umask下新建密钥仍从第一刻就是_0600",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "子进程在 umask 000 下失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("umask");
        let path = dir.join("identity.key");
        Identity::generate().save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn 并发首次创建最终都读取同一个完整密钥() {
        let dir = test_dir("concurrent");
        let path = Arc::new(dir.join("identity.key"));
        let barrier = Arc::new(Barrier::new(16));
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            tasks.push(std::thread::spawn(move || {
                barrier.wait();
                Identity::load_or_create(&path)
            }));
        }

        let identities: Vec<_> = tasks
            .into_iter()
            .map(|task| task.join().unwrap().unwrap())
            .collect();
        let node_id = identities[0].node_id();
        assert!(
            identities
                .iter()
                .all(|identity| identity.node_id() == node_id)
        );
        assert_eq!(fs::read(&*path).unwrap().len(), SECRET_KEY_LEN);
        assert_eq!(Identity::load(&path).unwrap().node_id(), node_id);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save拒绝覆盖已有正常密钥() {
        let dir = test_dir("save_existing");
        let path = dir.join("identity.key");
        let first = Identity::generate();
        let second = Identity::generate();
        first.save(&path).unwrap();
        assert!(second.save(&path).is_err());
        assert_eq!(Identity::load(&path).unwrap().node_id(), first.node_id());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink占名不能覆盖目标也不能被加载() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("symlink");
        fs::create_dir_all(&dir).unwrap();
        let protected = dir.join("protected.key");
        let path = dir.join("identity.key");
        fs::write(&protected, [0xabu8; SECRET_KEY_LEN]).unwrap();
        symlink(&protected, &path).unwrap();

        assert!(Identity::generate().save(&path).is_err());
        assert!(Identity::load_or_create(&path).is_err());
        assert_eq!(fs::read(&protected).unwrap(), [0xabu8; SECRET_KEY_LEN]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn 已存在异常目标明确失败() {
        let dir = test_dir("abnormal");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");
        fs::create_dir(&path).unwrap();

        assert!(Identity::load(&path).is_err());
        assert!(Identity::load_or_create(&path).is_err());
        assert!(Identity::generate().save(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn reparse_point占名不能覆盖目标() {
        use std::os::windows::fs::symlink_file;

        let dir = test_dir("reparse");
        fs::create_dir_all(&dir).unwrap();
        let protected = dir.join("protected.key");
        let path = dir.join("identity.key");
        fs::write(&protected, [0xabu8; SECRET_KEY_LEN]).unwrap();
        if symlink_file(&protected, &path).is_err() {
            // Local Windows runners may lack SeCreateSymbolicLinkPrivilege. A
            // directory still verifies that create-new never follows an occupied name.
            fs::create_dir(&path).unwrap();
        }

        assert!(Identity::generate().save(&path).is_err());
        assert!(Identity::load_or_create(&path).is_err());
        assert_eq!(fs::read(&protected).unwrap(), [0xabu8; SECRET_KEY_LEN]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_or_create_能创建缺失的文件() {
        let dir = std::env::temp_dir().join(format!("p2p_file_loc_{}", std::process::id()));
        let path = dir.join("identity.key");
        let _ = fs::remove_dir_all(&dir);

        let created = Identity::load_or_create(&path).unwrap();
        assert!(path.exists());
        let reused = Identity::load_or_create(&path).unwrap();
        assert_eq!(created.node_id(), reused.node_id());

        fs::remove_dir_all(&dir).unwrap();
    }
}
