//! 节点身份：Ed25519 长期密钥对，节点 ID 为公钥的 BLAKE3 摘要。
//!
//! 节点 ID 是**自证**的：任何人拿到公钥都能算出同一个 ID，因此只要事先知道
//! 对方的节点 ID，就能确认握手时对面拿出的公钥确实是本人的，不需要 CA。
//! QUIC 的 TLS 证书用自签名证书，信任链换成了「公钥 → 节点 ID」这一步。

use std::fmt;
use std::fs;
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
                identity.save(path)?;
                Ok(identity)
            }
            Err(err) => Err(err),
        }
    }

    /// 从密钥文件读取身份。
    pub fn load(path: &Path) -> Result<Self> {
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

    /// 把私钥写入文件，权限 0600（Unix）。
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.secret_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
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
