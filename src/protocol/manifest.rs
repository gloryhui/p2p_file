//! 文件清单：描述一个文件的全部信息，接收端凭它校验每一片数据。
//!
//! 清单里的 `root_hash` 覆盖了文件名、长度、分片大小和所有分片哈希，
//! 因此清单本身无法被篡改——改任何一个字段都会导致根哈希对不上。
//! 实际使用时还应把这个根哈希通过带外方式（或已认证的握手）确认一次。

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 默认分片大小 256 KiB。
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;

/// 允许的最小分片大小。
pub const MIN_CHUNK_SIZE: u32 = 16 * 1024;

/// 允许的最大分片大小。
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// 分片哈希长度（BLAKE3）。
pub const CHUNK_HASH_LEN: usize = 32;

/// 根哈希域的用途标签，换协议版本时一并改掉，避免跨版本撞哈希。
const ROOT_HASH_DOMAIN: &[u8] = b"p2p_file/manifest/v1";

/// 一个 BLAKE3 摘要。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkHash(pub [u8; CHUNK_HASH_LEN]);

impl ChunkHash {
    /// 计算一片数据的摘要。
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// 校验一片数据。
    ///
    /// 这里是普通比较而非恒定时间比较：校验的是公开的文件内容，
    /// 不存在需要防时序侧信道泄露的秘密。
    pub fn verify(&self, data: &[u8]) -> bool {
        self.0 == *blake3::hash(data).as_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; CHUNK_HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ChunkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for ChunkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChunkHash({})", &self.to_hex()[..16])
    }
}

/// 分片总数。空文件为 0。
pub fn chunk_count(total_len: u64, chunk_size: u32) -> u64 {
    if total_len == 0 {
        0
    } else {
        total_len.div_ceil(chunk_size as u64)
    }
}

/// 第 `index` 片的长度。越界返回 `None`。
pub fn chunk_len_at(index: u32, total_len: u64, chunk_size: u32) -> Option<u32> {
    let total = chunk_count(total_len, chunk_size);
    if u64::from(index) >= total {
        return None;
    }
    let offset = u64::from(index) * u64::from(chunk_size);
    let remaining = total_len - offset;
    Some(remaining.min(u64::from(chunk_size)) as u32)
}

/// 计算根哈希。字段顺序与长度都写死，保证跨平台跨版本一致。
pub fn root_hash_of(
    file_name: &str,
    total_len: u64,
    chunk_size: u32,
    chunks: &[ChunkHash],
) -> ChunkHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROOT_HASH_DOMAIN);
    hasher.update(&(file_name.len() as u64).to_le_bytes());
    hasher.update(file_name.as_bytes());
    hasher.update(&total_len.to_le_bytes());
    hasher.update(&chunk_size.to_le_bytes());
    hasher.update(&(chunks.len() as u64).to_le_bytes());
    for chunk in chunks {
        hasher.update(chunk.as_bytes());
    }
    ChunkHash(*hasher.finalize().as_bytes())
}

/// 文件清单。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    /// 文件名（不含路径，接收端不应直接信任它当路径用，见 `safe_file_name`）。
    pub file_name: String,
    /// 文件总长度（字节）。
    pub total_len: u64,
    /// 分片大小（字节），除最后一片外每片都是这个长度。
    pub chunk_size: u32,
    /// 每片的 BLAKE3 摘要。
    pub chunks: Vec<ChunkHash>,
    /// 覆盖以上所有字段的根哈希。
    pub root_hash: ChunkHash,
}

impl FileManifest {
    /// 构造并校验清单。
    pub fn new(
        file_name: impl Into<String>,
        total_len: u64,
        chunk_size: u32,
        chunks: Vec<ChunkHash>,
    ) -> Result<Self> {
        let file_name = file_name.into();
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(Error::Protocol(format!(
                "分片大小 {chunk_size} 超出允许范围 {MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}"
            )));
        }
        let expected = chunk_count(total_len, chunk_size);
        if chunks.len() as u64 != expected {
            return Err(Error::Protocol(format!(
                "分片数量不符：文件 {total_len} 字节 / 分片 {chunk_size} 字节应为 {expected} 片，实际 {} 片",
                chunks.len()
            )));
        }
        let root_hash = root_hash_of(&file_name, total_len, chunk_size, &chunks);
        Ok(Self {
            file_name,
            total_len,
            chunk_size,
            chunks,
            root_hash,
        })
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunks.len() as u32
    }

    /// 第 `index` 片的偏移量。
    pub fn chunk_offset(&self, index: u32) -> Option<u64> {
        (index < self.chunk_count()).then(|| u64::from(index) * u64::from(self.chunk_size))
    }

    /// 第 `index` 片的长度。
    pub fn chunk_len(&self, index: u32) -> Option<u32> {
        chunk_len_at(index, self.total_len, self.chunk_size)
    }

    /// 第 `index` 片的偏移量与长度。
    pub fn chunk_range(&self, index: u32) -> Option<(u64, u32)> {
        Some((self.chunk_offset(index)?, self.chunk_len(index)?))
    }

    /// 校验第 `index` 片的数据。
    pub fn verify_chunk(&self, index: u32, data: &[u8]) -> bool {
        let Some(expected_len) = self.chunk_len(index) else {
            return false;
        };
        if data.len() != expected_len as usize {
            return false;
        }
        self.chunks[index as usize].verify(data)
    }

    /// 重新计算根哈希并与此前记录的值比对，用于检出清单被篡改。
    pub fn verify_root_hash(&self) -> bool {
        self.root_hash
            == root_hash_of(
                &self.file_name,
                self.total_len,
                self.chunk_size,
                &self.chunks,
            )
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// 反序列化清单，并强制校验根哈希。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = postcard::from_bytes(bytes)?;
        if !manifest.verify_root_hash() {
            return Err(Error::Protocol("清单根哈希校验失败，可能被篡改".into()));
        }
        Ok(manifest)
    }
}

/// 把清单里的文件名清洗成一个安全的、只有单层的文件名。
///
/// 对端可能发来 `../../.ssh/authorized_keys` 这类名字，**绝不能**直接拼路径。
pub fn safe_file_name(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .trim_matches('.');
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect();
    if cleaned.is_empty() {
        "download.bin".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_of(data: &[u8], chunk_size: u32) -> FileManifest {
        let chunks = data
            .chunks(chunk_size as usize)
            .map(ChunkHash::of)
            .collect::<Vec<_>>();
        FileManifest::new("demo.bin", data.len() as u64, chunk_size, chunks).unwrap()
    }

    #[test]
    fn 分片计数与长度() {
        assert_eq!(chunk_count(0, 1024), 0);
        assert_eq!(chunk_count(1, 1024), 1);
        assert_eq!(chunk_count(1024, 1024), 1);
        assert_eq!(chunk_count(1025, 1024), 2);

        assert_eq!(chunk_len_at(0, 1025, 1024), Some(1024));
        assert_eq!(chunk_len_at(1, 1025, 1024), Some(1));
        assert_eq!(chunk_len_at(2, 1025, 1024), None);
    }

    #[test]
    fn 清单能校验每一片() {
        // 两片多一点，确保跨分片边界。
        let total = MIN_CHUNK_SIZE as usize * 2 + 500;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let manifest = manifest_of(&data, MIN_CHUNK_SIZE);
        assert_eq!(manifest.chunk_count(), 3);
        assert_eq!(manifest.total_len, total as u64);

        for index in 0..manifest.chunk_count() {
            let (offset, len) = manifest.chunk_range(index).unwrap();
            let slice = &data[offset as usize..(offset + u64::from(len)) as usize];
            assert!(
                manifest.verify_chunk(index, slice),
                "第 {index} 片应校验通过"
            );
        }
    }

    #[test]
    fn 篡改数据会被检出() {
        let data = vec![7u8; MIN_CHUNK_SIZE as usize + 1000];
        let manifest = manifest_of(&data, MIN_CHUNK_SIZE);

        let mut tampered = data[..MIN_CHUNK_SIZE as usize].to_vec();
        tampered[0] ^= 0xff;
        assert!(!manifest.verify_chunk(0, &tampered));
    }

    #[test]
    fn 长度不符会被检出() {
        let data = vec![7u8; MIN_CHUNK_SIZE as usize + 1000];
        let manifest = manifest_of(&data, MIN_CHUNK_SIZE);

        assert!(!manifest.verify_chunk(0, &data[..100]), "太短应失败");
        assert!(
            !manifest.verify_chunk(1, &data[MIN_CHUNK_SIZE as usize - 1..]),
            "最后一片多给了数据应失败"
        );
        assert!(!manifest.verify_chunk(9, &[]), "越界分片应失败");
    }

    #[test]
    fn 分片数与文件长度不符时报错() {
        let chunks = vec![ChunkHash::of(b"a")];
        assert!(FileManifest::new("x.bin", 100_000, 4096, chunks).is_err());
    }

    #[test]
    fn 分片大小越界时报错() {
        assert!(FileManifest::new("x.bin", 0, 1, vec![]).is_err());
        assert!(FileManifest::new("x.bin", 0, MAX_CHUNK_SIZE + 1, vec![]).is_err());
    }

    #[test]
    fn 根哈希覆盖文件名与长度() {
        let data = vec![1u8; 100];
        let chunks = vec![ChunkHash::of(&data)];
        let a = FileManifest::new("a.bin", 100, MIN_CHUNK_SIZE, chunks.clone()).unwrap();
        let b = FileManifest::new("b.bin", 100, MIN_CHUNK_SIZE, chunks.clone()).unwrap();
        let c = FileManifest::new("a.bin", 101, MIN_CHUNK_SIZE, chunks).unwrap();
        assert_ne!(a.root_hash, b.root_hash);
        assert_ne!(a.root_hash, c.root_hash);
    }

    #[test]
    fn 序列化往返且能检出篡改() {
        let data = vec![3u8; MIN_CHUNK_SIZE as usize * 2 + 100];
        let manifest = manifest_of(&data, MIN_CHUNK_SIZE);

        let bytes = manifest.to_bytes().unwrap();
        let back = FileManifest::from_bytes(&bytes).unwrap();
        assert_eq!(manifest, back);

        // 手工把 bytes 里某一位翻转，重新解析应因根哈希不符而失败。
        let mut corrupted = bytes.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        assert!(FileManifest::from_bytes(&corrupted).is_err());
    }

    #[test]
    fn 空文件清单合法() {
        let manifest = FileManifest::new("empty.bin", 0, MIN_CHUNK_SIZE, vec![]).unwrap();
        assert_eq!(manifest.chunk_count(), 0);
        assert!(manifest.verify_root_hash());
    }

    #[test]
    fn 文件名清洗挡住路径穿越() {
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("/absolute/path/movie.mkv"), "movie.mkv");
        assert_eq!(
            safe_file_name("..\\..\\windows\\system32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(safe_file_name("..."), "download.bin");
        assert_eq!(safe_file_name(""), "download.bin");
        assert_eq!(safe_file_name("normal.txt"), "normal.txt");
    }
}
