//! 文件清单：描述一个文件的全部信息，接收端凭它校验每一片数据。
//!
//! 清单里的 `root_hash` 覆盖了文件名、长度、分片大小和所有分片哈希，所以
//! **改任何一个字段**都会导致根哈希对不上。但它防的是链路中间的第三方篡改，
//! **不防发送端本身**：对端完全可以自己算一个自洽的根哈希，却把 `chunk_size`
//! 写成 0、把分片数写成跟 `total_len` 对不上。因此来自网络的清单必须先过
//! [`FileManifest::validate`] 才能使用（`from_bytes` / `ControlMessage::decode`
//! 已经强制调用）。根哈希的意义是「接收到的这份清单和发送端声称的是同一份」，
//! 想确认它对应哪个文件仍需带外核对。

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

/// 校验分片大小是否落在协议允许的范围内。
///
/// 单独抽出来是为了让发送端在**分配缓冲区之前**就能拒绝非法值：
/// `vec![0u8; chunk_size as usize]` 在 `chunk_size` 很大时是一次真实的大分配。
/// 范围检查同时也挡住了 `chunk_size == 0`（后面会做除法）。
pub fn validate_chunk_size(chunk_size: u32) -> Result<()> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(Error::Protocol(format!(
            "分片大小 {chunk_size} 超出允许范围 {MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}"
        )));
    }
    Ok(())
}

/// 分片总数。空文件为 0。
///
/// `chunk_size == 0` 不是合法清单（会被 [`FileManifest::validate`] 拒绝），这里
/// 返回 0 而不是做 `div_ceil(0)`：`chunk_len_at` / `verify_chunk` 可能在校验之前
/// 就被畸形数据调到，宁可给出无意义的 0，也不能让对端把进程打 panic。
pub fn chunk_count(total_len: u64, chunk_size: u32) -> u64 {
    if total_len == 0 || chunk_size == 0 {
        0
    } else {
        total_len.div_ceil(u64::from(chunk_size))
    }
}

/// 第 `index` 片的长度。越界或算术越界返回 `None`。
pub fn chunk_len_at(index: u32, total_len: u64, chunk_size: u32) -> Option<u32> {
    let total = chunk_count(total_len, chunk_size);
    if u64::from(index) >= total {
        return None;
    }
    // 校验过的清单里 index < total <= chunks.len() <= u32::MAX、chunk_size <=
    // u32::MAX，乘积不会溢出；这里仍然用 checked_*，保证**任何**输入都只是
    // 返回 None，而不是 debug 下 panic。
    let offset = u64::from(index).checked_mul(u64::from(chunk_size))?;
    let remaining = total_len.checked_sub(offset)?;
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
    ///
    /// 校验逻辑只有 [`Self::validate`] 一处，这里先算根哈希再走它，避免出现
    /// 「`new()` 检查一套、`from_bytes()` 检查另一套」的分叉。
    pub fn new(
        file_name: impl Into<String>,
        total_len: u64,
        chunk_size: u32,
        chunks: Vec<ChunkHash>,
    ) -> Result<Self> {
        let file_name = file_name.into();
        // 早失败：分片大小不对就没必要先算一遍所有分片哈希。
        validate_chunk_size(chunk_size)?;
        let root_hash = root_hash_of(&file_name, total_len, chunk_size, &chunks);
        let manifest = Self {
            file_name,
            total_len,
            chunk_size,
            chunks,
            root_hash,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// **唯一**的完整校验入口。所有来自网络的清单都必须先过这里才能使用。
    ///
    /// 检查项：
    ///
    /// 1. `MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE`（同时排除 0）；
    /// 2. `chunks.len()` 能安全放进协议使用的 `u32`；
    /// 3. `chunks.len()` 与 `total_len / chunk_size` **精确**一致——这条同时
    ///    挡住了「`total_len` 极大而分片数很少」这类畸形清单；
    /// 4. 根哈希自洽。
    ///
    /// 任何一项不通过都只返回 [`Error::Protocol`]，不会 panic，也不会按对端
    /// 声称的长度做分配。
    pub fn validate(&self) -> Result<()> {
        validate_chunk_size(self.chunk_size)?;

        // 分片下标在协议里是 u32，`chunk_count()` 会做 `len as u32`。正常网络
        // 路径上分片数受帧长限制远达不到 u32::MAX，但校验不能依赖调用方的克制。
        if self.chunks.len() > u32::MAX as usize {
            return Err(Error::Protocol(format!(
                "分片数量 {} 超过协议上限 {}",
                self.chunks.len(),
                u32::MAX
            )));
        }

        let expected = chunk_count(self.total_len, self.chunk_size);
        if self.chunks.len() as u64 != expected {
            return Err(Error::Protocol(format!(
                "分片数量不符：文件 {} 字节 / 分片 {} 字节应为 {expected} 片，实际 {} 片",
                self.total_len,
                self.chunk_size,
                self.chunks.len()
            )));
        }

        if !self.verify_root_hash() {
            return Err(Error::Protocol("清单根哈希校验失败，可能被篡改".into()));
        }
        Ok(())
    }

    /// 分片数量。`validate()` 保证 `chunks.len() <= u32::MAX`，转换安全。
    pub fn chunk_count(&self) -> u32 {
        self.chunks.len() as u32
    }

    /// 第 `index` 片的偏移量。越界或算术越界返回 `None`。
    pub fn chunk_offset(&self, index: u32) -> Option<u64> {
        if index >= self.chunk_count() {
            return None;
        }
        u64::from(index).checked_mul(u64::from(self.chunk_size))
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
        // chunk_len 已经确认 index < chunk_count()，这里不会越界。
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

    /// 反序列化清单，并强制走完整 [`Self::validate`]。
    ///
    /// 这是不可信字节变成可用清单的唯一入口；只校验根哈希是不够的——攻击者
    /// 完全可以自己算出一个自洽的根哈希，但把 `chunk_size` 写成 0。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = postcard::from_bytes(bytes)?;
        manifest.validate()?;
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

    // -----------------------------------------------------------------------
    // Issue #3：不可信清单的完整校验
    // -----------------------------------------------------------------------

    /// 攻击者可以自己算根哈希，所以「根哈希自洽」绝不等于「清单可用」。
    fn forged(
        file_name: &str,
        total_len: u64,
        chunk_size: u32,
        chunks: Vec<ChunkHash>,
    ) -> FileManifest {
        let root_hash = root_hash_of(file_name, total_len, chunk_size, &chunks);
        FileManifest {
            file_name: file_name.to_string(),
            total_len,
            chunk_size,
            chunks,
            root_hash,
        }
    }

    #[test]
    fn chunk_size_为零时不会除零_panic() {
        // 旧代码：chunk_count(total_len>0, 0) -> div_ceil(0) -> panic。
        assert_eq!(chunk_count(1024, 0), 0);
        assert_eq!(chunk_len_at(0, 1024, 0), None);
        assert_eq!(chunk_len_at(u32::MAX, u64::MAX, 0), None);

        let evil = forged("evil.bin", 1024, 0, vec![ChunkHash::of(b"x")]);
        // 使用路径上的每个入口都只能返回错误/None，不能 panic。
        assert!(evil.validate().is_err());
        assert!(!evil.verify_chunk(0, b"x"));
        assert_eq!(evil.chunk_range(0), None);
        assert_eq!(evil.chunk_count(), 1);
    }

    #[test]
    fn 网络字节里的_chunk_size_零会被拒绝() {
        let bytes = forged("evil.bin", 1024, 0, vec![ChunkHash::of(b"x")])
            .to_bytes()
            .unwrap();
        let err = FileManifest::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "实际 {err:?}");
    }

    #[test]
    fn 分片大小超出范围会被拒绝() {
        // 0 / 1 / MIN-1 / MAX+1 / u32::MAX 全部拒绝，且都不能 panic。
        for bad in [
            0u32,
            1,
            MIN_CHUNK_SIZE - 1,
            MAX_CHUNK_SIZE + 1,
            u32::MAX,
            u32::MAX - 1,
        ] {
            let m = forged("x.bin", 0, bad, vec![]);
            let err = m.validate().unwrap_err();
            assert!(matches!(err, Error::Protocol(_)), "{bad}: 实际 {err:?}");

            let bytes = m.to_bytes().unwrap();
            assert!(FileManifest::from_bytes(&bytes).is_err(), "{bad} 应被拒绝");
            assert!(FileManifest::new("x.bin", 0, bad, vec![]).is_err());
        }

        // 边界值本身合法。
        assert!(FileManifest::new("x.bin", 0, MIN_CHUNK_SIZE, vec![]).is_ok());
        assert!(FileManifest::new("x.bin", 0, MAX_CHUNK_SIZE, vec![]).is_ok());
        assert!(validate_chunk_size(DEFAULT_CHUNK_SIZE).is_ok());
    }

    #[test]
    fn 分片数量与总长度不符会被拒绝() {
        // 数量太少。
        let too_few = forged(
            "x.bin",
            10_000_000,
            MIN_CHUNK_SIZE,
            vec![ChunkHash::of(b"a")],
        );
        assert!(too_few.validate().is_err());

        // 数量太多（total_len=0 却带了分片）。
        let too_many = forged("x.bin", 0, MIN_CHUNK_SIZE, vec![ChunkHash::of(b"a")]);
        assert!(too_many.validate().is_err());

        // 空文件带分片、非空文件不带分片。
        assert!(
            forged("x.bin", 1, MIN_CHUNK_SIZE, vec![])
                .validate()
                .is_err()
        );
        assert!(
            forged("x.bin", 0, MIN_CHUNK_SIZE, vec![])
                .validate()
                .is_ok()
        );

        // 差一片也拒绝（多一片）。
        let data = vec![0u8; MIN_CHUNK_SIZE as usize * 2];
        let mut chunks = data
            .chunks(MIN_CHUNK_SIZE as usize)
            .map(ChunkHash::of)
            .collect::<Vec<_>>();
        chunks.push(ChunkHash::of(b"extra"));
        assert!(
            forged("x.bin", data.len() as u64, MIN_CHUNK_SIZE, chunks)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn 根哈希不对会被拒绝() {
        let mut m = FileManifest::new("x.bin", 0, MIN_CHUNK_SIZE, vec![]).unwrap();
        m.root_hash = ChunkHash::of(b"not the real root");
        assert!(m.validate().is_err());
        assert!(!m.verify_root_hash());

        // 改文件名也算篡改。
        let mut m = FileManifest::new("x.bin", 0, MIN_CHUNK_SIZE, vec![]).unwrap();
        m.file_name = "y.bin".into();
        assert!(m.validate().is_err());
    }

    #[test]
    fn 极端总长度不会溢出或_panic() {
        // total_len = u64::MAX 配少量分片：validate 必须拒绝，且不能因为
        // 乘除/减法溢出而 panic。这里不假设派生的下标值是什么（这份清单本来
        // 就不合法），只要求「算得出结果或者给出 None」，绝不能 panic。
        for total_len in [u64::MAX, u64::MAX - 1, 1 << 62, u32::MAX as u64 + 1] {
            let m = forged(
                "x.bin",
                total_len,
                MIN_CHUNK_SIZE,
                vec![ChunkHash::of(b"a")],
            );
            assert!(m.validate().is_err(), "total_len={total_len} 应被拒绝");

            let _ = m.chunk_range(0);
            let _ = m.chunk_range(u32::MAX);
            let _ = m.chunk_offset(0);
            let _ = m.chunk_offset(u32::MAX);
            let _ = m.chunk_len(0);
            let _ = m.chunk_len(u32::MAX);

            // 数据长度对不上时一律拒绝，不会去索引越界的分片。
            assert!(!m.verify_chunk(0, &[]));
            assert!(!m.verify_chunk(u32::MAX, &[]));

            let _ = chunk_count(total_len, MAX_CHUNK_SIZE);
            let _ = chunk_count(total_len, 0);
            let _ = chunk_len_at(u32::MAX, total_len, MAX_CHUNK_SIZE);
            let _ = chunk_len_at(0, total_len, 0);
        }
    }

    #[test]
    fn 极大_chunk_size_与极大下标不越界() {
        // chunk_offset 用的是 checked_mul；用未校验的结构体直接调用也不能溢出。
        let m = forged("x.bin", u64::MAX, MAX_CHUNK_SIZE, vec![ChunkHash::of(b"a")]);
        assert_eq!(m.chunk_offset(0), Some(0));
        assert_eq!(m.chunk_offset(1), None, "只有 1 片，下标 1 越界");
    }

    #[test]
    fn from_bytes_与_new_走同一套校验() {
        // 造一个根哈希自洽、但分片数与 total_len 对不上的清单：
        // 旧代码的 from_bytes 只查根哈希，会放它过去。
        let m = forged(
            "x.bin",
            10_000_000,
            MIN_CHUNK_SIZE,
            vec![ChunkHash::of(b"a")],
        );
        assert!(m.verify_root_hash(), "根哈希本身是自洽的");
        assert!(m.validate().is_err());
        assert!(FileManifest::from_bytes(&m.to_bytes().unwrap()).is_err());
    }

    /// 任意字节输入（含随机截断/翻转）都不能把清单使用路径打 panic。
    ///
    /// 用固定种子的 xorshift 保证可复现；覆盖「解码失败」和「解码成功但字段
    /// 畸形」两种情况。
    #[test]
    fn 任意字节输入都不会让清单路径_panic() {
        let mut seed = 0x0f1e_2d3c_4b5a_6978u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let data: Vec<u8> = (0..(MIN_CHUNK_SIZE as usize * 2 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        let valid = manifest_of(&data, MIN_CHUNK_SIZE).to_bytes().unwrap();

        for round in 0..3_000u32 {
            let mut bytes = valid.clone();
            match round % 3 {
                // 随机翻转 1~4 个字节。
                0 => {
                    for _ in 0..(1 + next() % 4) {
                        let pos = (next() as usize) % bytes.len();
                        bytes[pos] ^= (next() as u8) | 1;
                    }
                }
                // 随机截断。
                1 => {
                    let keep = (next() as usize) % (bytes.len() + 1);
                    bytes.truncate(keep);
                }
                // 完全随机的垃圾。
                _ => {
                    let len = (next() as usize) % 128;
                    bytes = (0..len).map(|_| next() as u8).collect();
                }
            }

            let result = std::panic::catch_unwind(|| {
                if let Ok(m) = FileManifest::from_bytes(&bytes) {
                    // 能解码出来的清单必须是合法的，且使用它不能 panic。
                    assert!(m.validate().is_ok());
                    let _ = m.verify_root_hash();
                    let _ = m.chunk_count();
                    let _ = m.chunk_range(0);
                    let _ = m.chunk_range(m.chunk_count());
                    let _ = m.verify_chunk(0, &[]);
                    let _ = m.verify_chunk(u32::MAX, &data);
                    for index in [0u32, 1, m.chunk_count().saturating_sub(1)] {
                        let _ = m.chunk_len(index);
                        let _ = m.chunk_offset(index);
                    }
                }
            });
            assert!(result.is_ok(), "第 {round} 轮输入把清单路径打 panic 了");
        }
    }

    /// 与上面同样的目标，但直接对「解码 + 落盘准备」整条链路做检查。
    #[test]
    fn 任意字节输入都不会让解码路径_panic() {
        use crate::protocol::message::ControlMessage;

        let mut seed = 0xdead_beef_cafe_1234u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let valid = ControlMessage::Manifest(Box::new(manifest_of(
            &vec![9u8; MIN_CHUNK_SIZE as usize + 3],
            MIN_CHUNK_SIZE,
        )))
        .encode()
        .unwrap();

        for round in 0..3_000u32 {
            let mut bytes = valid.clone();
            if round % 2 == 0 {
                let pos = (next() as usize) % bytes.len();
                bytes[pos] ^= (next() as u8) | 1;
            } else {
                let keep = (next() as usize) % (bytes.len() + 1);
                bytes.truncate(keep);
            }

            let result = std::panic::catch_unwind(|| {
                let _ = ControlMessage::decode(&bytes);
            });
            assert!(result.is_ok(), "第 {round} 轮解码 panic 了");
        }
    }
}
