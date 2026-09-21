//! 落盘：临时文件 + 位图，支持断点续传。
//!
//! 设计要点：
//!
//! - 数据先写进 `<名字>.<根哈希前 16 位>.part`，**全部校验通过后**才改名成正式文件，
//!   中途放弃或崩溃都不会留下一个看起来正常、实际残缺的文件。
//! - 位图单独存 `<同名>.bitmap`，每片写成功就更新一次，因此崩溃后能接着传。
//! - 临时文件名带上根哈希，换一个文件（内容不同）不会误用上一次的残留进度。
//!
//! 目前用的是同步 `std::fs`。放到异步传输循环里会阻塞执行器，正式实现应当把
//! 这些调用挪进 `tokio::task::spawn_blocking`（TODO）。

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::protocol::manifest::{FileManifest, safe_file_name};
use crate::transfer::resume::ChunkBitmap;

/// 临时文件后缀。
const PART_SUFFIX: &str = "part";
/// 位图文件后缀。
const BITMAP_SUFFIX: &str = "bitmap";

/// 一个进行中的下载。
pub struct PartialDownload {
    manifest: FileManifest,
    target_path: PathBuf,
    temp_path: PathBuf,
    state_path: PathBuf,
    /// `None` 表示句柄已关闭（收尾或放弃之后）。
    file: Option<File>,
    bitmap: ChunkBitmap,
}

impl PartialDownload {
    /// 正式文件的目标路径（已做过文件名清洗，不会跑出 `dir`）。
    pub fn target_path_for(dir: &Path, manifest: &FileManifest) -> PathBuf {
        dir.join(safe_file_name(&manifest.file_name))
    }

    /// 临时文件路径。带根哈希前缀，避免不同内容的同名文件互相污染。
    pub fn temp_path_for(dir: &Path, manifest: &FileManifest) -> PathBuf {
        let name = safe_file_name(&manifest.file_name);
        let tag = &manifest.root_hash.to_hex()[..16];
        dir.join(format!("{name}.{tag}.{PART_SUFFIX}"))
    }

    /// 位图路径。
    pub fn state_path_for(dir: &Path, manifest: &FileManifest) -> PathBuf {
        let name = safe_file_name(&manifest.file_name);
        let tag = &manifest.root_hash.to_hex()[..16];
        dir.join(format!("{name}.{tag}.{BITMAP_SUFFIX}"))
    }

    /// 开始（或继续）一个下载。
    ///
    /// 临时文件与位图已存在且自洽时自动续传。
    ///
    /// 入口先做一次完整 [`FileManifest::validate`]：这个结构体会按
    /// `manifest.total_len` 直接 `set_len` 出文件、按 `chunk_count` 分配位图，
    /// 是「不可信清单」最危险的下游。校验不通过就什么都不碰。
    pub fn create(dir: &Path, manifest: FileManifest) -> Result<Self> {
        manifest.validate()?;
        fs::create_dir_all(dir)?;

        let target_path = Self::target_path_for(dir, &manifest);
        let temp_path = Self::temp_path_for(dir, &manifest);
        let state_path = Self::state_path_for(dir, &manifest);

        let mut bitmap = load_bitmap(&state_path, manifest.chunk_count())?;

        // 已有的临时文件长度对不上就整个作废，从头来。
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&temp_path)?;

        let existing_len = file.metadata()?.len();
        if existing_len != manifest.total_len {
            file.set_len(0)?;
            file.set_len(manifest.total_len)?;
            bitmap = ChunkBitmap::new(manifest.chunk_count());
            save_bitmap(&state_path, &bitmap)?;
        }

        Ok(Self {
            manifest,
            target_path,
            temp_path,
            state_path,
            file: Some(file),
            bitmap,
        })
    }

    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    pub fn bitmap(&self) -> &ChunkBitmap {
        &self.bitmap
    }

    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    /// 还缺哪些片。
    pub fn missing(&self) -> Vec<u32> {
        self.bitmap.missing()
    }

    pub fn is_complete(&self) -> bool {
        self.bitmap.is_complete()
    }

    /// 写入一片数据。
    ///
    /// 先按清单校验，再落盘，最后更新位图。对端发来坏数据只会被丢弃，
    /// 不会破坏文件。
    pub fn write_chunk(&mut self, index: u32, data: &[u8]) -> Result<()> {
        if !self.manifest.verify_chunk(index, data) {
            return Err(Error::Protocol(format!(
                "第 {index} 片校验失败（长度或哈希不符），已丢弃"
            )));
        }

        let offset = self
            .manifest
            .chunk_offset(index)
            .ok_or_else(|| Error::Protocol(format!("第 {index} 片越界")))?;

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| Error::Protocol("下载已结束，无法继续写入".into()))?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;

        self.bitmap.set(index)?;
        save_bitmap(&self.state_path, &self.bitmap)?;
        Ok(())
    }

    /// 收尾：落盘并改名成正式文件，清理位图。返回正式文件路径。
    pub fn finalize(mut self) -> Result<PathBuf> {
        if !self.bitmap.is_complete() {
            return Err(Error::Protocol(format!(
                "还有 {} 片没收到，不能收尾",
                self.manifest.chunk_count() - self.bitmap.count_set()
            )));
        }

        if let Some(file) = self.file.as_mut() {
            file.sync_all()?;
        }
        // 先关句柄再改名：Unix 上无所谓，Windows 上文件被占用就改不动。
        self.file = None;

        let target = unique_path(&self.target_path);
        fs::rename(&self.temp_path, &target)?;
        let _ = fs::remove_file(&self.state_path);

        Ok(target)
    }

    /// 放弃下载，删掉临时文件和位图。
    pub fn discard(mut self) -> Result<()> {
        self.file = None;
        let _ = fs::remove_file(&self.temp_path);
        let _ = fs::remove_file(&self.state_path);
        Ok(())
    }
}

impl std::fmt::Debug for PartialDownload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialDownload")
            .field("target", &self.target_path)
            .field("bitmap", &self.bitmap)
            .finish()
    }
}

/// 读位图；文件不存在或不可用时返回空位图（当作从头开始）。
fn load_bitmap(path: &Path, chunk_count: u32) -> Result<ChunkBitmap> {
    match fs::read(path) {
        Ok(bytes) => match ChunkBitmap::from_bytes(chunk_count, &bytes) {
            Ok(bitmap) => Ok(bitmap),
            Err(_) => Ok(ChunkBitmap::new(chunk_count)),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(ChunkBitmap::new(chunk_count)),
        Err(err) => Err(err.into()),
    }
}

/// 原子写位图：先写临时文件再改名，避免崩溃时留下半截状态。
fn save_bitmap(path: &Path, bitmap: &ChunkBitmap) -> Result<()> {
    let tmp = path.with_extension("bitmap.tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&bitmap.to_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// 目标文件已存在时另找一个名字，避免覆盖用户已有的文件。
fn unique_path(target: &Path) -> PathBuf {
    if !target.exists() {
        return target.to_path_buf();
    }

    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let stem = target
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let ext = target.extension().map(|s| s.to_string_lossy().into_owned());

    for counter in 1..10_000u32 {
        let name = match &ext {
            Some(ext) => format!("{stem} ({counter}).{ext}"),
            None => format!("{stem} ({counter})"),
        };
        let candidate = dir.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    // 极端情况下退回原名，交给 rename 覆盖。
    target.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::manifest::{ChunkHash, MIN_CHUNK_SIZE};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "p2p_file_store_{tag}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn manifest_for(content: &[u8], name: &str) -> FileManifest {
        let chunks = content
            .chunks(MIN_CHUNK_SIZE as usize)
            .map(ChunkHash::of)
            .collect::<Vec<_>>();
        FileManifest::new(name, content.len() as u64, MIN_CHUNK_SIZE, chunks).unwrap()
    }

    fn slice<'a>(content: &'a [u8], manifest: &FileManifest, index: u32) -> &'a [u8] {
        let (offset, len) = manifest.chunk_range(index).unwrap();
        &content[offset as usize..(offset + u64::from(len)) as usize]
    }

    #[test]
    fn 完整写入并收尾() {
        let dir = temp_dir("complete");
        let content: Vec<u8> = (0..MIN_CHUNK_SIZE * 2 + 11)
            .map(|i| (i % 241) as u8)
            .collect();
        let manifest = manifest_for(&content, "movie.bin");

        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert_eq!(download.missing().len(), 3);

        for index in 0..manifest.chunk_count() {
            download
                .write_chunk(index, slice(&content, &manifest, index))
                .unwrap();
        }
        assert!(download.is_complete());

        let out = download.finalize().unwrap();
        assert_eq!(fs::read(&out).unwrap(), content);
        assert_eq!(out.file_name().unwrap(), "movie.bin");
        assert!(!PartialDownload::temp_path_for(&dir, &manifest).exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 坏数据被拒绝且不写坏文件() {
        let dir = temp_dir("bad");
        let content = vec![5u8; MIN_CHUNK_SIZE as usize];
        let manifest = manifest_for(&content, "a.bin");
        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();

        let mut tampered = content.clone();
        tampered[0] ^= 0xff;
        assert!(download.write_chunk(0, &tampered).is_err());
        assert!(
            download.write_chunk(0, &content[..10]).is_err(),
            "长度不符也应拒绝"
        );
        assert!(
            download.write_chunk(99, &content).is_err(),
            "越界分片应拒绝"
        );

        assert_eq!(download.bitmap().count_set(), 0, "坏数据不应被标记为已完成");
        assert_eq!(
            fs::metadata(download.temp_path()).unwrap().len(),
            content.len() as u64
        );

        // 正确数据仍然能写入。
        download.write_chunk(0, &content).unwrap();
        assert!(download.is_complete());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 重新打开时接着上次的进度() {
        let dir = temp_dir("resume");
        let content: Vec<u8> = (0..MIN_CHUNK_SIZE * 3).map(|i| (i % 199) as u8).collect();
        let manifest = manifest_for(&content, "b.bin");

        {
            let mut first = PartialDownload::create(&dir, manifest.clone()).unwrap();
            first.write_chunk(0, slice(&content, &manifest, 0)).unwrap();
            first.write_chunk(1, slice(&content, &manifest, 1)).unwrap();
            // 直接丢弃结构体（不调用 discard/finalize），模拟进程退出或断线。
        }

        let second = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert_eq!(second.bitmap().present(), vec![0, 1]);
        assert_eq!(second.missing(), vec![2]);

        let mut second = second;
        second
            .write_chunk(2, slice(&content, &manifest, 2))
            .unwrap();
        let out = second.finalize().unwrap();
        assert_eq!(fs::read(&out).unwrap(), content);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 临时文件长度不符则重来() {
        let dir = temp_dir("reset");
        let content = vec![1u8; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "c.bin");

        // 先造一个长度错误的残留文件。
        fs::write(PartialDownload::temp_path_for(&dir, &manifest), b"junk").unwrap();

        let download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert_eq!(download.bitmap().count_set(), 0);
        assert_eq!(
            fs::metadata(download.temp_path()).unwrap().len(),
            content.len() as u64,
            "残留文件应被重新截断到正确长度"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 没传完不能收尾() {
        let dir = temp_dir("incomplete");
        let content = vec![2u8; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "d.bin");
        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        download
            .write_chunk(0, slice(&content, &manifest, 0))
            .unwrap();
        assert!(download.finalize().is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 文件名穿越被挡住() {
        let dir = temp_dir("trav");
        let content = vec![3u8; 8];
        let manifest = manifest_for(&content, "../../evil.sh");

        let target = PartialDownload::target_path_for(&dir, &manifest);
        assert_eq!(target, dir.join("evil.sh"), "清洗后必须落在输出目录内");

        let temp = PartialDownload::temp_path_for(&dir, &manifest);
        assert_eq!(temp.parent().unwrap(), dir);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 同名文件不覆盖() {
        let dir = temp_dir("collide");
        let content = vec![4u8; 8];
        let manifest = manifest_for(&content, "same.bin");
        let existing = "已有的重要文件".as_bytes();
        fs::write(dir.join("same.bin"), existing).unwrap();

        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        download.write_chunk(0, &content).unwrap();
        let out = download.finalize().unwrap();

        assert_eq!(out.file_name().unwrap(), "same (1).bin");
        assert_eq!(fs::read(dir.join("same.bin")).unwrap(), existing);
        assert_eq!(fs::read(&out).unwrap(), content);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 放弃时清理残留() {
        let dir = temp_dir("discard");
        let content = vec![6u8; MIN_CHUNK_SIZE as usize];
        let manifest = manifest_for(&content, "e.bin");
        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        download.write_chunk(0, &content).unwrap();

        let temp = download.temp_path().to_path_buf();
        download.discard().unwrap();

        assert!(!temp.exists());
        assert!(!PartialDownload::state_path_for(&dir, &manifest).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Issue #3：畸形清单必须在**碰文件系统之前**被拒绝。
    ///
    /// `PartialDownload::create` 会按 `total_len` 直接 `set_len`、按
    /// `chunk_count` 分配位图，是畸形清单最危险的下游。旧代码在这里不校验，
    /// 后面的 `write_chunk -> verify_chunk -> chunk_len -> div_ceil(0)` 会 panic。
    #[test]
    fn 畸形清单在创建下载前被拒绝() {
        let dir = temp_dir("evil_manifest");

        let cases = vec![
            // chunk_size = 0：旧代码会在写第一片时除零 panic。
            FileManifest {
                file_name: "evil.bin".into(),
                total_len: 1024,
                chunk_size: 0,
                chunks: vec![ChunkHash::of(b"x")],
                root_hash: ChunkHash::of(b"y"),
            },
            // 分片数与 total_len 不符。
            FileManifest {
                file_name: "evil.bin".into(),
                total_len: 10_000_000,
                chunk_size: MIN_CHUNK_SIZE,
                chunks: vec![ChunkHash::of(b"x")],
                root_hash: ChunkHash::of(b"y"),
            },
            // 根哈希不对。
            FileManifest {
                file_name: "evil.bin".into(),
                total_len: 0,
                chunk_size: MIN_CHUNK_SIZE,
                chunks: vec![],
                root_hash: ChunkHash::of(b"y"),
            },
            // 极端 total_len：不能让 set_len 被拉到一个天文数字。
            FileManifest {
                file_name: "evil.bin".into(),
                total_len: u64::MAX,
                chunk_size: MIN_CHUNK_SIZE,
                chunks: vec![ChunkHash::of(b"x")],
                root_hash: ChunkHash::of(b"y"),
            },
        ];

        for (index, manifest) in cases.into_iter().enumerate() {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                PartialDownload::create(&dir, manifest.clone())
            }));
            let result =
                outcome.unwrap_or_else(|_| panic!("第 {index} 个畸形清单把 create 打 panic 了"));
            let err = result.expect_err("畸形清单必须被拒绝");
            assert!(
                matches!(err, Error::Protocol(_)),
                "第 {index} 个: 实际 {err:?}"
            );
            assert!(
                fs::read_dir(&dir).unwrap().next().is_none(),
                "第 {index} 个畸形清单不该创建任何文件"
            );
        }

        fs::remove_dir_all(&dir).unwrap();
    }
}
