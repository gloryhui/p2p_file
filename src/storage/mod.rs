//! 落盘：临时文件 + 位图，支持断点续传。
//!
//! 设计要点：
//!
//! - 数据先写进 `<名字>.<根哈希前 16 位>.part`，**全部校验通过后**才改名成正式文件，
//!   中途放弃或崩溃都不会留下一个看起来正常、实际残缺的文件。
//! - 位图单独存 `<同名>.bitmap`。位图是可丢失的恢复提示，不是数据真相；每次
//!   恢复都会重新校验其中标记为完成的分片。位图只保存 durable checkpoint 的快照。
//!   位图完整保留时只需重传未 checkpoint 的分片；位图丢失时可能全部重传，
//!   包括 Windows 替换位图时删除旧文件与改名之间发生崩溃的情况。
//! - 临时文件名带上根哈希，换一个文件（内容不同）不会误用上一次的残留进度。
//!
//! 目前用的是同步 `std::fs`。放到异步传输循环里会阻塞执行器，正式实现应当把
//! 这些调用挪进 `tokio::task::spawn_blocking`（TODO）。

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::protocol::manifest::{FileManifest, safe_file_name};
use crate::transfer::resume::ChunkBitmap;

/// 临时文件后缀。
const PART_SUFFIX: &str = "part";
/// 位图文件后缀。
const BITMAP_SUFFIX: &str = "bitmap";
/// 正式文件最多尝试的带编号候选数；耗尽后明确失败，绝不回退到原名覆盖。
const MAX_FINALIZE_SUFFIX: u32 = 10_000;
/// 脏数据达到这个大小后做一次 durable checkpoint。
const CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;
/// 距离上次 durable checkpoint 超过这个时间后做一次 checkpoint。
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
struct CheckpointPolicy {
    bytes: u64,
    interval: Duration,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            bytes: CHECKPOINT_BYTES,
            interval: CHECKPOINT_INTERVAL,
        }
    }
}

/// 一个进行中的下载。
pub struct PartialDownload {
    manifest: FileManifest,
    target_path: PathBuf,
    temp_path: PathBuf,
    state_path: PathBuf,
    /// `None` 表示句柄已关闭（收尾或放弃之后）。
    file: Option<File>,
    /// 当前进程已经校验并写入 `.part` 的分片，可能尚未 sync 到稳定存储。
    written_bitmap: ChunkBitmap,
    /// 最近一次成功 checkpoint 后，已安全落盘并写入 `.bitmap` 的快照。
    durable_bitmap: ChunkBitmap,
    /// 上次成功 checkpoint 后累计写入的字节数（包括重复写入）。
    dirty_bytes: u64,
    /// 最近一次成功 durable checkpoint 的时间。
    last_checkpoint: Instant,
    checkpoint_policy: CheckpointPolicy,
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
        Self::create_with_policy(dir, manifest, CheckpointPolicy::default())
    }

    fn create_with_policy(
        dir: &Path,
        manifest: FileManifest,
        checkpoint_policy: CheckpointPolicy,
    ) -> Result<Self> {
        manifest.validate()?;
        fs::create_dir_all(dir)?;

        let target_path = Self::target_path_for(dir, &manifest);
        let temp_path = Self::temp_path_for(dir, &manifest);
        let state_path = Self::state_path_for(dir, &manifest);

        let (mut bitmap, bitmap_needs_repair) = load_bitmap(&state_path, manifest.chunk_count())?;

        // 已有的临时文件长度对不上就整个作废，从头来。
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&temp_path)?;

        let existing_len = file.metadata()?.len();
        if existing_len != manifest.total_len {
            file.set_len(0)?;
            file.set_len(manifest.total_len)?;
            // 不允许空位图在文件长度尚未安全落盘时成为恢复状态。
            file.sync_all()?;
            bitmap = ChunkBitmap::new(manifest.chunk_count());
            save_bitmap(&state_path, &bitmap)?;
        } else {
            // bitmap 只说明“上次曾经认为这些片完成”，不能跳过磁盘数据校验。
            // 每次只分配一个受 manifest 限制的 chunk 缓冲区，避免恢复路径被状态文件
            // 放大成不受控的内存分配。
            let mut bitmap_changed = bitmap_needs_repair;
            for index in bitmap.present() {
                let (offset, len) = manifest
                    .chunk_range(index)
                    .ok_or_else(|| Error::Protocol(format!("位图中的分片 {index} 越界")))?;
                file.seek(SeekFrom::Start(offset))?;
                let mut data = vec![0u8; len as usize];
                match file.read_exact(&mut data) {
                    Ok(()) if manifest.verify_chunk(index, &data) => {}
                    Ok(()) => {
                        bitmap.clear(index)?;
                        bitmap_changed = true;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                        bitmap.clear(index)?;
                        bitmap_changed = true;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            if bitmap_changed {
                save_bitmap(&state_path, &bitmap)?;
            }
        }

        let durable_bitmap = bitmap.clone();
        Ok(Self {
            manifest,
            target_path,
            temp_path,
            state_path,
            file: Some(file),
            written_bitmap: bitmap,
            durable_bitmap,
            dirty_bytes: 0,
            last_checkpoint: Instant::now(),
            checkpoint_policy,
        })
    }

    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    /// 当前进程已经写入并校验通过的分片。未进入 checkpoint 的分片也会出现在这里。
    pub fn bitmap(&self) -> &ChunkBitmap {
        &self.written_bitmap
    }

    /// 最近一次成功 checkpoint 的持久化进度。
    #[cfg(test)]
    pub(crate) fn durable_bitmap(&self) -> &ChunkBitmap {
        &self.durable_bitmap
    }

    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    /// 还缺哪些片。
    pub fn missing(&self) -> Vec<u32> {
        self.written_bitmap.missing()
    }

    pub fn is_complete(&self) -> bool {
        self.written_bitmap.is_complete()
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

        {
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| Error::Protocol("下载已结束，无法继续写入".into()))?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(data)?;
        }

        self.written_bitmap.set(index)?;
        self.dirty_bytes = self.dirty_bytes.saturating_add(data.len() as u64);
        self.checkpoint_if_due()
    }

    fn checkpoint_if_due(&mut self) -> Result<()> {
        if self.dirty_bytes >= self.checkpoint_policy.bytes
            || self.last_checkpoint.elapsed() >= self.checkpoint_policy.interval
        {
            self.checkpoint()?;
        }
        Ok(())
    }

    /// 将当前 written bitmap 与 `.part` 一起推进到 durable 状态。
    pub(crate) fn checkpoint(&mut self) -> Result<()> {
        let checkpoint_bytes = self.dirty_bytes;
        let checkpoint_started = Instant::now();

        // 顺序不可改变：先让文件数据 durable，再发布 bitmap 快照。
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| Error::Protocol("下载已结束，无法 checkpoint".into()))?;
        file.sync_data()?;

        let snapshot = self.written_bitmap.clone();
        save_bitmap(&self.state_path, &snapshot)?;
        self.durable_bitmap = snapshot;
        self.dirty_bytes = 0;
        self.last_checkpoint = Instant::now();

        tracing::debug!(
            checkpoint_bytes,
            checkpoint_elapsed_ms = checkpoint_started.elapsed().as_millis(),
            "完成 durable checkpoint"
        );
        Ok(())
    }

    /// 收尾：落盘并改名成正式文件，清理位图。返回正式文件路径。
    pub fn finalize(mut self) -> Result<PathBuf> {
        if !self.written_bitmap.is_complete() {
            return Err(Error::Protocol(format!(
                "还有 {} 片没收到，不能收尾",
                self.manifest.chunk_count() - self.written_bitmap.count_set()
            )));
        }

        // 即使尚未达到自动 checkpoint 条件，收尾也必须先发布完整的 durable bitmap。
        self.checkpoint()?;
        if let Some(file) = self.file.as_mut() {
            file.sync_all()?;
        }
        // 先关句柄再改名：Unix 上无所谓，Windows 上文件被占用就改不动。
        self.file = None;

        // `hard_link` 在目标目录项已存在时原子失败，不会跟随或覆盖普通文件、
        // symlink 或 Windows reparse point。成功后删除同一目录中的 `.part`，
        // 从而把已经 sync 的 inode 交给正式文件名；失败时只尝试下一个名字，
        // 绝不退回到可能覆盖目标的 rename。
        let target = publish_no_replace(&self.temp_path, &self.target_path)?;
        sync_parent_dir(&target)?;
        remove_file_if_exists(&self.state_path)?;
        sync_parent_dir(&self.state_path)?;

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
            .field("written_bitmap", &self.written_bitmap)
            .field("durable_bitmap", &self.durable_bitmap)
            .field("dirty_bytes", &self.dirty_bytes)
            .finish()
    }
}

/// 读位图；文件不存在或不可用时返回空位图（当作从头开始）。第二个返回值
/// 表示状态文件存在但需要被修复。
fn load_bitmap(path: &Path, chunk_count: u32) -> Result<(ChunkBitmap, bool)> {
    match fs::read(path) {
        Ok(bytes) => match ChunkBitmap::from_bytes(chunk_count, &bytes) {
            Ok(bitmap) => Ok((bitmap, false)),
            // 损坏/半截 bitmap 只能当作“没有可复用进度”，并在 create 中修复落盘。
            Err(_) => Ok((ChunkBitmap::new(chunk_count), true)),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok((ChunkBitmap::new(chunk_count), false))
        }
        Err(err) => Err(err.into()),
    }
}

/// 写位图：先把临时文件写完并同步，再做跨平台替换。
///
/// Unix 的 `rename` 可以直接替换旧目标。Windows 不允许用同样的调用覆盖已有
/// 文件，因此采用“删除旧目标，再改名”的语义；这会留下一个很短的 bitmap 缺失
/// 窗口，但 bitmap 本来就是提示信息，恢复时会重新校验 `.part`，所以崩溃最多导致
/// 重传，绝不会把坏数据当成已完成。临时文件和目录同步仍保证正常完成时状态完整。
fn save_bitmap(path: &Path, bitmap: &ChunkBitmap) -> Result<()> {
    let tmp = path.with_extension("bitmap.tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&bitmap.to_bytes())?;
    file.sync_all()?;
    // Windows cannot rename an open temporary file reliably.
    drop(file);
    replace_bitmap_file(&tmp, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_bitmap_file(tmp: &Path, path: &Path) -> Result<()> {
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(windows)]
fn replace_bitmap_file(tmp: &Path, path: &Path) -> Result<()> {
    // std::fs::rename maps to MoveFileEx without replace-existing on Windows.
    // Remove the old state explicitly, then rename the already-synced replacement.
    // A missing bitmap is safe because create() treats it as empty and revalidates data.
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    // Windows has no portable std equivalent for syncing a directory handle. The
    // file contents are synced before replacement, and recovery treats bitmap as
    // advisory, so an uncommitted directory entry can only cause retransmission.
    Ok(())
}

/// 生成正式文件候选名。这里不检查存在性；是否可用只能由原子 publish 操作决定。
fn candidate_paths(target: &Path, max_suffix: u32) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(max_suffix as usize + 1);
    candidates.push(target.to_path_buf());
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let stem = target
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let ext = target.extension().map(|s| s.to_string_lossy().into_owned());

    for counter in 1..=max_suffix {
        let name = match &ext {
            Some(ext) => format!("{stem} ({counter}).{ext}"),
            None => format!("{stem} ({counter})"),
        };
        candidates.push(dir.join(name));
    }
    candidates
}

/// 在同一目录内以 no-replace 语义发布临时文件。
///
/// `hard_link` 对目标目录项使用原子 create-new 语义：Linux 上对应 `link(2)`，
/// Windows 上对应 `CreateHardLinkW`。两者都不会替换已存在的目录项，因此普通
/// 文件、目录、symlink 和 reparse point 都只会被视为“这个名字已占用”。如果底层
/// 文件系统不支持 hard link，则返回错误；这里绝不能退回 `rename`，否则会重新
/// 引入跨平台覆盖风险。
fn publish_no_replace(temp: &Path, target: &Path) -> Result<PathBuf> {
    publish_no_replace_with(temp, target, MAX_FINALIZE_SUFFIX, |_| {})
}

fn publish_no_replace_with<F>(
    temp: &Path,
    target: &Path,
    max_suffix: u32,
    mut before_attempt: F,
) -> Result<PathBuf>
where
    F: FnMut(&Path),
{
    for candidate in candidate_paths(target, max_suffix) {
        before_attempt(&candidate);
        match fs::hard_link(temp, &candidate) {
            Ok(()) => {
                // The link is now the formal name. Removing only our same-directory
                // temp entry cannot overwrite another file; if removal fails, report
                // failure and keep the bitmap for recovery instead of claiming success.
                fs::remove_file(temp)?;
                return Ok(candidate);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                // Some Windows reparse-point cases surface as PermissionDenied rather
                // than AlreadyExists. `symlink_metadata` does not follow the name, so
                // an existing directory entry is still safely treated as occupied.
                match fs::symlink_metadata(&candidate) {
                    Ok(_) => continue,
                    Err(metadata_err) if metadata_err.kind() == std::io::ErrorKind::NotFound => {
                        return Err(err.into());
                    }
                    Err(metadata_err) => return Err(metadata_err.into()),
                }
            }
        }
    }

    Err(Error::Protocol(format!(
        "正式文件名已耗尽：{} 个候选均被占用",
        max_suffix + 1
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::manifest::{ChunkHash, MIN_CHUNK_SIZE};
    use std::sync::{Arc, Barrier};

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

    fn no_auto_checkpoint_policy() -> CheckpointPolicy {
        CheckpointPolicy {
            bytes: u64::MAX,
            interval: Duration::MAX,
        }
    }

    fn persisted_bitmap(dir: &Path, manifest: &FileManifest) -> ChunkBitmap {
        ChunkBitmap::from_bytes(
            manifest.chunk_count(),
            &fs::read(PartialDownload::state_path_for(dir, manifest)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn 字节阈值自动checkpoint并开始下一批() {
        let dir = temp_dir("checkpoint_bytes");
        let content = vec![0x41; MIN_CHUNK_SIZE as usize * 3];
        let manifest = manifest_for(&content, "bytes.bin");
        let mut download = PartialDownload::create_with_policy(
            &dir,
            manifest.clone(),
            CheckpointPolicy {
                bytes: u64::from(MIN_CHUNK_SIZE) * 2,
                interval: Duration::MAX,
            },
        )
        .unwrap();
        download
            .write_chunk(0, slice(&content, &manifest, 0))
            .unwrap();
        assert!(persisted_bitmap(&dir, &manifest).present().is_empty());
        download
            .write_chunk(1, slice(&content, &manifest, 1))
            .unwrap();
        assert_eq!(persisted_bitmap(&dir, &manifest).present(), vec![0, 1]);
        assert_eq!(download.dirty_bytes, 0);
        download
            .write_chunk(2, slice(&content, &manifest, 2))
            .unwrap();
        assert_eq!(download.dirty_bytes, u64::from(MIN_CHUNK_SIZE));
        drop(download);
        let recovered = PartialDownload::create(&dir, manifest).unwrap();
        assert_eq!(recovered.bitmap().present(), vec![0, 1]);
        drop(recovered);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn 时间阈值在下一片写入后自动checkpoint() {
        let dir = temp_dir("checkpoint_interval");
        let content = vec![0x42; MIN_CHUNK_SIZE as usize];
        let manifest = manifest_for(&content, "interval.bin");
        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        // 直接回拨检查点时间，不依赖 sleep 或机器运行速度。
        let previous = Instant::now() - CHECKPOINT_INTERVAL;
        download.last_checkpoint = previous;
        download.write_chunk(0, &content).unwrap();
        assert!(persisted_bitmap(&dir, &manifest).is_complete());
        assert!(download.durable_bitmap.is_complete());
        assert_eq!(download.dirty_bytes, 0);
        assert!(download.last_checkpoint > previous);
        drop(download);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn checkpoint保存失败不推进状态且可以重试() {
        let dir = temp_dir("checkpoint_failure");
        let content = vec![0x43; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "failure.bin");
        let mut download = PartialDownload::create_with_policy(
            &dir,
            manifest.clone(),
            no_auto_checkpoint_policy(),
        )
        .unwrap();
        download
            .write_chunk(0, slice(&content, &manifest, 0))
            .unwrap();
        download.checkpoint().unwrap();
        download
            .write_chunk(1, slice(&content, &manifest, 1))
            .unwrap();
        let previous = download.last_checkpoint;
        // 用目录占据 bitmap.tmp，跨平台稳定阻止保存，不依赖权限。
        let blocked = download.state_path.with_extension("bitmap.tmp");
        fs::create_dir(&blocked).unwrap();
        assert!(download.checkpoint().is_err());
        assert!(download.written_bitmap.is_complete());
        assert_eq!(download.durable_bitmap.present(), vec![0]);
        assert_eq!(persisted_bitmap(&dir, &manifest).present(), vec![0]);
        assert_eq!(download.dirty_bytes, u64::from(MIN_CHUNK_SIZE));
        assert_eq!(download.last_checkpoint, previous);
        fs::remove_dir(blocked).unwrap();
        download.checkpoint().unwrap();
        assert!(persisted_bitmap(&dir, &manifest).is_complete());
        assert_eq!(download.dirty_bytes, 0);
        drop(download);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn finalize强制checkpoint失败时不能发布文件() {
        let dir = temp_dir("finalize_checkpoint_failure");
        let content = vec![0x44; MIN_CHUNK_SIZE as usize];
        let manifest = manifest_for(&content, "finalize-failure.bin");
        let mut download = PartialDownload::create_with_policy(
            &dir,
            manifest.clone(),
            no_auto_checkpoint_policy(),
        )
        .unwrap();
        download.write_chunk(0, &content).unwrap();
        fs::create_dir(download.state_path.with_extension("bitmap.tmp")).unwrap();
        assert!(download.finalize().is_err());
        assert!(!PartialDownload::target_path_for(&dir, &manifest).exists());
        assert!(PartialDownload::temp_path_for(&dir, &manifest).exists());
        assert!(persisted_bitmap(&dir, &manifest).present().is_empty());
        fs::remove_dir_all(dir).unwrap();
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
            first.checkpoint().unwrap();
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
    fn 未checkpoint的分片不进入持久化恢复进度() {
        let dir = temp_dir("not_durable");
        let content = vec![0x31u8; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "not-durable.bin");

        {
            let mut download = PartialDownload::create_with_policy(
                &dir,
                manifest.clone(),
                no_auto_checkpoint_policy(),
            )
            .unwrap();
            download
                .write_chunk(0, slice(&content, &manifest, 0))
                .unwrap();
            assert!(download.bitmap().is_set(0));
            assert!(!download.durable_bitmap().is_set(0));
            let persisted = ChunkBitmap::from_bytes(
                manifest.chunk_count(),
                &fs::read(PartialDownload::state_path_for(&dir, &manifest)).unwrap(),
            )
            .unwrap();
            assert!(!persisted.is_set(0));
        }

        let recovered = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert!(!recovered.bitmap().is_set(0));
        assert_eq!(recovered.missing(), vec![0, 1]);
        drop(recovered);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checkpoint后可以恢复() {
        let dir = temp_dir("checkpoint_resume");
        let content = vec![0x32u8; MIN_CHUNK_SIZE as usize * 3];
        let manifest = manifest_for(&content, "checkpoint.bin");

        {
            let mut download = PartialDownload::create_with_policy(
                &dir,
                manifest.clone(),
                no_auto_checkpoint_policy(),
            )
            .unwrap();
            download
                .write_chunk(0, slice(&content, &manifest, 0))
                .unwrap();
            download
                .write_chunk(1, slice(&content, &manifest, 1))
                .unwrap();
            assert_eq!(download.durable_bitmap().present(), Vec::<u32>::new());
            download.checkpoint().unwrap();
            assert_eq!(download.durable_bitmap().present(), vec![0, 1]);
        }

        let recovered = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert_eq!(recovered.bitmap().present(), vec![0, 1]);
        assert_eq!(recovered.missing(), vec![2]);
        drop(recovered);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checkpoint后篡改的分片会清位且保留其它分片() {
        let dir = temp_dir("checkpoint_corrupt");
        let content: Vec<u8> = (0..MIN_CHUNK_SIZE * 3)
            .map(|index| (index % 193) as u8)
            .collect();
        let manifest = manifest_for(&content, "checkpoint-corrupt.bin");

        {
            let mut download = PartialDownload::create_with_policy(
                &dir,
                manifest.clone(),
                no_auto_checkpoint_policy(),
            )
            .unwrap();
            for index in 0..manifest.chunk_count() {
                download
                    .write_chunk(index, slice(&content, &manifest, index))
                    .unwrap();
            }
            download.checkpoint().unwrap();
        }

        let temp = PartialDownload::temp_path_for(&dir, &manifest);
        let (offset, _) = manifest.chunk_range(1).unwrap();
        let mut corrupted = slice(&content, &manifest, 1).to_vec();
        corrupted[0] ^= 0xff;
        let mut file = OpenOptions::new().write(true).open(&temp).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&corrupted).unwrap();
        file.sync_all().unwrap();

        let recovered = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert_eq!(recovered.bitmap().present(), vec![0, 2]);
        assert_eq!(recovered.durable_bitmap().present(), vec![0, 2]);
        let persisted = ChunkBitmap::from_bytes(
            manifest.chunk_count(),
            &fs::read(PartialDownload::state_path_for(&dir, &manifest)).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.present(), vec![0, 2]);
        drop(recovered);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn finalize会强制checkpoint() {
        let dir = temp_dir("finalize_checkpoint");
        let content = vec![0x33u8; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "finalize-checkpoint.bin");

        let mut download = PartialDownload::create_with_policy(
            &dir,
            manifest.clone(),
            no_auto_checkpoint_policy(),
        )
        .unwrap();
        for index in 0..manifest.chunk_count() {
            download
                .write_chunk(index, slice(&content, &manifest, index))
                .unwrap();
        }
        let persisted_before_finalize =
            fs::read(PartialDownload::state_path_for(&dir, &manifest)).unwrap();
        assert_eq!(persisted_before_finalize, vec![0u8]);

        let output = download.finalize().unwrap();
        assert_eq!(fs::read(&output).unwrap(), content);
        assert!(!PartialDownload::temp_path_for(&dir, &manifest).exists());
        assert!(!PartialDownload::state_path_for(&dir, &manifest).exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 可以连续执行多次checkpoint() {
        let dir = temp_dir("checkpoint_multiple");
        let content = vec![0x34u8; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "checkpoint-multiple.bin");

        {
            let mut download = PartialDownload::create_with_policy(
                &dir,
                manifest.clone(),
                no_auto_checkpoint_policy(),
            )
            .unwrap();
            download
                .write_chunk(0, slice(&content, &manifest, 0))
                .unwrap();
            download.checkpoint().unwrap();
            assert_eq!(download.durable_bitmap().present(), vec![0]);
            download
                .write_chunk(1, slice(&content, &manifest, 1))
                .unwrap();
            download.checkpoint().unwrap();
            assert_eq!(download.durable_bitmap().present(), vec![0, 1]);
        }

        let recovered = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert!(recovered.is_complete());
        drop(recovered);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 恢复时会清除指向损坏磁盘数据的完成位() {
        let dir = temp_dir("resume_corrupt");
        let content: Vec<u8> = (0..MIN_CHUNK_SIZE * 2).map(|i| (i % 197) as u8).collect();
        let manifest = manifest_for(&content, "corrupt.bin");

        {
            let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
            download
                .write_chunk(0, slice(&content, &manifest, 0))
                .unwrap();
            download.checkpoint().unwrap();
        }

        // bitmap 仍然声称第 0 片完成，但磁盘上的真实数据已被篡改。
        let temp = PartialDownload::temp_path_for(&dir, &manifest);
        let mut corrupted = slice(&content, &manifest, 0).to_vec();
        corrupted[0] ^= 0xff;
        let mut file = OpenOptions::new().write(true).open(&temp).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&corrupted).unwrap();
        file.sync_all().unwrap();

        let recovered = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert!(!recovered.bitmap().is_set(0), "损坏分片不能继续被跳过");
        assert_eq!(recovered.missing(), vec![0, 1]);
        assert_eq!(
            ChunkBitmap::from_bytes(
                manifest.chunk_count(),
                &fs::read(PartialDownload::state_path_for(&dir, &manifest)).unwrap()
            )
            .unwrap()
            .count_set(),
            0,
            "修正后的 bitmap 必须持久化"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bitmap损坏时安全恢复为空并修复状态文件() {
        let dir = temp_dir("bitmap_corrupt");
        let content = vec![8u8; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "bitmap.bin");

        {
            let _download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        }
        // 两片只需要一个字节；填充位为 1，故这是不可接受的 bitmap。
        fs::write(
            PartialDownload::state_path_for(&dir, &manifest),
            [0b1111_1111u8],
        )
        .unwrap();

        let recovered = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert!(recovered.bitmap().present().is_empty());
        assert_eq!(
            fs::read(PartialDownload::state_path_for(&dir, &manifest)).unwrap(),
            [0u8]
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 临时文件长度变化时不保留旧完成位() {
        let dir = temp_dir("resume_length");
        let content = vec![9u8; MIN_CHUNK_SIZE as usize * 2];
        let manifest = manifest_for(&content, "length.bin");

        {
            let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
            download
                .write_chunk(0, slice(&content, &manifest, 0))
                .unwrap();
            download.checkpoint().unwrap();
            assert_eq!(persisted_bitmap(&dir, &manifest).present(), vec![0]);
        }
        let temp = PartialDownload::temp_path_for(&dir, &manifest);
        OpenOptions::new()
            .write(true)
            .open(&temp)
            .unwrap()
            .set_len(manifest.total_len - 1)
            .unwrap();

        let recovered = PartialDownload::create(&dir, manifest.clone()).unwrap();
        assert!(recovered.bitmap().present().is_empty());
        assert_eq!(fs::metadata(temp).unwrap().len(), manifest.total_len);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 连续更新bitmap可覆盖已有状态() {
        let dir = temp_dir("bitmap_replace");
        let content: Vec<u8> = (0..MIN_CHUNK_SIZE * 3).map(|i| (i % 223) as u8).collect();
        let manifest = manifest_for(&content, "replace.bin");
        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();

        for index in 0..manifest.chunk_count() {
            download
                .write_chunk(index, slice(&content, &manifest, index))
                .unwrap();
        }
        download.checkpoint().unwrap();
        let saved = ChunkBitmap::from_bytes(
            manifest.chunk_count(),
            &fs::read(PartialDownload::state_path_for(&dir, &manifest)).unwrap(),
        )
        .unwrap();
        assert!(saved.is_complete());

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
    fn finalize改名失败时保留恢复状态() {
        let dir = temp_dir("finalize_error");
        let content = vec![10u8; MIN_CHUNK_SIZE as usize];
        let manifest = manifest_for(&content, "finalize.bin");
        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        download.write_chunk(0, &content).unwrap();
        let temp = download.temp_path().to_path_buf();
        let state = PartialDownload::state_path_for(&dir, &manifest);
        // 让 rename 的目标父目录不存在；这模拟 rename/finalize 失败，且不依赖权限。
        download.target_path = dir.join("missing-parent").join("finalize.bin");

        assert!(download.finalize().is_err());
        assert!(temp.exists(), "finalize 失败不能丢失 .part");
        assert!(state.exists(), "finalize 失败不能丢失 bitmap");

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
    fn 连续候选被占用时选择下一个名字() {
        let dir = temp_dir("collide_many");
        let content = vec![4u8; 8];
        let manifest = manifest_for(&content, "same.bin");
        for name in ["same.bin", "same (1).bin", "same (2).bin"] {
            fs::write(dir.join(name), b"reserved").unwrap();
        }

        let mut download = PartialDownload::create(&dir, manifest.clone()).unwrap();
        download.write_chunk(0, &content).unwrap();
        let out = download.finalize().unwrap();

        assert_eq!(out.file_name().unwrap(), "same (3).bin");
        for name in ["same.bin", "same (1).bin", "same (2).bin"] {
            assert_eq!(fs::read(dir.join(name)).unwrap(), b"reserved");
        }
        assert_eq!(fs::read(&out).unwrap(), content);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 两个同名下载并发收尾不会互相覆盖() {
        let dir = temp_dir("collide_concurrent");
        let first_content = vec![0x11u8; MIN_CHUNK_SIZE as usize];
        let second_content = vec![0x22u8; MIN_CHUNK_SIZE as usize];
        let first_manifest = manifest_for(&first_content, "same.bin");
        let second_manifest = manifest_for(&second_content, "same.bin");

        let mut first = PartialDownload::create(&dir, first_manifest).unwrap();
        first.write_chunk(0, &first_content).unwrap();
        let mut second = PartialDownload::create(&dir, second_manifest).unwrap();
        second.write_chunk(0, &second_content).unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let second_barrier = Arc::clone(&barrier);
        let first_task = std::thread::spawn(move || {
            first_barrier.wait();
            first.finalize().unwrap()
        });
        let second_task = std::thread::spawn(move || {
            second_barrier.wait();
            second.finalize().unwrap()
        });
        let first_output = first_task.join().unwrap();
        let second_output = second_task.join().unwrap();

        assert_ne!(first_output, second_output, "并发 publish 必须拿到不同名字");
        let outputs = [
            fs::read(&first_output).unwrap(),
            fs::read(&second_output).unwrap(),
        ];
        assert!(outputs.contains(&first_content));
        assert!(outputs.contains(&second_content));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn candidate在提交瞬间被抢占时不会覆盖抢占者() {
        let dir = temp_dir("collide_race");
        let temp = dir.join("incoming.part");
        let target = dir.join("same.bin");
        fs::write(&temp, b"downloaded").unwrap();
        let mut first_attempt = true;

        let output = publish_no_replace_with(&temp, &target, 2, |candidate| {
            if first_attempt {
                first_attempt = false;
                fs::write(candidate, b"racer").unwrap();
            }
        })
        .unwrap();

        assert_eq!(output.file_name().unwrap(), "same (1).bin");
        assert_eq!(fs::read(&target).unwrap(), b"racer");
        assert_eq!(fs::read(&output).unwrap(), b"downloaded");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn 名称耗尽返回明确错误且不覆盖已有内容() {
        let dir = temp_dir("collide_exhausted");
        let temp = dir.join("incoming.part");
        let target = dir.join("same.bin");
        fs::write(&temp, b"downloaded").unwrap();
        for candidate in candidate_paths(&target, 2) {
            fs::write(candidate, b"reserved").unwrap();
        }

        let error = publish_no_replace_with(&temp, &target, 2, |_| {})
            .expect_err("所有候选占用时必须明确失败");
        assert!(
            error.to_string().contains("耗尽"),
            "错误应说明候选耗尽，实际: {error}"
        );
        assert_eq!(fs::read(&temp).unwrap(), b"downloaded");
        for candidate in candidate_paths(&target, 2) {
            assert_eq!(fs::read(candidate).unwrap(), b"reserved");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn 已存在_symlink按占名处理且不跟随覆盖() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("collide_symlink");
        let real = dir.join("protected.txt");
        let target = dir.join("same.bin");
        fs::write(&real, b"protected").unwrap();
        symlink(&real, &target).unwrap();

        let temp = dir.join("incoming.part");
        fs::write(&temp, b"downloaded").unwrap();
        let output = publish_no_replace(&temp, &target).unwrap();

        assert_eq!(output.file_name().unwrap(), "same (1).bin");
        assert_eq!(fs::read(&real).unwrap(), b"protected");
        assert_eq!(fs::read(&target).unwrap(), b"protected");
        assert_eq!(fs::read(&output).unwrap(), b"downloaded");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn 已存在_reparse_point按占名处理() {
        use std::os::windows::fs::symlink_file;

        let dir = temp_dir("collide_reparse");
        let real = dir.join("protected.txt");
        let target = dir.join("same.bin");
        fs::write(&real, b"protected").unwrap();
        // GitHub Windows runners normally permit this. If a local runner lacks
        // SeCreateSymbolicLinkPrivilege, a directory still verifies the crucial
        // no-replace boundary: hard_link must treat the occupied name as used.
        let is_symlink = symlink_file(&real, &target).is_ok();
        if !is_symlink {
            fs::create_dir(&target).unwrap();
        }

        let temp = dir.join("incoming.part");
        fs::write(&temp, b"downloaded").unwrap();
        let output = publish_no_replace(&temp, &target).unwrap();

        assert_eq!(output.file_name().unwrap(), "same (1).bin");
        assert_eq!(fs::read(&real).unwrap(), b"protected");
        assert_eq!(fs::read(&output).unwrap(), b"downloaded");
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
