//! Bounded, cancellable selection scan. No network or persistent mutation here.
use super::{
    secure_fs as fs,
    task_model::{PeerId, TaskDirection, TaskId, TaskRecord},
};
use crate::{
    error::Result,
    identity::NodeId,
    protocol::manifest::{DEFAULT_CHUNK_SIZE, FileManifest},
    transfer::chunker::manifest_from_reader,
};
use cap_std::fs::Dir;
use std::{
    collections::HashSet,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub const MAX_SELECTION_ENTRIES: usize = 4096;
pub const MAX_SELECTION_CHUNKS: usize = 131_072;
#[derive(Clone, Default)]
pub(crate) struct ScanCancellation(Arc<AtomicBool>);
impl ScanCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Acquire) {
            Err(fs::fail("目录扫描已取消"))
        } else {
            Ok(())
        }
    }
}
struct CancellableReader<R> {
    inner: R,
    cancel: ScanCancellation,
}
impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cancel
            .check()
            .map_err(|_| io::Error::other("selection scan cancelled"))?;
        self.inner.read(bytes)
    }
}

pub fn scan_file(dir: &Dir, name: &str, cancel: &ScanCancellation) -> Result<FileManifest> {
    cancel.check()?;
    let file = fs::open(dir, name, false, false)?;
    let length = file.metadata()?.len();
    if length.div_ceil(u64::from(DEFAULT_CHUNK_SIZE)) > super::protocol::MAX_CHUNKS as u64 {
        return Err(fs::fail("文件超过桌面清单资源上限"));
    }
    let before = fs::identity(&file)?;
    let mut reader = CancellableReader {
        inner: std::io::BufReader::new(file.take(length.saturating_add(1))),
        cancel: cancel.clone(),
    };
    let manifest = manifest_from_reader(name, DEFAULT_CHUNK_SIZE, &mut reader)?;
    let current = fs::open(dir, name, false, false)?;
    if manifest.total_len != length
        || current.metadata()?.len() != length
        || fs::identity(&current)? != before
    {
        return Err(fs::fail("源文件内容已变化"));
    }
    Ok(manifest)
}

struct Scan<'a> {
    source: &'a Path,
    peer: PeerId,
    group: TaskId,
    records: Vec<TaskRecord>,
    chunks: usize,
    cancel: &'a ScanCancellation,
}
impl Scan<'_> {
    fn visit(&mut self, dir: &Dir, relative: String, path: PathBuf) -> Result<()> {
        self.cancel.check()?;
        super::protocol::validate_relative_path(&relative)?;
        if self.records.len() >= MAX_SELECTION_ENTRIES {
            return Err(fs::fail("目录清单条目超过上限"));
        }
        self.records.push(
            TaskRecord::new_directory(
                TaskId::generate(),
                self.peer.clone(),
                TaskDirection::Send,
                path.clone(),
                relative.clone(),
                Some(self.group.clone()),
            )
            .map_err(super::transfer_files::local_error)?,
        );
        let mut names = Vec::new();
        let mut keys = HashSet::new();
        for entry in dir.entries()? {
            self.cancel.check()?;
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| fs::fail("源目录包含非 UTF-8 名称"))?;
            if names.len() + self.records.len() >= MAX_SELECTION_ENTRIES {
                return Err(fs::fail("目录清单条目超过上限"));
            }
            let rel = format!("{relative}/{name}");
            super::protocol::validate_relative_path(&rel)?;
            if !keys.insert(fs::name_key(&name)) {
                return Err(fs::fail("源目录存在大小写或 Unicode 规范化冲突"));
            }
            names.push(name);
        }
        names.sort();
        for name in names {
            self.cancel.check()?;
            let metadata = dir.symlink_metadata(&name)?;
            #[cfg(windows)]
            let reparse = {
                use cap_std::fs::MetadataExt;
                metadata.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let reparse = false;
            if metadata.file_type().is_symlink() || reparse {
                return Err(fs::fail("源目录不支持链接或 reparse point"));
            }
            let rel = format!("{relative}/{name}");
            if metadata.is_dir() {
                let child = fs::child(dir, &name, false)?;
                self.visit(&child, rel, path.join(name))?;
            } else if metadata.is_file() {
                if self.records.len() >= MAX_SELECTION_ENTRIES {
                    return Err(fs::fail("目录清单条目超过上限"));
                }
                let manifest = scan_file(dir, &name, self.cancel)?;
                self.chunks = self
                    .chunks
                    .checked_add(manifest.chunks.len())
                    .ok_or_else(|| fs::fail("目录清单资源超限"))?;
                if self.chunks > MAX_SELECTION_CHUNKS {
                    return Err(fs::fail("目录清单资源超限"));
                }
                let mut record = TaskRecord::new_file(
                    TaskId::generate(),
                    self.peer.clone(),
                    TaskDirection::Send,
                    path.join(&name),
                    rel,
                    manifest,
                )
                .map_err(super::transfer_files::local_error)?;
                record
                    .set_selection_binding(
                        Some(self.group.clone()),
                        Some(self.source.to_path_buf()),
                    )
                    .map_err(super::transfer_files::local_error)?;
                self.records.push(record);
            } else {
                return Err(fs::fail("源目录包含非普通文件"));
            }
        }
        Ok(())
    }
}

pub fn scan_directory(
    peer: NodeId,
    source: &Path,
    cancel: &ScanCancellation,
) -> Result<Vec<TaskRecord>> {
    if !source.is_absolute() || source.to_str().is_none() {
        return Err(fs::fail("源目录必须为绝对 UTF-8 路径"));
    }
    let top = source
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| fs::fail("源目录名称不可用"))?;
    let root = fs::root(source)?;
    let mut scan = Scan {
        source,
        peer: PeerId::from_node_id(peer),
        group: TaskId::generate(),
        records: Vec::new(),
        chunks: 0,
        cancel,
    };
    scan.visit(&root, top.to_owned(), source.to_path_buf())?;
    cancel.check()?;
    Ok(scan.records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::fs as ambient;
    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!("p2p-selection-{}", rand::random::<u128>()));
        ambient::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn nested_chinese_empty_entries_keep_top_directory_and_one_durable_group() {
        let path = fixture();
        let selected = path.join("目录");
        ambient::create_dir_all(selected.join("nested/空目录")).unwrap();
        ambient::write(selected.join("nested/空文件.txt"), []).unwrap();
        ambient::write(selected.join("中文.txt"), b"content").unwrap();
        let records = scan_directory(
            Identity::generate().node_id(),
            &selected,
            &ScanCancellation::default(),
        )
        .unwrap();
        assert_eq!(records.len(), 5);
        let names = records
            .iter()
            .map(|r| r.relative_path().unwrap())
            .collect::<Vec<_>>();
        assert!(names.contains(&"目录"));
        assert!(names.contains(&"目录/nested/空目录"));
        assert!(names.contains(&"目录/nested/空文件.txt"));
        assert!(names.contains(&"目录/中文.txt"));
        assert!(
            records
                .iter()
                .all(|r| r.group_id() == records[0].group_id())
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r.directory_details().is_some())
                .count(),
            3
        );
        ambient::remove_dir_all(path).unwrap();
    }
    #[test]
    fn cancelled_scan_and_entry_limit_reject_before_any_task_mutation() {
        let path = fixture();
        let cancel = ScanCancellation::default();
        cancel.cancel();
        assert!(
            scan_directory(Identity::generate().node_id(), &path, &cancel)
                .unwrap_err()
                .to_string()
                .contains("取消")
        );
        for index in 0..MAX_SELECTION_ENTRIES {
            ambient::write(path.join(format!("file{index}")), []).unwrap();
        }
        assert!(
            scan_directory(
                Identity::generate().node_id(),
                &path,
                &ScanCancellation::default()
            )
            .unwrap_err()
            .to_string()
            .contains("上限")
        );
        ambient::remove_dir_all(path).unwrap();
    }
    #[test]
    fn cancelling_reader_during_hash_returns_error_without_retry_loop() {
        let cancel = ScanCancellation::default();
        let mut reader = CancellableReader {
            inner: io::Cursor::new(vec![1; 1024]),
            cancel: cancel.clone(),
        };
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes).unwrap();
        cancel.cancel();
        assert!(reader.read_exact(&mut bytes).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn source_symlink_and_normalization_or_case_collision_are_rejected() {
        use std::os::unix::fs::symlink;
        let path = fixture();
        let outside = fixture();
        ambient::write(outside.join("secret"), b"unselected").unwrap();
        symlink(&outside, path.join("link")).unwrap();
        assert!(
            scan_directory(
                Identity::generate().node_id(),
                &path,
                &ScanCancellation::default()
            )
            .unwrap_err()
            .to_string()
            .contains("链接")
        );
        ambient::remove_file(path.join("link")).unwrap();
        for pair in [
            ["name", "NAME"],
            ["é.txt", "e\u{301}.txt"],
            ["σ.txt", "ς.txt"],
            ["I.txt", "ı.txt"],
        ] {
            for name in pair {
                ambient::write(path.join(name), []).unwrap();
            }
            assert!(
                scan_directory(
                    Identity::generate().node_id(),
                    &path,
                    &ScanCancellation::default()
                )
                .unwrap_err()
                .to_string()
                .contains("冲突")
            );
            for name in pair {
                ambient::remove_file(path.join(name)).unwrap();
            }
        }
        ambient::remove_dir_all(path).unwrap();
        ambient::remove_dir_all(outside).unwrap();
    }
    #[test]
    fn portable_invalid_paths_and_internal_namespace_are_rejected() {
        for path in [
            "../escape",
            "/absolute",
            "a/../b",
            "a/./b",
            "a//b",
            "C:/drive",
            "\\\\server\\share",
            "a\\b",
            "a:ads",
            "CON.txt",
            "COM1",
            "LPT².txt",
            "a.",
            "a ",
            "a/\0bad",
            ".p2p-desktop",
            "a/.P2P-DESKTOP/b",
        ] {
            assert!(
                super::super::protocol::validate_relative_path(path).is_err(),
                "accepted {path:?}"
            );
        }
    }
    #[test]
    fn collision_keys_detect_case_and_unicode_normalization_on_all_platforms() {
        assert_eq!(fs::name_key("name"), fs::name_key("NAME"));
        assert_eq!(fs::name_key("é.txt"), fs::name_key("e\u{301}.txt"));
        assert_eq!(fs::name_key("σ.txt"), fs::name_key("ς.txt"));
        assert_eq!(fs::name_key("I.txt"), fs::name_key("ı.txt"));
        assert_eq!(fs::name_key("straße.txt"), fs::name_key("STRASSE.txt"));
    }
    #[cfg(windows)]
    #[test]
    fn windows_source_junction_and_receive_reparse_directory_are_rejected() {
        let path = fixture();
        let outside = fixture();
        ambient::write(outside.join("unselected.txt"), b"untouched").unwrap();
        let link = path.join("junction");
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "junction fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            scan_directory(
                Identity::generate().node_id(),
                &path,
                &ScanCancellation::default()
            )
            .is_err()
        );
        let directory = fs::root(&path).unwrap();
        assert!(fs::parent(&directory, "junction/new.txt", true).is_err());
        assert_eq!(
            ambient::read(outside.join("unselected.txt")).unwrap(),
            b"untouched"
        );
        assert!(!outside.join("new.txt").exists());
        drop(directory);
        ambient::remove_dir(link).unwrap();
        ambient::remove_dir_all(path).unwrap();
        ambient::remove_dir_all(outside).unwrap();
    }
}
