//! Blocking file operations for the desktop adapter. Invoke on a blocking worker.
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use super::{
    protocol,
    task_model::{PeerId, TaskDirection, TaskId, TaskRecord, TaskState, system_time_unix_ms},
    task_store::TaskStore,
};
use crate::{
    error::{Error, Result},
    identity::NodeId,
    protocol::manifest::{DEFAULT_CHUNK_SIZE, FileManifest},
    storage::PartialDownload,
    transfer::chunker::{manifest_from_reader, read_chunk},
};

pub const MAX_DESKTOP_CHUNK: u32 = 1024 * 1024;

pub fn failure(message: &str) -> Error {
    Error::Protocol(message.into())
}
pub fn local_error(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

pub fn validate_single_file(manifest: &FileManifest, relative: &str) -> Result<()> {
    protocol::validate_relative_path(relative)?;
    manifest.validate()?;
    if relative.contains('/')
        || relative != manifest.file_name
        || manifest.chunk_size > MAX_DESKTOP_CHUNK
        || manifest.chunks.len() > protocol::MAX_CHUNKS
    {
        return Err(failure("单文件任务清单或名称不受支持"));
    }
    Ok(())
}

pub fn regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    if !metadata.is_file() || metadata.file_type().is_symlink() || reparse {
        return Err(failure("源或目标必须是普通文件"));
    }
    Ok(())
}

fn bounded_manifest(path: &Path, chunk_size: u32, max_len: u64) -> Result<FileManifest> {
    use std::io::Read;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| failure("文件名必须为 UTF-8"))?;
    let file = File::open(path)?;
    if file.metadata()?.len() > max_len {
        return Err(failure("源文件内容已变化或超过资源上限"));
    }
    let mut reader = std::io::BufReader::new(file.take(max_len.saturating_add(1)));
    let manifest = manifest_from_reader(name, chunk_size, &mut reader)?;
    if manifest.total_len > max_len {
        return Err(failure("源文件内容已变化或超过资源上限"));
    }
    Ok(manifest)
}

pub fn select_file(store: &mut TaskStore, peer: NodeId, source: PathBuf) -> Result<TaskRecord> {
    if !source.is_absolute() || source.to_str().is_none() {
        return Err(failure("源路径必须为绝对 UTF-8 路径"));
    }
    regular_file(&source)?;
    let metadata = fs::metadata(&source)?;
    if metadata.len().div_ceil(DEFAULT_CHUNK_SIZE as u64) > protocol::MAX_CHUNKS as u64 {
        return Err(failure("文件超过桌面清单资源上限"));
    }
    let manifest = bounded_manifest(&source, DEFAULT_CHUNK_SIZE, metadata.len())?;
    validate_single_file(&manifest, &manifest.file_name)?;
    let record = TaskRecord::new_file(
        TaskId::generate(),
        PeerId::from_node_id(peer),
        TaskDirection::Send,
        source,
        manifest.file_name.clone(),
        manifest,
    )
    .map_err(local_error)?;
    store.create(record.clone()).map_err(local_error)?;
    transition(store, record.task_id(), TaskState::Queued)?;
    store.task(record.task_id()).map_err(local_error)
}

pub fn bound_task(store: &TaskStore, peer: NodeId, id: &TaskId) -> Result<TaskRecord> {
    let record = store.task(id).map_err(local_error)?;
    if record.peer_id() != &PeerId::from_node_id(peer) || record.file_details().is_none() {
        return Err(failure("任务未授权给该对端"));
    }
    Ok(record)
}

pub fn transition(store: &mut TaskStore, id: &TaskId, state: TaskState) -> Result<()> {
    store
        .transition(id, state, None, system_time_unix_ms().map_err(local_error)?)
        .map_err(local_error)
}

pub fn begin_attempt(store: &mut TaskStore, id: &TaskId) -> Result<TaskRecord> {
    let record = store.task(id).map_err(local_error)?;
    if record.state() == TaskState::Completed {
        return Ok(record);
    }
    if matches!(
        record.state(),
        TaskState::Paused | TaskState::Interrupted | TaskState::Failed
    ) {
        transition(store, id, TaskState::Queued)?;
    }
    transition(store, id, TaskState::Connecting)?;
    transition(store, id, TaskState::Negotiating)?;
    store.task(id).map_err(local_error)
}

pub fn accept_offer(
    store: &mut TaskStore,
    peer: NodeId,
    id: &TaskId,
    root: &Path,
    relative: String,
    manifest: FileManifest,
) -> Result<TaskRecord> {
    validate_single_file(&manifest, &relative)?;
    if store.list().iter().any(|task| task.task_id() == id) {
        let existing = bound_task(store, peer, id)?;
        let details = existing.file_details().unwrap();
        if existing.direction() != TaskDirection::Receive
            || details.relative_path != relative
            || details.manifest != manifest
        {
            return Err(failure("已有任务与 Offer 身份不符"));
        }
        return begin_attempt(store, id);
    }
    let record = TaskRecord::new_file(
        id.clone(),
        PeerId::from_node_id(peer),
        TaskDirection::Receive,
        root.to_path_buf(),
        relative,
        manifest,
    )
    .map_err(local_error)?;
    store.create(record).map_err(local_error)?;
    transition(store, id, TaskState::Queued)?;
    begin_attempt(store, id)
}

#[derive(Debug)]
pub struct VerifiedSource {
    file: File,
    path: PathBuf,
}

pub fn verify_source(record: &TaskRecord) -> Result<VerifiedSource> {
    if record.direction() != TaskDirection::Send {
        return Err(failure("任务不是本机发送任务"));
    }
    regular_file(record.local_path()).map_err(|_| failure("源文件不可用"))?;
    let manifest = &record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?
        .manifest;
    let current = bounded_manifest(record.local_path(), manifest.chunk_size, manifest.total_len)
        .map_err(|error| {
            if matches!(error, Error::Io(_)) {
                failure("源文件不可用")
            } else {
                failure("源文件内容已变化")
            }
        })?;
    if &current != manifest {
        return Err(failure("源文件内容已变化"));
    }
    Ok(VerifiedSource {
        file: File::open(record.local_path())?,
        path: record.local_path().to_path_buf(),
    })
}

pub fn source_chunk(
    source: &mut VerifiedSource,
    manifest: &FileManifest,
    index: u32,
) -> Result<Vec<u8>> {
    regular_file(&source.path).map_err(|_| failure("源文件不可用"))?;
    let current = File::open(&source.path).map_err(|_| failure("源文件不可用"))?;
    if !same_handles(&source.file, &current)? {
        return Err(failure("源文件内容已变化"));
    }
    let file = &mut source.file;
    if file.metadata()?.len() != manifest.total_len {
        return Err(failure("源文件内容已变化"));
    }
    let (offset, len) = manifest
        .chunk_range(index)
        .ok_or_else(|| failure("分片索引非法"))?;
    let bytes = read_chunk(file, offset, len).map_err(|_| failure("源文件不可用或内容已变化"))?;
    if !manifest.verify_chunk(index, &bytes) {
        return Err(failure("源文件内容已变化"));
    }
    Ok(bytes)
}

pub fn stage_dir(record: &TaskRecord) -> Result<PathBuf> {
    let mut path = record.local_path().to_path_buf();
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(failure("接收根目录不可用"));
    }
    for component in [
        ".p2p-desktop",
        record.peer_id().as_str(),
        record.task_id().as_str(),
    ] {
        path.push(component);
        super::config::ensure_private_app_dir(&path)?;
    }
    Ok(path)
}

pub fn open_download(record: &TaskRecord) -> Result<PartialDownload> {
    let details = record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?;
    PartialDownload::create(&stage_dir(record)?, details.manifest.clone())
}

/// No collision replacement in T006. T007 adds its separate backup transaction.
/// Retain the staged inode until receipt commit, so recovery can prove ownership.
pub fn publish(
    store: &mut TaskStore,
    record: &TaskRecord,
    download: &mut PartialDownload,
) -> Result<PathBuf> {
    let id = record.task_id();
    let details = record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?;
    let staged = download.prepare_desktop_publication()?;
    store.prepare_publication(id).map_err(local_error)?;
    let target = record.local_path().join(&details.relative_path);
    match fs::hard_link(&staged, &target) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            regular_file(&target)?;
            if !same_file(&staged, &target)? {
                return Err(failure("接收目标已存在，等待重名发布处理"));
            }
        }
        Err(error) => return Err(error.into()),
    }
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target)?
        .sync_all()?;
    sync_dir(record.local_path())?;
    // A staged inode can be modified by an external process after linking.
    if bounded_manifest(
        &target,
        details.manifest.chunk_size,
        details.manifest.total_len,
    )? != details.manifest
    {
        return Err(failure("发布内容校验失败"));
    }
    store
        .commit_receipt(id, system_time_unix_ms().map_err(local_error)?)
        .map_err(local_error)?;
    if cleanup_staging(record).is_err() {
        tracing::warn!("完成回执已持久化；临时文件清理将在恢复时重试");
    }
    Ok(target)
}

pub fn cleanup_staging(record: &TaskRecord) -> Result<()> {
    let directory = stage_dir(record)?;
    let manifest = &record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?
        .manifest;
    for path in [
        PartialDownload::temp_path_for(&directory, manifest),
        PartialDownload::state_path_for(&directory, manifest),
    ] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    sync_dir(&directory)
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> Result<bool> {
    same_handles(&File::open(a)?, &File::open(b)?)
}
#[cfg(unix)]
fn same_handles(a: &File, b: &File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (a, b) = (a.metadata()?, b.metadata()?);
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}
#[cfg(windows)]
fn same_handles(a: &File, b: &File) -> Result<bool> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    #[derive(Default)]
    struct FileInformation {
        attributes: u32,
        creation: [u32; 2],
        access: [u32; 2],
        write: [u32; 2],
        volume: u32,
        size: [u32; 2],
        links: u32,
        index: [u32; 2],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            handle: *mut std::ffi::c_void,
            info: *mut FileInformation,
        ) -> i32;
    }
    let identity = |file: &File| -> Result<(u32, [u32; 2])> {
        let mut info = FileInformation::default();
        // File holds a valid handle and info has the documented C structure layout.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok((info.volume, info.index))
    };
    Ok(identity(a)? == identity(b)?)
}
#[cfg(not(any(unix, windows)))]
fn same_handles(_a: &File, _b: &File) -> Result<bool> {
    Err(failure("此平台不支持文件身份校验"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::protocol::manifest::MIN_CHUNK_SIZE;
    use crate::transfer::chunker::manifest_from_path;
    fn fixture() -> (PathBuf, TaskStore, TaskRecord, Vec<u8>) {
        let root = std::env::temp_dir().join(format!(
            "p2p-desktop-transfer-files-{}",
            rand::random::<u128>()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("receive")).unwrap();
        let (mut store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        let bytes = vec![17; MIN_CHUNK_SIZE as usize * 2 + 7];
        fs::write(root.join("selected.bin"), &bytes).unwrap();
        let manifest = manifest_from_path(&root.join("selected.bin"), MIN_CHUNK_SIZE).unwrap();
        let peer = Identity::generate().node_id();
        let record = accept_offer(
            &mut store,
            peer,
            &TaskId::generate(),
            &root.join("receive"),
            "selected.bin".into(),
            manifest,
        )
        .unwrap();
        transition(&mut store, record.task_id(), TaskState::Transferring).unwrap();
        (root, store, record, bytes)
    }
    fn fill(download: &mut PartialDownload, bytes: &[u8]) {
        for index in download.missing() {
            let (offset, len) = download.manifest().chunk_range(index).unwrap();
            download
                .write_chunk(
                    index,
                    &bytes[offset as usize..offset as usize + len as usize],
                )
                .unwrap();
        }
    }
    #[test]
    fn published_inode_before_receipt_is_recovered_without_second_publication() {
        let (root, mut store, record, bytes) = fixture();
        let mut download = open_download(&record).unwrap();
        fill(&mut download, &bytes);
        transition(&mut store, record.task_id(), TaskState::Finalizing).unwrap();
        let staged = download.prepare_desktop_publication().unwrap();
        store.prepare_publication(record.task_id()).unwrap();
        let target = record.local_path().join("selected.bin");
        fs::hard_link(&staged, &target).unwrap();
        sync_dir(record.local_path()).unwrap();
        drop(download);
        drop(store);
        let (mut store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        assert_eq!(
            store.task(record.task_id()).unwrap().state(),
            TaskState::Interrupted
        );
        let record = begin_attempt(&mut store, record.task_id()).unwrap();
        transition(&mut store, record.task_id(), TaskState::Transferring).unwrap();
        transition(&mut store, record.task_id(), TaskState::Finalizing).unwrap();
        let mut download = open_download(&record).unwrap();
        assert!(download.is_complete());
        assert_eq!(publish(&mut store, &record, &mut download).unwrap(), target);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert!(
            store
                .task(record.task_id())
                .unwrap()
                .file_details()
                .unwrap()
                .receipt_committed
        );
        drop(store);
        let (store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        assert_eq!(
            store.task(record.task_id()).unwrap().state(),
            TaskState::Completed
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn finalize_conflict_does_not_claim_receipt_even_for_identical_content() {
        let (root, mut store, record, bytes) = fixture();
        let target = record.local_path().join("selected.bin");
        fs::write(&target, &bytes).unwrap();
        let mut download = open_download(&record).unwrap();
        fill(&mut download, &bytes);
        transition(&mut store, record.task_id(), TaskState::Finalizing).unwrap();
        assert!(publish(&mut store, &record, &mut download).is_err());
        assert!(
            !store
                .task(record.task_id())
                .unwrap()
                .file_details()
                .unwrap()
                .receipt_committed
        );
        assert_eq!(fs::read(target).unwrap(), bytes);
        assert!(download.temp_path().exists());
        drop(download);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pause_checkpoint_survives_restart_and_rechecks_corruption() {
        let (root, mut store, record, bytes) = fixture();
        let mut download = open_download(&record).unwrap();
        download
            .write_chunk(0, &bytes[..MIN_CHUNK_SIZE as usize])
            .unwrap();
        download.checkpoint().unwrap();
        transition(&mut store, record.task_id(), TaskState::Pausing).unwrap();
        transition(&mut store, record.task_id(), TaskState::Paused).unwrap();
        let part = download.temp_path().to_path_buf();
        drop(download);
        drop(store);
        let (store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        let record = store.task(record.task_id()).unwrap();
        assert_eq!(record.state(), TaskState::Paused);
        let download = open_download(&record).unwrap();
        assert_eq!(download.bitmap().count_set(), 1);
        drop(download);
        use std::io::Write;
        let mut file = fs::OpenOptions::new().write(true).open(part).unwrap();
        file.write_all(&[99]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let download = open_download(&record).unwrap();
        assert_eq!(download.bitmap().count_set(), 0);
        drop(download);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn changed_missing_source_and_wrong_peer_are_rejected() {
        let (root, mut store, _, _) = fixture();
        let peer = Identity::generate().node_id();
        let source = root.join("selected.bin");
        let record = select_file(&mut store, peer, source.clone()).unwrap();
        assert!(bound_task(&store, Identity::generate().node_id(), record.task_id()).is_err());
        let mut opened = verify_source(&record).unwrap();
        fs::rename(&source, root.join("previous.bin")).unwrap();
        fs::write(&source, b"replacement").unwrap();
        assert!(
            source_chunk(&mut opened, &record.file_details().unwrap().manifest, 0)
                .unwrap_err()
                .to_string()
                .contains("变化")
        );
        drop(opened);
        fs::write(&source, b"new").unwrap();
        assert!(
            verify_source(&record)
                .unwrap_err()
                .to_string()
                .contains("变化")
        );
        fs::remove_file(source).unwrap();
        assert!(
            verify_source(&record)
                .unwrap_err()
                .to_string()
                .contains("不可用")
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
