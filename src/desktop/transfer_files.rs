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
    if relative.rsplit('/').next() != Some(manifest.file_name.as_str())
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
    if record.peer_id() != &PeerId::from_node_id(peer)
        || (record.file_details().is_none() && record.directory_details().is_none())
    {
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

#[cfg(test)]
pub fn accept_offer(
    store: &mut TaskStore,
    peer: NodeId,
    id: &TaskId,
    root: &Path,
    relative: String,
    manifest: FileManifest,
) -> Result<TaskRecord> {
    accept_entry(store, peer, id, root, relative, manifest, None)
}

fn receive_selection_root(
    store: &TaskStore,
    peer: NodeId,
    group: Option<&TaskId>,
    root: &Path,
) -> PathBuf {
    if let Some(group) = group
        && let Some(existing) = store.list().iter().find(|t| {
            t.direction() == TaskDirection::Receive
                && t.peer_id() == &PeerId::from_node_id(peer)
                && t.group_id() == Some(group)
        })
    {
        return existing.local_path().to_path_buf();
    }
    root.to_path_buf()
}

pub fn accept_entry(
    store: &mut TaskStore,
    peer: NodeId,
    id: &TaskId,
    root: &Path,
    relative: String,
    manifest: FileManifest,
    group: Option<TaskId>,
) -> Result<TaskRecord> {
    validate_single_file(&manifest, &relative)?;
    if store.list().iter().any(|task| task.task_id() == id) {
        let existing = bound_task(store, peer, id)?;
        let details = existing
            .file_details()
            .ok_or_else(|| failure("已有目录任务不能变成文件"))?;
        if existing.direction() != TaskDirection::Receive
            || details.relative_path != relative
            || details.manifest != manifest
            || existing.group_id() != group.as_ref()
        {
            return Err(failure("已有任务与 Offer 身份不符"));
        }
        return begin_attempt(store, id);
    }
    let mut record = TaskRecord::new_file(
        id.clone(),
        PeerId::from_node_id(peer),
        TaskDirection::Receive,
        receive_selection_root(store, peer, group.as_ref(), root),
        relative,
        manifest,
    )
    .map_err(local_error)?;
    record
        .set_selection_binding(group, None)
        .map_err(local_error)?;
    store.create(record).map_err(local_error)?;
    transition(store, id, TaskState::Queued)?;
    begin_attempt(store, id)
}

pub fn accept_directory(
    store: &mut TaskStore,
    peer: NodeId,
    id: &TaskId,
    root: &Path,
    relative: String,
    group: Option<TaskId>,
) -> Result<TaskRecord> {
    protocol::validate_relative_path(&relative)?;
    if store.list().iter().any(|t| t.task_id() == id) {
        let existing = bound_task(store, peer, id)?;
        if existing.direction() != TaskDirection::Receive
            || existing
                .directory_details()
                .map(|d| d.relative_path.as_str())
                != Some(relative.as_str())
            || existing.group_id() != group.as_ref()
        {
            return Err(failure("已有目录任务与 Offer 不符"));
        }
        return begin_attempt(store, id);
    }
    let record = TaskRecord::new_directory(
        id.clone(),
        PeerId::from_node_id(peer),
        TaskDirection::Receive,
        receive_selection_root(store, peer, group.as_ref(), root),
        relative,
        group,
    )
    .map_err(local_error)?;
    store.create(record).map_err(local_error)?;
    transition(store, id, TaskState::Queued)?;
    begin_attempt(store, id)
}

#[derive(Debug)]
pub struct VerifiedSource {
    file: File,
    parent: cap_std::fs::Dir,
    name: String,
}

pub fn source_parent(record: &TaskRecord) -> Result<(cap_std::fs::Dir, String)> {
    let details = record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?;
    if let Some(root) = &details.source_root {
        let dir = super::secure_fs::root(root)?;
        let (_, relative) = details
            .relative_path
            .split_once('/')
            .ok_or_else(|| failure("目录源绑定非法"))?;
        if root.join(relative) != record.local_path() {
            return Err(failure("目录源绑定非法"));
        }
        super::secure_fs::parent(&dir, relative, false)
    } else {
        let parent = record
            .local_path()
            .parent()
            .ok_or_else(|| failure("源路径不可用"))?;
        let name = record
            .local_path()
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| failure("源路径不可用"))?;
        Ok((
            cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?,
            name.to_owned(),
        ))
    }
}

pub fn verify_source(record: &TaskRecord) -> Result<VerifiedSource> {
    use std::io::Read;
    if record.direction() != TaskDirection::Send {
        return Err(failure("任务不是本机发送任务"));
    }
    let (parent, name) = source_parent(record).map_err(|_| failure("源文件不可用"))?;
    let file = super::secure_fs::open(&parent, &name, false, false)
        .map_err(|_| failure("源文件不可用"))?;
    let manifest = &record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?
        .manifest;
    if file.metadata()?.len() != manifest.total_len {
        return Err(failure("源文件内容已变化"));
    }
    let mut reader =
        std::io::BufReader::new(file.try_clone()?.take(manifest.total_len.saturating_add(1)));
    let current = manifest_from_reader(&manifest.file_name, manifest.chunk_size, &mut reader)
        .map_err(|_| failure("源文件不可用"))?;
    if current != *manifest {
        return Err(failure("源文件内容已变化"));
    }
    let opened = super::secure_fs::open(&parent, &name, false, false)
        .map_err(|_| failure("源文件不可用"))?;
    if !same_handles(&file, &opened)? {
        return Err(failure("源文件内容已变化"));
    }
    Ok(VerifiedSource { file, parent, name })
}

pub fn source_chunk(
    source: &mut VerifiedSource,
    manifest: &FileManifest,
    index: u32,
) -> Result<Vec<u8>> {
    let current = super::secure_fs::open(&source.parent, &source.name, false, false)
        .map_err(|_| failure("源文件不可用"))?;
    if !same_handles(&source.file, &current)? || source.file.metadata()?.len() != manifest.total_len
    {
        return Err(failure("源文件内容已变化"));
    }
    let (offset, len) = manifest
        .chunk_range(index)
        .ok_or_else(|| failure("分片索引非法"))?;
    let bytes = read_chunk(&mut source.file, offset, len)
        .map_err(|_| failure("源文件不可用或内容已变化"))?;
    if !manifest.verify_chunk(index, &bytes) {
        return Err(failure("源文件内容已变化"));
    }
    Ok(bytes)
}

#[cfg(test)]
pub fn stage_dir(record: &TaskRecord) -> Result<PathBuf> {
    let _ = stage_capability(record)?;
    Ok(record
        .local_path()
        .join(".p2p-desktop")
        .join(record.peer_id().as_str())
        .join(record.task_id().as_str()))
}
pub fn stage_capability(record: &TaskRecord) -> Result<cap_std::fs::Dir> {
    let root = super::secure_fs::root(record.local_path())?;
    let internal = super::secure_fs::child(&root, ".p2p-desktop", true)?;
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        internal.set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))?;
    }
    let peer = super::secure_fs::child(&internal, record.peer_id().as_str(), true)?;
    super::secure_fs::child(&peer, record.task_id().as_str(), true)
}
pub fn open_download(record: &TaskRecord) -> Result<PartialDownload> {
    let details = record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?;
    let dir = std::sync::Arc::new(stage_capability(record)?);
    let path = record
        .local_path()
        .join(".p2p-desktop")
        .join(record.peer_id().as_str())
        .join(record.task_id().as_str());
    PartialDownload::create_desktop(&path, dir, details.manifest.clone())
}
pub fn publish(
    store: &mut TaskStore,
    record: &TaskRecord,
    download: &mut PartialDownload,
) -> Result<PathBuf> {
    super::publish::file(store, record, download)
}
pub fn cleanup_staging(record: &TaskRecord) -> Result<()> {
    let dir = stage_capability(record)?;
    let manifest = &record
        .file_details()
        .ok_or_else(|| failure("缺少文件任务绑定"))?
        .manifest;
    for path in [
        PartialDownload::temp_path_for(Path::new(""), manifest),
        PartialDownload::state_path_for(Path::new(""), manifest),
        PathBuf::from("publish.json"),
        PathBuf::from("data.part"),
        PathBuf::from("data.bitmap"),
    ] {
        match dir.remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    super::secure_fs::sync(&dir)
}
#[cfg(test)]
fn sync_dir(path: &Path) -> Result<()> {
    super::secure_fs::sync(&super::secure_fs::root(path)?)
}

fn same_handles(a: &File, b: &File) -> Result<bool> {
    Ok(super::secure_fs::identity(a)? == super::secure_fs::identity(b)?)
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
    fn identical_existing_content_is_backed_up_not_mistaken_for_prior_receipt() {
        let (root, mut store, record, bytes) = fixture();
        let target = record.local_path().join("selected.bin");
        fs::write(&target, &bytes).unwrap();
        let mut download = open_download(&record).unwrap();
        fill(&mut download, &bytes);
        transition(&mut store, record.task_id(), TaskState::Finalizing).unwrap();
        let staged = download.temp_path().to_path_buf();
        let before = super::super::secure_fs::identity(&File::open(&target).unwrap()).unwrap();
        publish(&mut store, &record, &mut download).unwrap();
        assert!(
            store
                .task(record.task_id())
                .unwrap()
                .file_details()
                .unwrap()
                .receipt_committed
        );
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert!(!staged.exists());
        assert_ne!(
            before,
            super::super::secure_fs::identity(&File::open(&target).unwrap()).unwrap()
        );
        let backups = fs::read_dir(record.local_path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("selected+")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(&backups[0]).unwrap(), bytes);
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
    #[test]
    fn longest_portable_basename_uses_fixed_staging_names() {
        let (root, mut store, _, bytes) = fixture();
        let name = "x".repeat(255);
        let source = root.join(&name);
        fs::write(&source, &bytes).unwrap();
        let manifest = manifest_from_path(&source, MIN_CHUNK_SIZE).unwrap();
        let record = accept_offer(
            &mut store,
            Identity::generate().node_id(),
            &TaskId::generate(),
            &root.join("receive"),
            name.clone(),
            manifest,
        )
        .unwrap();
        transition(&mut store, record.task_id(), TaskState::Transferring).unwrap();
        let mut download = open_download(&record).unwrap();
        assert_eq!(download.temp_path().file_name().unwrap(), "data.part");
        fill(&mut download, &bytes);
        transition(&mut store, record.task_id(), TaskState::Finalizing).unwrap();
        publish(&mut store, &record, &mut download).unwrap();
        assert_eq!(fs::read(root.join("receive").join(name)).unwrap(), bytes);
        drop(download);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn staging_part_and_bitmap_symlinks_cannot_touch_unselected_files() {
        use std::os::unix::fs::symlink;
        for entry in ["data.part", "data.bitmap"] {
            let (root, store, record, _) = fixture();
            let outside = root.join("unselected.bin");
            fs::write(&outside, b"private untouched data").unwrap();
            let stage = stage_dir(&record).unwrap();
            symlink(&outside, stage.join(entry)).unwrap();
            assert!(open_download(&record).is_err());
            assert_eq!(fs::read(outside).unwrap(), b"private untouched data");
            drop(store);
            fs::remove_dir_all(root).unwrap();
        }
    }
}
