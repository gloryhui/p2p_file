//! Recoverable GUI collision publication. The caller serializes target mutations
//! through the sole TaskStore writer; every filesystem operation is handle-relative.
use super::{
    secure_fs::{self as fs, FileIdentity},
    task_model::{TaskRecord, system_time_unix_ms},
    task_store::TaskStore,
    transfer_files::local_error,
};
use crate::{
    error::Result, protocol::manifest::FileManifest, storage::PartialDownload,
    transfer::chunker::manifest_from_reader,
};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    path::PathBuf,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Phase {
    Prepared,
    OldBackedUp,
    NewPublished,
    ReceiptCommitted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    task: String,
    peer: String,
    relative: String,
    root_hash: String,
    parent: FileIdentity,
    staged: FileIdentity,
    old: Option<FileIdentity>,
    backup: Option<String>,
    timestamp: String,
    suffix: u32,
    phase: Phase,
}
fn named_identity(dir: &Dir, name: &str) -> Result<Option<FileIdentity>> {
    match fs::open(dir, name, false, false) {
        Ok(file) => Ok(Some(fs::identity(&file)?)),
        Err(crate::error::Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn read_journal(dir: &Dir) -> Result<Option<Journal>> {
    match fs::open(dir, "publish.json", false, false) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(65_537).read_to_end(&mut bytes)?;
            if bytes.len() > 65_536 {
                return Err(fs::fail("发布 journal 超限"));
            }
            let journal =
                serde_json::from_slice(&bytes).map_err(|_| fs::fail("发布 journal 损坏"))?;
            Ok(Some(journal))
        }
        Err(crate::error::Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn write_journal(dir: &Dir, journal: &Journal) -> Result<()> {
    fs::atomic_json(dir, "publish.json", journal)
}

/// Gregorian civil date conversion; Unix timestamp in UTC, no local timezone.
fn timestamp(ms: i64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let time = secs % 86_400;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}{:03}Z",
        time / 3600,
        (time / 60) % 60,
        time % 60,
        ms % 1000
    )
}
fn backup_name(name: &str, timestamp: &str, suffix: u32) -> Result<String> {
    let (stem, ext) = name
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map_or((name, None), |(s, e)| (s, Some(e)));
    let counter = if suffix == 0 {
        String::new()
    } else {
        format!("-{suffix}")
    };
    let result = format!(
        "{stem}+{timestamp}{counter}{}",
        ext.map_or(String::new(), |e| format!(".{e}"))
    );
    super::protocol::validate_relative_path(&result)?;
    Ok(result)
}
fn verify(dir: &Dir, name: &str, manifest: &FileManifest) -> Result<()> {
    let file = fs::open(dir, name, false, false)?;
    if file.metadata()?.len() != manifest.total_len {
        return Err(fs::fail("发布内容校验失败"));
    }
    let mut reader = std::io::BufReader::new(file.take(manifest.total_len.saturating_add(1)));
    if manifest_from_reader(&manifest.file_name, manifest.chunk_size, &mut reader)? != *manifest {
        return Err(fs::fail("发布内容校验失败"));
    }
    Ok(())
}

pub fn file(
    store: &mut TaskStore,
    record: &TaskRecord,
    download: &mut PartialDownload,
) -> Result<PathBuf> {
    file_with_boundary(store, record, download, |_| Ok(()))
}
fn file_with_boundary(
    store: &mut TaskStore,
    record: &TaskRecord,
    download: &mut PartialDownload,
    mut boundary: impl FnMut(&'static str) -> Result<()>,
) -> Result<PathBuf> {
    let details = record
        .file_details()
        .ok_or_else(|| fs::fail("缺少文件绑定"))?;
    let staged_path = download.prepare_desktop_publication()?;
    let stage = download
        .desktop_directory()
        .ok_or_else(|| fs::fail("发布缺少目录句柄"))?;
    let staged_name = staged_path.file_name().unwrap().to_str().unwrap();
    let root = fs::root(record.local_path())?;
    let (parent, name) = fs::parent(&root, &details.relative_path, true)?;
    let staged = fs::identity(&fs::open(&stage, staged_name, false, false)?)?;
    let parent_id = fs::identity(&parent.try_clone()?.into_std_file())?;
    boundary("before-prepared")?;
    let mut journal = if let Some(journal) = read_journal(&stage)? {
        if journal.version != 1
            || journal.task != record.task_id().as_str()
            || journal.peer != record.peer_id().as_str()
            || journal.relative != details.relative_path
            || journal.root_hash != details.manifest.root_hash.to_hex()
            || journal.staged != staged
            || journal.parent != parent_id
            || journal.old.is_some() != journal.backup.is_some()
            || journal.suffix > 10_000
            || journal.timestamp.len() != 19
            || journal.timestamp.as_bytes()[8] != b'T'
            || journal.timestamp.as_bytes()[18] != b'Z'
            || journal
                .timestamp
                .bytes()
                .enumerate()
                .any(|(i, b)| i != 8 && i != 18 && !b.is_ascii_digit())
        {
            return Err(fs::fail("发布 journal 身份与目标目录不符"));
        }
        if let Some(backup) = &journal.backup {
            super::protocol::validate_relative_path(backup)?;
            if backup.contains('/')
                || *backup != backup_name(&name, &journal.timestamp, journal.suffix)?
            {
                return Err(fs::fail("备份名称非法"));
            }
        }
        journal
    } else {
        let current = named_identity(&parent, &name)?;
        // T006 retained a same-inode published target without a journal.
        let old = current.filter(|id| *id != staged);
        let stamp = timestamp(system_time_unix_ms().map_err(local_error)?);
        let backup = old
            .as_ref()
            .map(|_| backup_name(&name, &stamp, 0))
            .transpose()?;
        let journal = Journal {
            version: 1,
            task: record.task_id().as_str().into(),
            peer: record.peer_id().as_str().into(),
            relative: details.relative_path.clone(),
            root_hash: details.manifest.root_hash.to_hex(),
            parent: parent_id,
            staged: staged.clone(),
            old,
            backup,
            timestamp: stamp,
            suffix: 0,
            phase: Phase::Prepared,
        };
        write_journal(&stage, &journal)?;
        journal
    };
    store
        .prepare_publication(record.task_id())
        .map_err(local_error)?;
    boundary("after-prepared")?;
    if journal.phase == Phase::Prepared {
        if let Some(old) = &journal.old {
            loop {
                let backup = journal.backup.as_ref().unwrap();
                if named_identity(&parent, backup)?.as_ref() == Some(old) {
                    break;
                }
                if named_identity(&parent, &name)?.as_ref() != Some(old) {
                    return Err(fs::fail("发布旧目标已被外部进程改变"));
                }
                boundary("before-backup")?;
                match fs::rename_no_replace(&parent, &name, backup) {
                    Ok(()) => {
                        fs::sync(&parent)?;
                        boundary("after-backup-filesystem")?;
                        if named_identity(&parent, backup)?.as_ref() != Some(old) {
                            return Err(fs::fail("发布备份身份已被外部进程改变"));
                        }
                        break;
                    }
                    Err(crate::error::Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                        journal.suffix += 1;
                        if journal.suffix > 10_000 {
                            return Err(fs::fail("备份名称碰撞次数超限"));
                        }
                        journal.backup =
                            Some(backup_name(&name, &journal.timestamp, journal.suffix)?);
                        write_journal(&stage, &journal)?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        journal.phase = Phase::OldBackedUp;
        write_journal(&stage, &journal)?;
        boundary("after-backup-journal")?;
    }
    if let Some(old) = &journal.old
        && named_identity(&parent, journal.backup.as_ref().unwrap())?.as_ref() != Some(old)
    {
        return Err(fs::fail("发布备份丢失或身份变化"));
    }
    if matches!(journal.phase, Phase::OldBackedUp) {
        boundary("before-publish")?;
        match stage.hard_link(staged_name, &parent, &name) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if named_identity(&parent, &name)?.as_ref() != Some(&staged) {
                    return Err(fs::fail("发布目标被外部进程抢占"));
                }
            }
            Err(e) => return Err(e.into()),
        }
        fs::sync(&parent)?;
        boundary("after-publish-filesystem")?;
        journal.phase = Phase::NewPublished;
        write_journal(&stage, &journal)?;
        boundary("after-publish-journal")?;
    }
    if named_identity(&parent, &name)?.as_ref() != Some(&staged) {
        return Err(fs::fail("发布正式文件身份不符"));
    }
    let target = fs::open(&parent, &name, true, false)?;
    target.sync_all()?;
    drop(target);
    boundary("before-receipt")?;
    verify(&parent, &name, &details.manifest)?;
    if named_identity(&parent, &name)?.as_ref() != Some(&staged) {
        return Err(fs::fail("发布正式文件在回执前被替换"));
    }
    store
        .commit_receipt(
            record.task_id(),
            system_time_unix_ms().map_err(local_error)?,
        )
        .map_err(local_error)?;
    boundary("after-receipt")?;
    journal.phase = Phase::ReceiptCommitted;
    if write_journal(&stage, &journal).is_err() {
        tracing::warn!("回执已提交；发布 journal 清理待重试");
    }
    if super::transfer_files::cleanup_staging(record).is_err() {
        tracing::warn!("回执已提交；暂存清理待重试");
    }
    Ok(record.local_path().join(&details.relative_path))
}

pub fn directory(store: &mut TaskStore, record: &TaskRecord) -> Result<()> {
    let details = record
        .directory_details()
        .ok_or_else(|| fs::fail("缺少目录绑定"))?;
    let root = fs::root(record.local_path())?;
    let (parent, name) = fs::parent(&root, &details.relative_path, true)?;
    let directory = fs::child(&parent, &name, true)?;
    fs::sync(&directory)?;
    fs::sync(&parent)?;
    store
        .prepare_publication(record.task_id())
        .map_err(local_error)?;
    store
        .commit_receipt(
            record.task_id(),
            system_time_unix_ms().map_err(local_error)?,
        )
        .map_err(local_error)
}

#[cfg(test)]
mod tests {
    use super::super::{
        task_model::{TaskId, TaskState},
        transfer_files as disk,
    };
    use super::*;
    use crate::{
        identity::Identity, protocol::manifest::MIN_CHUNK_SIZE,
        transfer::chunker::manifest_from_path,
    };
    use std::fs as ambient;
    struct Fixture {
        root: PathBuf,
        store: TaskStore,
        record: TaskRecord,
        bytes: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("p2p-publish-{}", rand::random::<u128>()));
            ambient::create_dir(&root).unwrap();
            ambient::create_dir(root.join("receive")).unwrap();
            let bytes = vec![71; MIN_CHUNK_SIZE as usize + 7];
            ambient::write(root.join("report.txt"), &bytes).unwrap();
            let manifest = manifest_from_path(&root.join("report.txt"), MIN_CHUNK_SIZE).unwrap();
            let (mut store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
            let record = disk::accept_offer(
                &mut store,
                Identity::generate().node_id(),
                &TaskId::generate(),
                &root.join("receive"),
                "nested/report.txt".into(),
                manifest,
            )
            .unwrap();
            disk::transition(&mut store, record.task_id(), TaskState::Transferring).unwrap();
            disk::transition(&mut store, record.task_id(), TaskState::Finalizing).unwrap();
            ambient::create_dir(root.join("receive/nested")).unwrap();
            ambient::write(root.join("receive/nested/report.txt"), b"old user content").unwrap();
            Self {
                root,
                store,
                record,
                bytes,
            }
        }
        fn download(&self) -> PartialDownload {
            let mut download = disk::open_download(&self.record).unwrap();
            for index in download.missing() {
                let (offset, len) = download.manifest().chunk_range(index).unwrap();
                download
                    .write_chunk(
                        index,
                        &self.bytes[offset as usize..offset as usize + len as usize],
                    )
                    .unwrap();
            }
            download
        }
        fn backups(&self) -> Vec<PathBuf> {
            ambient::read_dir(self.root.join("receive/nested"))
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("report+")
                })
                .collect()
        }
        fn verify(&self) {
            assert_eq!(
                ambient::read(self.root.join("receive/nested/report.txt")).unwrap(),
                self.bytes
            );
            let backups = self.backups();
            assert_eq!(backups.len(), 1);
            assert_eq!(ambient::read(&backups[0]).unwrap(), b"old user content");
            assert!(
                self.store
                    .task(self.record.task_id())
                    .unwrap()
                    .receipt_committed()
            );
        }
        fn cleanup(self) {
            drop(self.store);
            ambient::remove_dir_all(self.root).unwrap();
        }
    }
    #[test]
    fn every_publication_boundary_reopens_without_losing_old_data_or_duplicate_backup() {
        for point in [
            "before-prepared",
            "after-prepared",
            "before-backup",
            "after-backup-filesystem",
            "after-backup-journal",
            "before-publish",
            "after-publish-filesystem",
            "after-publish-journal",
            "before-receipt",
            "after-receipt",
        ] {
            let mut f = Fixture::new();
            let mut download = f.download();
            let error = file_with_boundary(&mut f.store, &f.record, &mut download, |at| {
                if at == point {
                    Err(io::Error::new(
                        io::ErrorKind::StorageFull,
                        "injected durable boundary failure",
                    )
                    .into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert!(
                matches!(error, crate::error::Error::Io(_)),
                "{point}: {error}"
            );
            let old_is_target = ambient::read(f.root.join("receive/nested/report.txt"))
                .is_ok_and(|b| b == b"old user content");
            let old_is_backup = f
                .backups()
                .iter()
                .any(|p| ambient::read(p).unwrap() == b"old user content");
            assert!(
                old_is_target || old_is_backup,
                "lost old content at {point}"
            );
            let id = f.record.task_id().clone();
            drop(download);
            drop(f.store);
            let (mut store, _) = TaskStore::open(&f.root.join("state/tasks.json")).unwrap();
            let mut record = store.task(&id).unwrap();
            if record.state() != TaskState::Completed {
                assert!(!record.receipt_committed());
                record = disk::begin_attempt(&mut store, &id).unwrap();
                disk::transition(&mut store, &id, TaskState::Transferring).unwrap();
                disk::transition(&mut store, &id, TaskState::Finalizing).unwrap();
                let mut download = disk::open_download(&record).unwrap();
                assert!(download.is_complete());
                file(&mut store, &record, &mut download).unwrap();
            } else {
                disk::cleanup_staging(&record).unwrap();
            }
            f.store = store;
            f.record = record;
            f.verify();
            f.cleanup();
        }
    }
    #[test]
    fn timestamp_collision_preserves_occupied_backup_and_retries_fixed_suffix() {
        let mut f = Fixture::new();
        let mut download = f.download();
        let stage_path = disk::stage_dir(&f.record).unwrap();
        let mut occupied = None;
        file_with_boundary(&mut f.store, &f.record, &mut download, |at| {
            if at == "after-prepared" {
                let stage = fs::root(&stage_path)?;
                let journal = read_journal(&stage)?.unwrap();
                let path = f.root.join("receive/nested").join(journal.backup.unwrap());
                ambient::write(&path, b"occupied backup")?;
                occupied = Some(path);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            ambient::read(occupied.unwrap()).unwrap(),
            b"occupied backup"
        );
        assert_eq!(f.backups().len(), 2);
        assert!(
            f.backups()
                .iter()
                .any(|p| p.to_str().unwrap().contains("Z-1.txt"))
        );
        assert_eq!(
            ambient::read(f.root.join("receive/nested/report.txt")).unwrap(),
            f.bytes
        );
        drop(download);
        f.cleanup();
    }
    #[test]
    fn external_target_claim_is_never_overwritten_and_retry_does_not_backup_again() {
        let mut f = Fixture::new();
        let mut download = f.download();
        let target = f.root.join("receive/nested/report.txt");
        let error = file_with_boundary(&mut f.store, &f.record, &mut download, |at| {
            if at == "before-publish" {
                ambient::write(&target, b"external claimant")?;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("抢占"));
        assert_eq!(ambient::read(&target).unwrap(), b"external claimant");
        assert!(
            !f.store
                .task(f.record.task_id())
                .unwrap()
                .receipt_committed()
        );
        assert_eq!(f.backups().len(), 1);
        drop(download);
        ambient::remove_file(&target).unwrap();
        let mut download = disk::open_download(&f.record).unwrap();
        file(&mut f.store, &f.record, &mut download).unwrap();
        f.verify();
        drop(download);
        f.cleanup();
    }
    #[test]
    fn permissions_failure_keeps_recovery_and_does_not_commit_receipt() {
        let mut f = Fixture::new();
        let mut download = f.download();
        file_with_boundary(&mut f.store, &f.record, &mut download, |at| {
            if at == "before-backup" {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected filesystem permission failure",
                )
                .into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(
            ambient::read(f.root.join("receive/nested/report.txt")).unwrap(),
            b"old user content"
        );
        assert!(
            !f.store
                .task(f.record.task_id())
                .unwrap()
                .receipt_committed()
        );
        assert!(download.temp_path().exists());
        drop(download);
        let mut download = disk::open_download(&f.record).unwrap();
        file(&mut f.store, &f.record, &mut download).unwrap();
        f.verify();
        drop(download);
        f.cleanup();
    }
    #[test]
    fn backup_timestamp_is_utc_and_no_replace_rename_preserves_destination() {
        assert_eq!(timestamp(0), "19700101T000000000Z");
        assert_eq!(timestamp(1_600_000_000_123), "20200913T122640123Z");
        assert_eq!(
            backup_name("report.txt", "20200913T122640123Z", 1).unwrap(),
            "report+20200913T122640123Z-1.txt"
        );
        let f = Fixture::new();
        let dir = fs::root(&f.root.join("receive/nested")).unwrap();
        ambient::write(f.root.join("receive/nested/occupied.txt"), b"occupied").unwrap();
        assert!(fs::rename_no_replace(&dir, "report.txt", "occupied.txt").is_err());
        assert_eq!(
            ambient::read(f.root.join("receive/nested/occupied.txt")).unwrap(),
            b"occupied"
        );
        assert_eq!(
            ambient::read(f.root.join("receive/nested/report.txt")).unwrap(),
            b"old user content"
        );
        drop(dir);
        f.cleanup();
    }
    #[cfg(windows)]
    #[test]
    fn windows_open_target_failure_keeps_old_file_and_can_retry_after_release() {
        use std::os::windows::fs::OpenOptionsExt;
        let mut f = Fixture::new();
        let mut download = f.download();
        let held = ambient::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(f.root.join("receive/nested/report.txt"))
            .unwrap();
        assert!(file(&mut f.store, &f.record, &mut download).is_err());
        assert!(
            !f.store
                .task(f.record.task_id())
                .unwrap()
                .receipt_committed()
        );
        drop(held);
        drop(download);
        let mut download = disk::open_download(&f.record).unwrap();
        file(&mut f.store, &f.record, &mut download).unwrap();
        f.verify();
        drop(download);
        f.cleanup();
    }
    #[cfg(unix)]
    #[test]
    fn target_ancestor_replaced_by_symlink_cannot_write_outside_receive_root() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        let mut download = f.download();
        let outside = f.root.join("outside");
        ambient::create_dir(&outside).unwrap();
        ambient::rename(
            f.root.join("receive/nested"),
            f.root.join("receive/original"),
        )
        .unwrap();
        symlink(&outside, f.root.join("receive/nested")).unwrap();
        assert!(file(&mut f.store, &f.record, &mut download).is_err());
        assert_eq!(ambient::read_dir(&outside).unwrap().count(), 0);
        assert!(
            !f.store
                .task(f.record.task_id())
                .unwrap()
                .receipt_committed()
        );
        assert_eq!(
            ambient::read(f.root.join("receive/original/report.txt")).unwrap(),
            b"old user content"
        );
        f.cleanup();
    }
    #[test]
    fn external_replacement_immediately_before_receipt_is_not_completed() {
        let mut f = Fixture::new();
        let mut download = f.download();
        let target = f.root.join("receive/nested/report.txt");
        let error = file_with_boundary(&mut f.store, &f.record, &mut download, |at| {
            if at == "before-receipt" {
                ambient::remove_file(&target)?;
                ambient::write(&target, b"external replacement")?;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("发布"));
        assert!(
            !f.store
                .task(f.record.task_id())
                .unwrap()
                .receipt_committed()
        );
        assert_eq!(ambient::read(&target).unwrap(), b"external replacement");
        assert_eq!(f.backups().len(), 1);
        drop(download);
        f.cleanup();
    }
    #[test]
    fn corrupted_journal_binding_is_diagnostic_instead_of_panicking() {
        let mut f = Fixture::new();
        let mut download = f.download();
        let stage_path = disk::stage_dir(&f.record).unwrap();
        file_with_boundary(&mut f.store, &f.record, &mut download, |at| {
            if at == "after-prepared" {
                Err(fs::fail("injected stop"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        let stage = fs::root(&stage_path).unwrap();
        let mut journal = read_journal(&stage).unwrap().unwrap();
        journal.backup = None;
        write_journal(&stage, &journal).unwrap();
        drop(download);
        let mut download = disk::open_download(&f.record).unwrap();
        let error = file(&mut f.store, &f.record, &mut download).unwrap_err();
        assert!(error.to_string().contains("journal"));
        assert!(
            !f.store
                .task(f.record.task_id())
                .unwrap()
                .receipt_committed()
        );
        assert_eq!(
            ambient::read(f.root.join("receive/nested/report.txt")).unwrap(),
            b"old user content"
        );
        drop(download);
        drop(stage);
        f.cleanup();
    }
    #[test]
    fn two_threads_publish_same_target_serially_and_keep_both_displaced_contents() {
        use std::sync::{Arc, Barrier, Mutex};
        let mut f = Fixture::new();
        let first = f.download();
        let second_bytes = vec![93; MIN_CHUNK_SIZE as usize + 9];
        ambient::write(f.root.join("report.txt"), &second_bytes).unwrap();
        let manifest = manifest_from_path(&f.root.join("report.txt"), MIN_CHUNK_SIZE).unwrap();
        let second_record = disk::accept_offer(
            &mut f.store,
            Identity::generate().node_id(),
            &TaskId::generate(),
            &f.root.join("receive"),
            "nested/report.txt".into(),
            manifest,
        )
        .unwrap();
        disk::transition(
            &mut f.store,
            second_record.task_id(),
            TaskState::Transferring,
        )
        .unwrap();
        disk::transition(&mut f.store, second_record.task_id(), TaskState::Finalizing).unwrap();
        let mut second = disk::open_download(&second_record).unwrap();
        for index in second.missing() {
            let (offset, len) = second.manifest().chunk_range(index).unwrap();
            second
                .write_chunk(
                    index,
                    &second_bytes[offset as usize..offset as usize + len as usize],
                )
                .unwrap();
        }
        let store = Arc::new(Mutex::new(f.store));
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for (record, mut download) in [(f.record.clone(), first), (second_record.clone(), second)] {
            let store = store.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                file(&mut store.lock().unwrap(), &record, &mut download).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        f.store = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        assert!(
            f.store
                .task(f.record.task_id())
                .unwrap()
                .receipt_committed()
        );
        assert!(
            f.store
                .task(second_record.task_id())
                .unwrap()
                .receipt_committed()
        );
        let target = ambient::read(f.root.join("receive/nested/report.txt")).unwrap();
        assert!(target == f.bytes || target == second_bytes);
        let backups = f.backups();
        assert_eq!(backups.len(), 2);
        let contents = backups
            .iter()
            .map(|p| ambient::read(p).unwrap())
            .collect::<Vec<_>>();
        assert!(contents.contains(&b"old user content".to_vec()));
        assert!(contents.contains(if target == f.bytes {
            &second_bytes
        } else {
            &f.bytes
        }));
        f.cleanup();
    }
    /// Isolated libtest child only; no production environment hook.
    #[test]
    fn publication_process_entry() {
        let Some(root) = std::env::var_os("P2P_PUBLICATION_KILL_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let point = std::env::var("P2P_PUBLICATION_KILL_POINT").unwrap();
        let id = TaskId::parse(&ambient::read_to_string(root.join("task-id")).unwrap()).unwrap();
        let (mut store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
        let record = disk::begin_attempt(&mut store, &id).unwrap();
        disk::transition(&mut store, &id, TaskState::Transferring).unwrap();
        disk::transition(&mut store, &id, TaskState::Finalizing).unwrap();
        let mut download = disk::open_download(&record).unwrap();
        assert!(download.is_complete());
        file_with_boundary(&mut store, &record, &mut download, |at| {
            if at == point {
                use std::io::Write;
                let mut marker = ambient::File::create(root.join("kill-ready.tmp")).unwrap();
                marker.write_all(at.as_bytes()).unwrap();
                marker.sync_all().unwrap();
                drop(marker);
                ambient::rename(root.join("kill-ready.tmp"), root.join("kill-ready")).unwrap();
                // The parent kills this real process here. Destructors never run.
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        })
        .unwrap();
        panic!("requested publication boundary was not reached");
    }
    #[test]
    fn os_kill_at_every_publication_boundary_preserves_old_new_and_single_receipt() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for point in [
            "before-prepared",
            "after-prepared",
            "before-backup",
            "after-backup-filesystem",
            "after-backup-journal",
            "before-publish",
            "after-publish-filesystem",
            "after-publish-journal",
            "before-receipt",
            "after-receipt",
        ] {
            let f = Fixture::new();
            let mut download = f.download();
            download.checkpoint().unwrap();
            drop(download);
            let id = f.record.task_id().clone();
            ambient::write(f.root.join("task-id"), id.as_str()).unwrap();
            let root = f.root.clone();
            let bytes = f.bytes.clone();
            drop(f.store);
            let log = ambient::File::create(root.join("process.log")).unwrap();
            let mut child = ChildGuard(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "desktop::publish::tests::publication_process_entry",
                        "--nocapture",
                    ])
                    .env("P2P_PUBLICATION_KILL_ROOT", &root)
                    .env("P2P_PUBLICATION_KILL_POINT", point)
                    .stdout(log.try_clone().unwrap())
                    .stderr(log)
                    .spawn()
                    .unwrap(),
            );
            let start = std::time::Instant::now();
            loop {
                if root.join("kill-ready").exists() {
                    break;
                }
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "child failed at {point}: {}",
                    ambient::read_to_string(root.join("process.log")).unwrap()
                );
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(60),
                    "boundary {point} timed out; {}",
                    root.display()
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert_eq!(
                ambient::read_to_string(root.join("kill-ready")).unwrap(),
                point
            );
            child.0.kill().unwrap();
            let status = child.0.wait().unwrap();
            assert!(!status.success());
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
            }
            let (mut store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
            let mut record = store.task(&id).unwrap();
            let before = Fixture {
                root: root.clone(),
                store,
                record: record.clone(),
                bytes: bytes.clone(),
            };
            assert!(
                ambient::read(root.join("receive/nested/report.txt"))
                    .is_ok_and(|b| b == b"old user content")
                    || before
                        .backups()
                        .iter()
                        .any(|p| ambient::read(p).unwrap() == b"old user content"),
                "old data lost at {point}"
            );
            store = before.store;
            if record.state() != TaskState::Completed {
                assert!(!record.receipt_committed());
                let row = super::super::ui_model::TaskRow::from_record(&record, 1000.);
                assert_eq!(row.state, TaskState::Interrupted);
                assert_eq!(row.rate, 0.);
                record = disk::begin_attempt(&mut store, &id).unwrap();
                disk::transition(&mut store, &id, TaskState::Transferring).unwrap();
                disk::transition(&mut store, &id, TaskState::Finalizing).unwrap();
                let mut download = disk::open_download(&record).unwrap();
                assert!(download.is_complete());
                file(&mut store, &record, &mut download).unwrap();
            } else {
                disk::cleanup_staging(&record).unwrap();
            }
            let final_fixture = Fixture {
                root,
                store,
                record,
                bytes,
            };
            final_fixture.verify();
            assert_eq!(
                final_fixture.store.task(&id).unwrap().state(),
                TaskState::Completed
            );
            println!(
                "DESKTOP_E2E_PROOF {}",
                serde_json::json!({"scenario":"publication-os-kill", "platform":std::env::consts::OS,"detail":{"boundary":point,"task_id":id.as_str(),"os_kill":if cfg!(unix){"SIGKILL"}else{"TerminateProcess"},"backup_count":1,"receipt":true,"hash":blake3::hash(&final_fixture.bytes).to_hex().to_string()}})
            );
            final_fixture.cleanup();
        }
    }
}
