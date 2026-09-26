//! Versioned, single-writer task snapshots with atomic replacement.
//!
//! The desktop startup path holds the per-data-directory `InstanceLock` for
//! the lifetime of this store. Mutation requires `&mut TaskStore`; callers
//! must not create multiple stores for the same path outside that lock.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    instance_lock::{InstanceLock, InstanceLockError},
    task_events::{TaskEvent, TaskEventBuffer, TaskEventKind},
    task_model::{ProgressHint, TaskDiagnostic, TaskId, TaskModelError, TaskRecord, TaskState},
    task_recovery::{self, StartupRecoveryReport},
};

const STORE_FORMAT_VERSION: u32 = 1;
const MAX_STORE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum TaskStoreError {
    #[error("任务存储暂时不可用")]
    Io(#[source] io::Error),
    #[error("任务存储格式损坏；原文件已保留")]
    Corrupt,
    #[error("任务存储版本 {0} 不受支持；原文件已保留")]
    UnsupportedVersion(u32),
    #[error("{0}")]
    Model(#[from] TaskModelError),
    #[error("任务记录不存在")]
    TaskNotFound,
    #[error("任务目录已由另一个写入者使用")]
    AlreadyRunning,
    #[error("任务存储提交状态不确定；请重启应用后重试")]
    CommitUncertain,
    #[error("任务存储代数已耗尽")]
    GenerationExhausted,
    #[cfg(test)]
    #[error("任务存储提交故障注入")]
    InjectedFailure,
}

impl From<io::Error> for TaskStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

enum SnapshotWriteError {
    BeforeReplace(io::Error),
    AfterReplace,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreSnapshot {
    format_version: u32,
    generation: u64,
    tasks: Vec<TaskRecord>,
}

#[derive(Debug)]
pub(crate) struct TaskStore {
    path: PathBuf,
    _store_lock: InstanceLock,
    tasks: Vec<TaskRecord>,
    generation: u64,
    events: TaskEventBuffer,
    poisoned: bool,
    #[cfg(test)]
    fail_before_replace: bool,
}

impl TaskStore {
    /// Open one local task store. The caller must hold the existing
    /// per-data-directory instance lock for the complete lifetime of the
    /// returned store.
    pub(crate) fn open(path: &Path) -> Result<(Self, StartupRecoveryReport), TaskStoreError> {
        if !path.is_absolute() {
            return Err(TaskStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task store path must be absolute",
            )));
        }
        let parent = path.parent().ok_or_else(|| {
            TaskStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task store parent directory is missing",
            ))
        })?;
        super::config::ensure_private_app_dir(parent).map_err(TaskStoreError::Io)?;
        let store_lock =
            InstanceLock::acquire(&path.with_extension("lock")).map_err(|error| match error {
                InstanceLockError::AlreadyRunning => TaskStoreError::AlreadyRunning,
                InstanceLockError::Io(error) => TaskStoreError::Io(error),
            })?;

        let (mut tasks, generation) = match read_snapshot(path)? {
            Some(snapshot) => {
                validate_snapshot(&snapshot)?;
                (snapshot.tasks, snapshot.generation)
            }
            None => (Vec::new(), 0),
        };

        let recovery = task_recovery::recover_startup(&mut tasks)?;
        let mut store = Self {
            path: path.to_path_buf(),
            _store_lock: store_lock,
            tasks,
            generation,
            events: TaskEventBuffer::default(),
            poisoned: false,
            #[cfg(test)]
            fail_before_replace: false,
        };

        if path.exists() {
            for task_id in recovery.interrupted_task_ids() {
                store.events.record(
                    task_id.clone(),
                    store.task(task_id)?.updated_at_unix_ms(),
                    TaskEventKind::RecoveredAfterRestart,
                );
            }
        }

        // A missing file is initialized durably; recovered state is committed
        // before the store is returned to callers.
        if !path.exists() || !recovery.interrupted_task_ids().is_empty() {
            store.commit_current_tasks()?;
        }

        Ok((store, recovery))
    }

    pub(crate) fn list(&self) -> &[TaskRecord] {
        &self.tasks
    }

    pub(crate) fn task(&self, task_id: &TaskId) -> Result<TaskRecord, TaskStoreError> {
        self.tasks
            .iter()
            .find(|task| task.task_id() == task_id)
            .cloned()
            .ok_or(TaskStoreError::TaskNotFound)
    }

    /// Make a task visible only after its complete snapshot is durable.
    pub(crate) fn create(&mut self, task: TaskRecord) -> Result<TaskId, TaskStoreError> {
        self.ensure_healthy()?;
        task.validate()?;
        if task.state() != TaskState::Scanning {
            return Err(TaskModelError::NewTaskMustStartScanning.into());
        }
        if self
            .tasks
            .iter()
            .any(|existing| existing.task_id() == task.task_id())
        {
            return Err(TaskStoreError::Corrupt);
        }
        let task_id = task.task_id_owned();
        let timestamp = task.created_at_unix_ms();
        let mut candidate = self.tasks.clone();
        candidate.push(task);
        sort_tasks(&mut candidate);
        self.commit_tasks(candidate)?;
        self.events
            .record(task_id.clone(), timestamp, TaskEventKind::Created);
        Ok(task_id)
    }

    /// All scanned entries become durable together; a cancelled/failed scan leaves no partial group.
    pub(crate) fn create_selection(
        &mut self,
        records: Vec<TaskRecord>,
    ) -> Result<Vec<TaskId>, TaskStoreError> {
        self.ensure_healthy()?;
        let mut candidate = self.tasks.clone();
        let mut ids = Vec::new();
        for record in records {
            record.validate()?;
            if record.state() != TaskState::Scanning
                || candidate.iter().any(|t| t.task_id() == record.task_id())
            {
                return Err(TaskStoreError::Corrupt);
            }
            ids.push(record.task_id().clone());
            candidate.push(record);
        }
        sort_tasks(&mut candidate);
        self.commit_tasks(candidate)?;
        for id in &ids {
            let record = self.task(id)?;
            self.events.record(
                id.clone(),
                record.created_at_unix_ms(),
                TaskEventKind::Created,
            );
        }
        Ok(ids)
    }

    pub(crate) fn transition(
        &mut self,
        task_id: &TaskId,
        next: TaskState,
        diagnostic: Option<TaskDiagnostic>,
        now_unix_ms: i64,
    ) -> Result<(), TaskStoreError> {
        self.ensure_healthy()?;
        let mut candidate = self.tasks.clone();
        let task = candidate
            .iter_mut()
            .find(|task| task.task_id() == task_id)
            .ok_or(TaskStoreError::TaskNotFound)?;
        let previous = task.state();
        task.transition_to(next, diagnostic, now_unix_ms)?;
        task.validate_binding_unchanged(
            self.tasks
                .iter()
                .find(|stored| stored.task_id() == task_id)
                .ok_or(TaskStoreError::TaskNotFound)?,
        )?;
        let timestamp = task.updated_at_unix_ms();
        self.commit_tasks(candidate)?;
        self.events.record(
            task_id.clone(),
            timestamp,
            TaskEventKind::StateChanged {
                from: previous,
                to: next,
            },
        );
        Ok(())
    }

    pub(crate) fn prepare_publication(&mut self, id: &TaskId) -> Result<(), TaskStoreError> {
        self.ensure_healthy()?;
        let mut candidate = self.tasks.clone();
        candidate
            .iter_mut()
            .find(|t| t.task_id() == id)
            .ok_or(TaskStoreError::TaskNotFound)?
            .prepare_publication()?;
        self.commit_tasks(candidate)
    }

    pub(crate) fn commit_receipt(&mut self, id: &TaskId, now: i64) -> Result<(), TaskStoreError> {
        self.ensure_healthy()?;
        let mut candidate = self.tasks.clone();
        let task = candidate
            .iter_mut()
            .find(|t| t.task_id() == id)
            .ok_or(TaskStoreError::TaskNotFound)?;
        let from = task.state();
        task.commit_receipt(now)?;
        self.commit_tasks(candidate)?;
        self.events.record(
            id.clone(),
            now,
            TaskEventKind::StateChanged {
                from,
                to: TaskState::Completed,
            },
        );
        Ok(())
    }

    /// Progress is an in-memory display hint. Call `flush_progress_hints`
    /// explicitly at a coalesced boundary; never fsync once per chunk.
    pub(crate) fn set_progress_hint(
        &mut self,
        task_id: &TaskId,
        hint: ProgressHint,
    ) -> Result<(), TaskStoreError> {
        self.ensure_healthy()?;
        let mut candidate = self.tasks.clone();
        let task = candidate
            .iter_mut()
            .find(|task| task.task_id() == task_id)
            .ok_or(TaskStoreError::TaskNotFound)?;
        task.set_progress_hint(hint)?;
        self.tasks = candidate;
        self.events.record(
            task_id.clone(),
            hint.sampled_at_unix_ms(),
            TaskEventKind::ProgressHintChanged,
        );
        Ok(())
    }

    pub(crate) fn flush_progress_hints(&mut self) -> Result<(), TaskStoreError> {
        self.ensure_healthy()?;
        self.commit_current_tasks()
    }

    #[allow(dead_code)] // The task-list UI consumes this event API in a later authorized task.
    pub(crate) fn drain_events(&mut self) -> Vec<TaskEvent> {
        self.events.drain()
    }

    fn ensure_healthy(&self) -> Result<(), TaskStoreError> {
        if self.poisoned {
            Err(TaskStoreError::CommitUncertain)
        } else {
            Ok(())
        }
    }

    fn commit_current_tasks(&mut self) -> Result<(), TaskStoreError> {
        self.commit_tasks(self.tasks.clone())
    }

    fn commit_tasks(&mut self, mut candidate: Vec<TaskRecord>) -> Result<(), TaskStoreError> {
        self.ensure_healthy()?;
        sort_tasks(&mut candidate);
        for task in &candidate {
            task.validate()?;
        }
        validate_unique_ids(&candidate)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(TaskStoreError::GenerationExhausted)?;
        let snapshot = StoreSnapshot {
            format_version: STORE_FORMAT_VERSION,
            generation,
            tasks: candidate.clone(),
        };
        #[cfg(test)]
        let fail_before_replace = std::mem::take(&mut self.fail_before_replace);
        let result = write_snapshot(&self.path, &snapshot, || {
            #[cfg(test)]
            if fail_before_replace {
                return Err(io::Error::other("injected failure before atomic replace"));
            }
            Ok(())
        });
        if let Err(error) = result {
            let SnapshotWriteError::BeforeReplace(error) = error else {
                self.poisoned = true;
                return Err(TaskStoreError::CommitUncertain);
            };
            if error.kind() == io::ErrorKind::Other {
                #[cfg(test)]
                return Err(TaskStoreError::InjectedFailure);
            }
            return Err(TaskStoreError::Io(error));
        }
        self.tasks = candidate;
        self.generation = generation;
        Ok(())
    }
}

fn read_snapshot(path: &Path) -> Result<Option<StoreSnapshot>, TaskStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(TaskStoreError::Io(error)),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_STORE_BYTES {
        return Err(TaskStoreError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(TaskStoreError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "task store permissions must be private",
            )));
        }
    }

    let mut file = File::open(path).map_err(TaskStoreError::Io)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(TaskStoreError::Io)?;
    let snapshot: StoreSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| TaskStoreError::Corrupt)?;
    if snapshot.format_version != STORE_FORMAT_VERSION {
        return Err(TaskStoreError::UnsupportedVersion(snapshot.format_version));
    }
    Ok(Some(snapshot))
}

fn validate_snapshot(snapshot: &StoreSnapshot) -> Result<(), TaskStoreError> {
    if snapshot.format_version != STORE_FORMAT_VERSION {
        return Err(TaskStoreError::UnsupportedVersion(snapshot.format_version));
    }
    for task in &snapshot.tasks {
        task.validate()?;
    }
    validate_unique_ids(&snapshot.tasks)
}

fn validate_unique_ids(tasks: &[TaskRecord]) -> Result<(), TaskStoreError> {
    let mut ids = BTreeSet::new();
    if tasks.iter().any(|task| !ids.insert(task.task_id().clone())) {
        return Err(TaskStoreError::Corrupt);
    }
    Ok(())
}

fn sort_tasks(tasks: &mut [TaskRecord]) {
    tasks.sort_by(|left, right| left.task_id().cmp(right.task_id()));
}

fn write_snapshot<F>(
    path: &Path,
    snapshot: &StoreSnapshot,
    before_replace: F,
) -> Result<(), SnapshotWriteError>
where
    F: FnOnce() -> io::Result<()>,
{
    let parent = path.parent().ok_or_else(|| {
        SnapshotWriteError::BeforeReplace(io::Error::new(
            io::ErrorKind::InvalidInput,
            "task store parent directory is missing",
        ))
    })?;
    let bytes = serde_json::to_vec(snapshot).map_err(|error| {
        SnapshotWriteError::BeforeReplace(io::Error::new(io::ErrorKind::InvalidData, error))
    })?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(SnapshotWriteError::BeforeReplace(io::Error::new(
            io::ErrorKind::InvalidData,
            "task store exceeds its size limit",
        )));
    }
    let (temp_path, mut temp_file) = create_unique_temp(
        parent,
        path.file_name().ok_or_else(|| {
            SnapshotWriteError::BeforeReplace(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task store file name is missing",
            ))
        })?,
    )
    .map_err(SnapshotWriteError::BeforeReplace)?;
    let mut cleanup = TempFileCleanup(Some(temp_path.clone()));
    temp_file
        .write_all(&bytes)
        .map_err(SnapshotWriteError::BeforeReplace)?;
    temp_file
        .sync_all()
        .map_err(SnapshotWriteError::BeforeReplace)?;
    drop(temp_file);
    before_replace().map_err(SnapshotWriteError::BeforeReplace)?;
    replace_atomic(&temp_path, path).map_err(SnapshotWriteError::BeforeReplace)?;
    cleanup.0 = None;
    sync_parent_directory(parent).map_err(|_| SnapshotWriteError::AfterReplace)?;
    Ok(())
}

fn create_unique_temp(parent: &Path, target_name: &std::ffi::OsStr) -> io::Result<(PathBuf, File)> {
    for _ in 0..32 {
        let suffix = format!(
            "{}.{}.{}.tmp",
            target_name.to_string_lossy(),
            std::process::id(),
            rand::random::<u64>()
        );
        let candidate = parent.join(suffix);
        let mut options = OpenOptions::new();
        options.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique task store temporary file",
    ))
}

struct TempFileCleanup(Option<PathBuf>);

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn replace_atomic(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_atomic(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn replace_atomic(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    // MoveFileExW is called with MOVEFILE_WRITE_THROUGH. Windows does not offer
    // a portable directory fsync equivalent through std::fs::File.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::task_model::{ManifestIdentity, PeerId, TaskDirection, TaskErrorCode};
    use super::*;
    use crate::identity::{Identity, NodeId};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "p2p_file_task_store_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn write_private(path: &Path, contents: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).unwrap();
        file.write_all(contents).unwrap();
    }

    fn task() -> TaskRecord {
        let peer = NodeId::from_public_key(&Identity::generate().public_key());
        #[cfg(windows)]
        let source_path = PathBuf::from(r"C:\local\sensitive-source.bin");
        #[cfg(not(windows))]
        let source_path = PathBuf::from("/local/sensitive-source.bin");
        TaskRecord::new_sender(
            super::super::task_model::PeerId::from_node_id(peer),
            source_path,
            super::super::task_model::ManifestIdentity::blake3([9; 32], 12, 4).unwrap(),
        )
        .unwrap()
    }

    fn receiver_task() -> TaskRecord {
        let peer = NodeId::from_public_key(&Identity::generate().public_key());
        #[cfg(windows)]
        let receive_root = PathBuf::from(r"C:\Users\user\Downloads");
        #[cfg(not(windows))]
        let receive_root = PathBuf::from("/Users/user/Downloads");
        TaskRecord::new_receiver(
            PeerId::from_node_id(peer),
            receive_root,
            ManifestIdentity::blake3([7; 32], 12, 4).unwrap(),
        )
        .unwrap()
    }

    fn task_for_direction(direction: TaskDirection) -> TaskRecord {
        match direction {
            TaskDirection::Send => task(),
            TaskDirection::Receive => receiver_task(),
        }
    }

    fn transition_to_state(
        store: &mut TaskStore,
        task_id: &TaskId,
        target: TaskState,
        retryable_failure: bool,
    ) {
        use TaskState::*;

        let path: &[TaskState] = match target {
            Scanning => &[],
            Queued => &[Queued],
            Connecting => &[Queued, Connecting],
            Negotiating => &[Queued, Connecting, Negotiating],
            Transferring => &[Queued, Connecting, Negotiating, Transferring],
            Pausing => &[Queued, Pausing],
            Paused => &[Queued, Pausing, Paused],
            Finalizing => &[Queued, Connecting, Negotiating, Transferring, Finalizing],
            Completed => &[
                Queued,
                Connecting,
                Negotiating,
                Transferring,
                Finalizing,
                Completed,
            ],
            Interrupted => &[Interrupted],
            Failed => &[Failed],
        };

        for (index, next) in path.iter().copied().enumerate() {
            let diagnostic = (next == Failed)
                .then(|| TaskDiagnostic::new(TaskErrorCode::NetworkInterrupted, retryable_failure));
            store
                .transition(task_id, next, diagnostic, 100 + index as i64)
                .unwrap();
        }
        assert_eq!(store.task(task_id).unwrap().state(), target);
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn new_tasks_are_durable_before_the_store_exposes_them() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let task_id = store.create(task()).unwrap();
        assert_eq!(store.list().len(), 1);
        assert!(path.is_file());

        let mut already_queued = task();
        already_queued
            .transition_to(TaskState::Queued, None, 10)
            .unwrap();
        assert!(matches!(
            store.create(already_queued),
            Err(TaskStoreError::Model(
                TaskModelError::NewTaskMustStartScanning
            ))
        ));
        assert_eq!(store.list().len(), 1);
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::AlreadyRunning)
        ));
        drop(store);

        let (reopened, _) = TaskStore::open(&path).unwrap();
        let interrupted = reopened.task(&task_id).unwrap();
        assert_eq!(interrupted.state(), TaskState::Interrupted);
        assert_eq!(
            interrupted.diagnostic().unwrap().code(),
            super::super::task_model::TaskErrorCode::ApplicationRestarted
        );
        drop(reopened);
        let (second_reopen, report) = TaskStore::open(&path).unwrap();
        assert!(report.interrupted_task_ids().is_empty());
        assert_eq!(
            second_reopen.task(&task_id).unwrap().state(),
            TaskState::Interrupted
        );
        drop(second_reopen);
        cleanup(&dir);
    }

    #[test]
    fn failed_commit_does_not_expose_candidate_or_destroy_previous_snapshot() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let previous_task_id = store.create(task()).unwrap();
        let previous = fs::read(&path).unwrap();
        store.fail_before_replace = true;
        assert!(matches!(
            store.create(task()),
            Err(TaskStoreError::InjectedFailure)
        ));
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].task_id(), &previous_task_id);
        assert_eq!(fs::read(&path).unwrap(), previous);
        assert_eq!(
            fs::read_dir(&dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
        drop(store);
        let (reopened, _) = TaskStore::open(&path).unwrap();
        assert_eq!(reopened.list().len(), 1);
        assert_eq!(reopened.list()[0].task_id(), &previous_task_id);
        drop(reopened);
        cleanup(&dir);
    }

    #[test]
    fn truncated_and_unknown_version_stores_are_rejected_without_replacement() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        write_private(&path, b"{\"format_version\":");
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Corrupt)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        write_private(&path, br#"{"format_version":77,"generation":0,"tasks":[]}"#);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::UnsupportedVersion(77))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        write_private(&path, br#"{"format_version":1,"generation":0,"tasks":[]}"#);
        let (mut store, _) = TaskStore::open(&path).unwrap();
        store.create(task()).unwrap();
        drop(store);
        let current = fs::read_to_string(&path).unwrap();
        let future_record = current.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
        assert_ne!(current, future_record);
        write_private(&path, future_record.as_bytes());
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Model(
                TaskModelError::UnsupportedSchemaVersion(2)
            ))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_store_is_rejected_without_touching_its_target() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let target = dir.join("target.json");
        write_private(&target, b"untouched");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Corrupt)
        ));
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn broadly_readable_store_is_rejected_without_replacement() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        write_private(&path, br#"{"format_version":1,"generation":0,"tasks":[]}"#);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        cleanup(&dir);
    }

    #[test]
    fn snapshot_keeps_local_binding_but_excludes_contents_and_raw_errors() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let task_id = store.create(task()).unwrap();
        store
            .transition(
                &task_id,
                TaskState::Failed,
                Some(TaskDiagnostic::new(
                    super::super::task_model::TaskErrorCode::SourceUnavailable,
                    false,
                )),
                5,
            )
            .unwrap();
        let bytes = fs::read(&path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(task_id.as_str()));
        assert!(text.contains("sensitive-source.bin"));
        assert!(!text.contains("file-content-bytes"));
        assert!(!text.contains("remote-secret-path"));
        assert!(!text.contains("raw error"));
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn progress_hints_remain_volatile_until_an_explicit_coalesced_flush() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let task_id = store.create(task()).unwrap();
        store
            .set_progress_hint(&task_id, ProgressHint::new(4, 100))
            .unwrap();
        assert_eq!(
            store
                .task(&task_id)
                .unwrap()
                .progress_hint()
                .unwrap()
                .verified_bytes(),
            4
        );
        drop(store);

        let (reopened, _) = TaskStore::open(&path).unwrap();
        assert!(reopened.task(&task_id).unwrap().progress_hint().is_none());
        drop(reopened);
        cleanup(&dir);
    }

    #[test]
    fn recovery_lookup_uses_task_id_and_existing_local_binding_only() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let task_id = store.create(task()).unwrap();
        let recovery = task_recovery::sender_recovery(&store, &task_id).unwrap_err();
        assert!(matches!(
            recovery,
            TaskStoreError::Model(TaskModelError::NotRecoverable)
        ));
        transition_to_state(&mut store, &task_id, TaskState::Paused, false);
        let stored = store.task(&task_id).unwrap();
        let recovery = task_recovery::sender_recovery(&store, &task_id).unwrap();
        assert_eq!(recovery.task_id(), &task_id);
        assert_eq!(recovery.peer_id(), stored.peer_id());
        assert_eq!(recovery.source_path(), stored.local_path());
        assert_eq!(recovery.manifest_identity(), stored.manifest_identity());
        assert_eq!(recovery.state(), TaskState::Paused);
        assert_eq!(store.task(&task_id).unwrap(), stored);
        assert!(matches!(
            task_recovery::receiver_recovery(&store, &task_id),
            Err(TaskStoreError::Model(TaskModelError::WrongDirection))
        ));
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn sender_recovery_rejects_queued_without_mutating_the_task() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let task_id = store.create(task()).unwrap();
        transition_to_state(&mut store, &task_id, TaskState::Queued, false);
        let before = store.task(&task_id).unwrap();

        assert!(matches!(
            task_recovery::sender_recovery(&store, &task_id),
            Err(TaskStoreError::Model(TaskModelError::NotRecoverable))
        ));
        assert_eq!(store.task(&task_id).unwrap(), before);
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn receiver_recovery_rejects_queued_without_mutating_the_task() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let task_id = store.create(receiver_task()).unwrap();
        transition_to_state(&mut store, &task_id, TaskState::Queued, false);
        let before = store.task(&task_id).unwrap();

        assert!(matches!(
            task_recovery::receiver_recovery(&store, &task_id),
            Err(TaskStoreError::Model(TaskModelError::NotRecoverable))
        ));
        assert_eq!(store.task(&task_id).unwrap(), before);
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn recovery_state_matrix_allows_only_explicit_recovery_sources_read_only() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let cases = [
            (TaskState::Scanning, false, false),
            (TaskState::Queued, false, false),
            (TaskState::Connecting, false, false),
            (TaskState::Negotiating, false, false),
            (TaskState::Transferring, false, false),
            (TaskState::Pausing, false, false),
            (TaskState::Paused, false, true),
            (TaskState::Finalizing, false, false),
            (TaskState::Completed, false, false),
            (TaskState::Interrupted, false, true),
            (TaskState::Failed, false, false),
            (TaskState::Failed, true, true),
        ];

        for (state, retryable_failure, should_recover) in cases {
            for direction in [TaskDirection::Send, TaskDirection::Receive] {
                let task_id = store.create(task_for_direction(direction)).unwrap();
                transition_to_state(&mut store, &task_id, state, retryable_failure);
                let before = store.task(&task_id).unwrap();
                let result = match direction {
                    TaskDirection::Send => {
                        task_recovery::sender_recovery(&store, &task_id).map(|recovery| {
                            assert_eq!(recovery.task_id(), &task_id);
                            assert_eq!(recovery.peer_id(), before.peer_id());
                            assert_eq!(recovery.source_path(), before.local_path());
                            assert_eq!(recovery.manifest_identity(), before.manifest_identity());
                            assert_eq!(recovery.state(), before.state());
                        })
                    }
                    TaskDirection::Receive => task_recovery::receiver_recovery(&store, &task_id)
                        .map(|recovery| {
                            assert_eq!(recovery.task_id(), &task_id);
                            assert_eq!(recovery.peer_id(), before.peer_id());
                            assert_eq!(recovery.receive_root(), before.local_path());
                            assert_eq!(recovery.manifest_identity(), before.manifest_identity());
                            assert_eq!(recovery.state(), before.state());
                        }),
                };

                if should_recover {
                    assert!(result.is_ok(), "{direction:?} recovery for {state:?}");
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(TaskStoreError::Model(TaskModelError::NotRecoverable))
                        ),
                        "{direction:?} recovery for {state:?}"
                    );
                }
                assert_eq!(store.task(&task_id).unwrap(), before);

                let wrong_direction = match direction {
                    TaskDirection::Send => {
                        task_recovery::receiver_recovery(&store, &task_id).map(|_| ())
                    }
                    TaskDirection::Receive => {
                        task_recovery::sender_recovery(&store, &task_id).map(|_| ())
                    }
                };
                assert!(matches!(
                    wrong_direction,
                    Err(TaskStoreError::Model(TaskModelError::WrongDirection))
                ));
                assert_eq!(store.task(&task_id).unwrap(), before);
            }
        }

        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn paused_restart_roundtrip_preserves_identity_binding_manifest_state_and_diagnostic() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let task_id = store.create(task()).unwrap();
        store
            .transition(&task_id, TaskState::Queued, None, 10)
            .unwrap();
        store
            .transition(&task_id, TaskState::Connecting, None, 11)
            .unwrap();
        store
            .transition(&task_id, TaskState::Negotiating, None, 12)
            .unwrap();
        store
            .transition(&task_id, TaskState::Transferring, None, 13)
            .unwrap();
        store
            .transition(
                &task_id,
                TaskState::Failed,
                Some(TaskDiagnostic::new(
                    super::super::task_model::TaskErrorCode::NetworkInterrupted,
                    true,
                )),
                14,
            )
            .unwrap();
        store
            .transition(&task_id, TaskState::Queued, None, 15)
            .unwrap();
        store
            .transition(&task_id, TaskState::Connecting, None, 16)
            .unwrap();
        store
            .transition(&task_id, TaskState::Negotiating, None, 17)
            .unwrap();
        store
            .transition(&task_id, TaskState::Transferring, None, 18)
            .unwrap();
        store
            .transition(&task_id, TaskState::Pausing, None, 19)
            .unwrap();
        store
            .transition(
                &task_id,
                TaskState::Paused,
                Some(TaskDiagnostic::new(
                    super::super::task_model::TaskErrorCode::NetworkInterrupted,
                    true,
                )),
                20,
            )
            .unwrap();
        let record = store.task(&task_id).unwrap();
        let peer_id = record.peer_id().clone();
        let local_path = record.local_path().to_path_buf();
        let manifest = record.manifest_identity().clone();
        store
            .set_progress_hint(&task_id, ProgressHint::new(8, 21))
            .unwrap();
        store.flush_progress_hints().unwrap();
        drop(store);

        let (reopened, report) = TaskStore::open(&path).unwrap();
        let restored = reopened.task(&task_id).unwrap();
        assert!(report.interrupted_task_ids().is_empty());
        assert_eq!(restored.task_id(), &task_id);
        assert_eq!(restored.peer_id(), &peer_id);
        assert_eq!(restored.local_path(), local_path);
        assert_eq!(restored.manifest_identity(), &manifest);
        assert_eq!(restored.state(), TaskState::Paused);
        assert_eq!(
            restored.diagnostic().unwrap().code(),
            super::super::task_model::TaskErrorCode::NetworkInterrupted
        );
        assert_eq!(restored.progress_hint().unwrap().verified_bytes(), 8);
        drop(reopened);
        cleanup(&dir);
    }

    #[test]
    fn receiver_recovery_uses_only_the_stored_local_receive_root() {
        let dir = temp_dir();
        let path = dir.join("tasks.json");
        let (mut store, _) = TaskStore::open(&path).unwrap();
        let peer_id = super::super::task_model::PeerId::from_node_id(NodeId::from_public_key(
            &Identity::generate().public_key(),
        ));
        let receive_root = if cfg!(windows) {
            PathBuf::from(r"C:\Users\user\Downloads")
        } else {
            PathBuf::from("/Users/user/Downloads")
        };
        let record = TaskRecord::new_receiver(
            peer_id.clone(),
            receive_root.clone(),
            super::super::task_model::ManifestIdentity::blake3([5; 32], 8, 4).unwrap(),
        )
        .unwrap();
        let task_id = store.create(record).unwrap();
        transition_to_state(&mut store, &task_id, TaskState::Paused, false);
        let stored = store.task(&task_id).unwrap();
        let recovery = task_recovery::receiver_recovery(&store, &task_id).unwrap();
        assert_eq!(recovery.task_id(), &task_id);
        assert_eq!(recovery.peer_id(), &peer_id);
        assert_eq!(recovery.receive_root(), receive_root);
        assert_eq!(recovery.receive_root(), stored.local_path());
        assert_eq!(recovery.state(), TaskState::Paused);
        assert_eq!(store.task(&task_id).unwrap(), stored);
        assert!(matches!(
            task_recovery::sender_recovery(&store, &task_id),
            Err(TaskStoreError::Model(TaskModelError::WrongDirection))
        ));
        drop(store);
        cleanup(&dir);
    }
}
