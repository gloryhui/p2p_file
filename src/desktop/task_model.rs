//! Durable desktop task identities and lifecycle model for T003.
//!
//! This module contains local domain data only. It does not implement transfer
//! or network behavior. Recovery APIs take a TaskId and use the already stored
//! local source/receive root; callers cannot supply a remote filesystem path.

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::NodeId;

pub const TASK_RECORD_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TaskModelError {
    #[error("task ID must be 32 lowercase hexadecimal characters")]
    InvalidTaskId,
    #[error("peer ID is invalid")]
    InvalidPeerId,
    #[error("manifest identity is invalid")]
    InvalidManifestIdentity,
    #[error("local task path must be an absolute path")]
    RelativeLocalPath,
    #[error("local task path does not match the task direction")]
    DirectionPathMismatch,
    #[error("task record has an unsupported schema version: {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("task record timestamps are invalid")]
    InvalidTimestamps,
    #[error("task progress hint fields are invalid")]
    InvalidProgressHint,
    #[error("a Failed task requires a diagnostic")]
    MissingFailureDiagnostic,
    #[error("a new task must be persisted in Scanning before it can be queued")]
    NewTaskMustStartScanning,
    #[error("task state transition is not allowed: {from:?} -> {to:?}")]
    InvalidTransition { from: TaskState, to: TaskState },
    #[error("task direction does not match the requested recovery API")]
    WrongDirection,
    #[error("task is not in a recoverable state")]
    NotRecoverable,
    #[error("task binding fields are immutable")]
    ImmutableBinding,
    #[error("system clock is outside the supported timestamp range")]
    ClockOutOfRange,
}

/// Stable, random 128-bit task identifier, rendered as canonical lowercase hex.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TaskId(String);

impl TaskId {
    pub fn generate() -> Self {
        Self(hex::encode(rand::random::<[u8; 16]>()))
    }

    pub fn parse(value: &str) -> Result<Self, TaskModelError> {
        Self::try_from(value.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TaskId {
    type Error = TaskModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || hex::decode(&value).map_or(true, |bytes| bytes.len() != 16)
        {
            return Err(TaskModelError::InvalidTaskId);
        }
        Ok(Self(value))
    }
}

impl From<TaskId> for String {
    fn from(value: TaskId) -> Self {
        value.0
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated, stable peer binding persisted as the existing 128-bit NodeId.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PeerId(String);

impl PeerId {
    pub fn from_node_id(node_id: NodeId) -> Self {
        Self(node_id.to_hex())
    }

    pub fn parse(value: &str) -> Result<Self, TaskModelError> {
        Self::try_from(value.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PeerId {
    type Error = TaskModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let decoded = hex::decode(&value).map_err(|_| TaskModelError::InvalidPeerId)?;
        if decoded.len() != 16
            || value.len() != 32
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(TaskModelError::InvalidPeerId);
        }
        Ok(Self(value))
    }
}

impl From<PeerId> for String {
    fn from(value: PeerId) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestHashAlgorithm {
    Blake3V1,
}

/// Stable reference to the content manifest, without embedding file contents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestIdentity {
    algorithm: ManifestHashAlgorithm,
    root_hash: String,
    total_bytes: u64,
    chunk_size: u32,
    chunk_count: u64,
}

impl ManifestIdentity {
    pub fn blake3(
        root_hash: [u8; 32],
        total_bytes: u64,
        chunk_size: u32,
    ) -> Result<Self, TaskModelError> {
        if chunk_size == 0 {
            return Err(TaskModelError::InvalidManifestIdentity);
        }
        let identity = Self {
            algorithm: ManifestHashAlgorithm::Blake3V1,
            root_hash: hex::encode(root_hash),
            total_bytes,
            chunk_size,
            chunk_count: total_bytes.div_ceil(u64::from(chunk_size)),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn algorithm(&self) -> ManifestHashAlgorithm {
        self.algorithm
    }

    pub fn root_hash_hex(&self) -> &str {
        &self.root_hash
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    pub(crate) fn validate(&self) -> Result<(), TaskModelError> {
        if !matches!(self.algorithm(), ManifestHashAlgorithm::Blake3V1)
            || self.root_hash_hex().len() != 64
            || !self
                .root_hash_hex()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || hex::decode(self.root_hash_hex()).map_or(true, |bytes| bytes.len() != 32)
            || self.chunk_size() == 0
            || self.chunk_count() != self.total_bytes().div_ceil(u64::from(self.chunk_size()))
        {
            return Err(TaskModelError::InvalidManifestIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskDirection {
    Send,
    Receive,
}

/// Locally authorized path only. This type is never constructed from protocol data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "path", rename_all = "snake_case")]
pub enum LocalTaskPath {
    Source(PathBuf),
    ReceiveRoot(PathBuf),
}

impl LocalTaskPath {
    pub fn source(path: PathBuf) -> Result<Self, TaskModelError> {
        if !path.is_absolute() {
            return Err(TaskModelError::RelativeLocalPath);
        }
        Ok(Self::Source(path))
    }

    pub fn receive_root(path: PathBuf) -> Result<Self, TaskModelError> {
        if !path.is_absolute() {
            return Err(TaskModelError::RelativeLocalPath);
        }
        Ok(Self::ReceiveRoot(path))
    }

    pub fn path(&self) -> &std::path::Path {
        match self {
            Self::Source(path) | Self::ReceiveRoot(path) => path,
        }
    }

    pub fn is_sender_source(&self) -> bool {
        matches!(self, Self::Source(_))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Scanning,
    Queued,
    Connecting,
    Negotiating,
    Transferring,
    Pausing,
    Paused,
    Finalizing,
    Completed,
    Interrupted,
    Failed,
}

impl TaskState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }

    pub(crate) fn needs_startup_recovery(self) -> bool {
        matches!(
            self,
            Self::Scanning
                | Self::Queued
                | Self::Connecting
                | Self::Negotiating
                | Self::Transferring
                | Self::Pausing
                | Self::Finalizing
        )
    }

    fn allows(self, next: Self, retryable_failure: bool) -> bool {
        use TaskState::*;
        matches!(
            (self, next),
            (Scanning, Queued | Interrupted | Failed)
                | (Queued, Connecting | Pausing | Interrupted | Failed)
                | (Connecting, Negotiating | Pausing | Interrupted | Failed)
                | (Negotiating, Transferring | Pausing | Interrupted | Failed)
                | (Transferring, Pausing | Finalizing | Interrupted | Failed)
                | (Pausing, Paused | Interrupted | Failed)
                | (Paused, Queued | Interrupted | Failed)
                | (Finalizing, Completed | Interrupted | Failed)
                | (Interrupted, Queued | Failed)
        ) || (self == Failed && next == Queued && retryable_failure)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskErrorCode {
    SourceUnavailable,
    SourceChanged,
    PeerUnavailable,
    PermissionDenied,
    DiskFull,
    IntegrityMismatch,
    InvalidRemoteData,
    UnsupportedPeer,
    NetworkInterrupted,
    ApplicationRestarted,
    StorageUnavailable,
    UserCancelled,
    Other,
}

/// Safe diagnostic classification. Persist only a code and retryability bit,
/// never raw errors, paths, secrets, or transfer contents.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDiagnostic {
    code: TaskErrorCode,
    retryable: bool,
}

impl TaskDiagnostic {
    pub fn new(code: TaskErrorCode, retryable: bool) -> Self {
        Self { code, retryable }
    }

    pub fn code(self) -> TaskErrorCode {
        self.code
    }

    pub fn is_retryable(self) -> bool {
        self.retryable
    }

    pub fn safe_message(self) -> &'static str {
        match self.code {
            TaskErrorCode::SourceUnavailable => "本机源文件不可用",
            TaskErrorCode::SourceChanged => "本机源文件内容已变化",
            TaskErrorCode::PeerUnavailable => "对端当前不可用",
            TaskErrorCode::PermissionDenied => "本机目录权限不足",
            TaskErrorCode::DiskFull => "本机磁盘空间不足",
            TaskErrorCode::IntegrityMismatch => "内容完整性校验失败",
            TaskErrorCode::InvalidRemoteData => "对端数据无效",
            TaskErrorCode::UnsupportedPeer => "对端不支持此任务能力",
            TaskErrorCode::NetworkInterrupted => "网络连接中断",
            TaskErrorCode::ApplicationRestarted => "应用退出时任务被中断",
            TaskErrorCode::StorageUnavailable => "任务存储不可用",
            TaskErrorCode::UserCancelled => "任务已取消",
            TaskErrorCode::Other => "任务失败，详情不可用",
        }
    }
}

/// A display-only progress estimate. It is not authoritative over receiver
/// bitmap/checkpoint data and is intentionally flushed only at an explicit,
/// coalesced store boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressHint {
    verified_bytes: u64,
    sampled_at_unix_ms: i64,
}

impl ProgressHint {
    pub fn new(verified_bytes: u64, sampled_at_unix_ms: i64) -> Self {
        Self {
            verified_bytes,
            sampled_at_unix_ms,
        }
    }

    pub fn verified_bytes(self) -> u64 {
        self.verified_bytes
    }

    pub fn sampled_at_unix_ms(self) -> i64 {
        self.sampled_at_unix_ms
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    schema_version: u32,
    task_id: TaskId,
    peer_id: PeerId,
    direction: TaskDirection,
    local_path: LocalTaskPath,
    manifest_identity: ManifestIdentity,
    state: TaskState,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    diagnostic: Option<TaskDiagnostic>,
    progress_hint: Option<ProgressHint>,
}

impl TaskRecord {
    pub fn new_sender(
        peer_id: PeerId,
        source_path: PathBuf,
        manifest_identity: ManifestIdentity,
    ) -> Result<Self, TaskModelError> {
        Self::new(
            TaskId::generate(),
            peer_id,
            TaskDirection::Send,
            LocalTaskPath::source(source_path)?,
            manifest_identity,
            system_time_unix_ms()?,
        )
    }

    pub fn new_receiver(
        peer_id: PeerId,
        receive_root: PathBuf,
        manifest_identity: ManifestIdentity,
    ) -> Result<Self, TaskModelError> {
        Self::new(
            TaskId::generate(),
            peer_id,
            TaskDirection::Receive,
            LocalTaskPath::receive_root(receive_root)?,
            manifest_identity,
            system_time_unix_ms()?,
        )
    }

    fn new(
        task_id: TaskId,
        peer_id: PeerId,
        direction: TaskDirection,
        local_path: LocalTaskPath,
        manifest_identity: ManifestIdentity,
        now: i64,
    ) -> Result<Self, TaskModelError> {
        let record = Self {
            schema_version: TASK_RECORD_SCHEMA_VERSION,
            task_id,
            peer_id,
            direction,
            local_path,
            manifest_identity,
            state: TaskState::Scanning,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            diagnostic: None,
            progress_hint: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn direction(&self) -> TaskDirection {
        self.direction
    }

    pub fn local_path(&self) -> &std::path::Path {
        self.local_path.path()
    }

    pub fn manifest_identity(&self) -> &ManifestIdentity {
        &self.manifest_identity
    }

    pub fn state(&self) -> TaskState {
        self.state
    }

    pub fn created_at_unix_ms(&self) -> i64 {
        self.created_at_unix_ms
    }

    pub fn updated_at_unix_ms(&self) -> i64 {
        self.updated_at_unix_ms
    }

    pub fn diagnostic(&self) -> Option<TaskDiagnostic> {
        self.diagnostic
    }

    pub fn progress_hint(&self) -> Option<ProgressHint> {
        self.progress_hint
    }

    pub(crate) fn validate(&self) -> Result<(), TaskModelError> {
        if self.schema_version != TASK_RECORD_SCHEMA_VERSION {
            return Err(TaskModelError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        self.manifest_identity.validate()?;
        if !self.local_path.path().is_absolute() {
            return Err(TaskModelError::RelativeLocalPath);
        }
        if (self.direction == TaskDirection::Send) != self.local_path.is_sender_source() {
            return Err(TaskModelError::DirectionPathMismatch);
        }
        if self.created_at_unix_ms < 0 || self.updated_at_unix_ms < self.created_at_unix_ms {
            return Err(TaskModelError::InvalidTimestamps);
        }
        if self.progress_hint.is_some_and(|hint| {
            hint.verified_bytes > self.manifest_identity.total_bytes || hint.sampled_at_unix_ms < 0
        }) {
            return Err(TaskModelError::InvalidProgressHint);
        }
        if self.state == TaskState::Failed && self.diagnostic.is_none() {
            return Err(TaskModelError::MissingFailureDiagnostic);
        }
        Ok(())
    }

    pub(crate) fn validate_binding_unchanged(&self, current: &Self) -> Result<(), TaskModelError> {
        if self.task_id != current.task_id
            || self.peer_id != current.peer_id
            || self.direction != current.direction
            || self.local_path != current.local_path
            || self.manifest_identity != current.manifest_identity
        {
            return Err(TaskModelError::ImmutableBinding);
        }
        Ok(())
    }

    pub(crate) fn transition_to(
        &mut self,
        next: TaskState,
        diagnostic: Option<TaskDiagnostic>,
        now: i64,
    ) -> Result<(), TaskModelError> {
        let retryable = self.diagnostic.is_some_and(TaskDiagnostic::is_retryable);
        if !self.state.allows(next, retryable) {
            return Err(TaskModelError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        if next == TaskState::Failed && diagnostic.is_none() {
            return Err(TaskModelError::MissingFailureDiagnostic);
        }
        let mut updated = self.clone();
        updated.state = next;
        if next == TaskState::Queued {
            updated.diagnostic = None;
        } else if diagnostic.is_some() {
            updated.diagnostic = diagnostic;
        }
        updated.updated_at_unix_ms = now
            .max(updated.created_at_unix_ms)
            .max(updated.updated_at_unix_ms);
        updated.validate()?;
        *self = updated;
        Ok(())
    }

    pub(crate) fn set_progress_hint(&mut self, hint: ProgressHint) -> Result<(), TaskModelError> {
        if hint.verified_bytes > self.manifest_identity.total_bytes || hint.sampled_at_unix_ms < 0 {
            return Err(TaskModelError::InvalidProgressHint);
        }
        self.progress_hint = Some(hint);
        Ok(())
    }

    pub(crate) fn task_id_owned(&self) -> TaskId {
        self.task_id.clone()
    }
}

pub(crate) fn system_time_unix_ms() -> Result<i64, TaskModelError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TaskModelError::ClockOutOfRange)?;
    i64::try_from(duration.as_millis()).map_err(|_| TaskModelError::ClockOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ManifestIdentity {
        ManifestIdentity::blake3([7; 32], 10, 4).unwrap()
    }

    fn peer() -> PeerId {
        PeerId::from_node_id(NodeId::from_public_key(
            &crate::identity::Identity::generate().public_key(),
        ))
    }

    fn test_path(relative: &str) -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(format!(r"C:\{}", relative.replace('/', "\\")))
        }
        #[cfg(not(windows))]
        {
            PathBuf::from(format!("/{relative}"))
        }
    }

    #[test]
    fn task_id_is_stable_canonical_and_random() {
        let first = TaskId::generate();
        let second = TaskId::generate();
        assert_ne!(first, second);
        assert_eq!(TaskId::parse(first.as_str()).unwrap(), first);
        assert!(TaskId::parse("ABCDEF00000000000000000000000000").is_err());
        assert!(TaskId::parse("not-a-task-id").is_err());
    }

    #[test]
    fn sender_and_receiver_bind_only_the_correct_local_path_kind() {
        let source = test_path("local/source.bin");
        let sender = TaskRecord::new_sender(peer(), source.clone(), manifest()).unwrap();
        assert_eq!(sender.direction(), TaskDirection::Send);
        assert_eq!(sender.state(), TaskState::Scanning);
        assert_eq!(sender.local_path(), source);

        let receive_root = test_path("local/Downloads");
        let receiver = TaskRecord::new_receiver(peer(), receive_root.clone(), manifest()).unwrap();
        assert_eq!(receiver.direction(), TaskDirection::Receive);
        assert_eq!(receiver.local_path(), receive_root);
        assert!(TaskRecord::new_sender(peer(), PathBuf::from("relative"), manifest()).is_err());
    }

    #[test]
    fn transition_table_rejects_skips_and_terminal_revival() {
        let mut task =
            TaskRecord::new_sender(peer(), test_path("local/source.bin"), manifest()).unwrap();
        assert!(
            task.transition_to(TaskState::Transferring, None, 1)
                .is_err()
        );
        assert_eq!(task.state(), TaskState::Scanning);
        task.transition_to(TaskState::Queued, None, 2).unwrap();
        task.transition_to(TaskState::Connecting, None, 3).unwrap();
        task.transition_to(TaskState::Negotiating, None, 4).unwrap();
        task.transition_to(TaskState::Transferring, None, 5)
            .unwrap();
        task.transition_to(TaskState::Finalizing, None, 6).unwrap();
        task.transition_to(TaskState::Completed, None, 7).unwrap();
        assert!(task.transition_to(TaskState::Queued, None, 8).is_err());
    }

    #[test]
    fn only_explicitly_retryable_failures_can_be_queued_again() {
        let mut task =
            TaskRecord::new_sender(peer(), test_path("local/source.bin"), manifest()).unwrap();
        task.transition_to(
            TaskState::Failed,
            Some(TaskDiagnostic::new(TaskErrorCode::NetworkInterrupted, true)),
            1,
        )
        .unwrap();
        task.transition_to(TaskState::Queued, None, 2).unwrap();
        assert!(task.diagnostic().is_none());

        task.transition_to(
            TaskState::Failed,
            Some(TaskDiagnostic::new(TaskErrorCode::IntegrityMismatch, false)),
            3,
        )
        .unwrap();
        assert!(task.transition_to(TaskState::Queued, None, 4).is_err());
    }

    #[test]
    fn diagnostics_have_fixed_safe_messages_not_raw_error_strings() {
        let diagnostic = TaskDiagnostic::new(TaskErrorCode::SourceUnavailable, true);
        assert_eq!(diagnostic.safe_message(), "本机源文件不可用");
    }

    #[test]
    fn immutable_task_binding_rejects_path_replacement() {
        let original =
            TaskRecord::new_sender(peer(), test_path("local/source.bin"), manifest()).unwrap();
        let mut rebound = original.clone();
        rebound.local_path = LocalTaskPath::source(test_path("local/other.bin")).unwrap();
        assert_eq!(
            rebound.validate_binding_unchanged(&original),
            Err(TaskModelError::ImmutableBinding)
        );
    }
}
