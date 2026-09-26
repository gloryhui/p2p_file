//! Versioned desktop-only framing and protocol guards. No filesystem operations.
//!
//! The legacy ControlMessage enum and CLI wire protocol remain unchanged.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::protocol::frame::{read_raw_frame_limited, write_raw_frame_limited};
use crate::protocol::manifest::{ChunkHash, FileManifest};

use super::task_model::TaskId;

pub const VERSION: u16 = 1;
pub const CAP_TASK_PROTOCOL: u64 = 1;
pub const CAP_RELATIVE_ENTRIES: u64 = 2;
pub const CAP_PAUSE_RESUME: u64 = 4;
pub const CAP_SPEED_OWNERSHIP: u64 = 8;
pub const REQUIRED_CAPABILITIES: u64 = 15;
pub const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_CHUNKS: usize = 65_536;
pub const MAX_TASKS_PER_PEER: usize = 128;
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAGIC: &[u8; 5] = b"P2PD\x01";

fn invalid(message: &str) -> Error {
    Error::Protocol(message.into())
}

/// Only portable relative names selected by the sender cross this boundary.
pub fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 4096 || path.split('/').count() > 64 {
        return Err(invalid("桌面相对路径长度或深度非法"));
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > 255
            || component.ends_with(['.', ' '])
            || component
                .chars()
                .any(|ch| ch.is_control() || "\\:<>\"|?*".contains(ch))
        {
            return Err(invalid("桌面相对路径包含非法组件"));
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            });
        if device {
            return Err(invalid("桌面相对路径包含保留设备名"));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Entry {
    File(Box<FileManifest>),
    Directory,
}

impl Entry {
    fn validate(&self, relative_path: &str) -> Result<()> {
        validate_relative_path(relative_path)?;
        if let Self::File(manifest) = self {
            manifest.validate()?;
            if manifest.chunks.len() > MAX_CHUNKS
                || manifest.total_len > (1u64 << 40)
                || Some(manifest.file_name.as_str()) != relative_path.rsplit('/').next()
            {
                return Err(invalid("桌面清单超限或文件名与相对路径不一致"));
            }
        }
        Ok(())
    }

    fn identity(&self, path: &str) -> (ChunkHash, usize) {
        match self {
            Self::File(manifest) => (manifest.root_hash, manifest.chunks.len()),
            Self::Directory => (ChunkHash::of(path.as_bytes()), 0),
        }
    }
}

/// Fixed error codes prevent accidental disclosure of local source/receive paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ErrorCode {
    UnsupportedVersion,
    UnsupportedCapability,
    UnknownTask,
    WrongPeer,
    InvalidState,
    InvalidPath,
    InvalidManifest,
    Busy,
    SourceChanged,
    SourceMissing,
    Storage,
    Interrupted,
}

/// Append variants only. Request ordering and task binding are checked by TaskProtocol.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Hello {
        version: u16,
        capabilities: u64,
    },
    Ready,
    Offer {
        task_id: TaskId,
        group_id: Option<TaskId>,
        relative_path: String,
        entry: Entry,
    },
    Resume {
        task_id: TaskId,
        root_hash: ChunkHash,
        have: Vec<u8>,
    },
    Pause {
        task_id: TaskId,
    },
    Paused {
        task_id: TaskId,
        pause_request_id: u64,
    },
    ResumeTask {
        task_id: TaskId,
    },
    Completed {
        task_id: TaskId,
        root_hash: ChunkHash,
        receipt_version: u16,
    },
    Error {
        task_id: TaskId,
        code: ErrorCode,
    },
    Speed(SpeedControl),
}

impl Message {
    fn task_id(&self) -> Option<&TaskId> {
        match self {
            Self::Hello { .. } | Self::Ready => None,
            Self::Speed(control) => Some(control.test_id()),
            Self::Offer { task_id, .. }
            | Self::Resume { task_id, .. }
            | Self::Pause { task_id }
            | Self::Paused { task_id, .. }
            | Self::ResumeTask { task_id }
            | Self::Completed { task_id, .. }
            | Self::Error { task_id, .. } => Some(task_id),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Offer {
                relative_path,
                entry,
                ..
            } => entry.validate(relative_path),
            Self::Speed(control) => control.validate(),
            Self::Resume { have, .. } if have.len() > MAX_CHUNKS.div_ceil(8) => {
                Err(invalid("桌面恢复位图超限"))
            }
            Self::Completed {
                receipt_version, ..
            } if *receipt_version != 1 => Err(invalid("不支持的完成回执版本")),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub request_id: u64,
    pub message: Message,
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(self)?);
        if bytes.len() > MAX_FRAME_BYTES as usize {
            return Err(invalid("桌面帧超限"));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FRAME_BYTES as usize {
            return Err(invalid("桌面帧超限"));
        }
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| invalid("对端不支持桌面协议"))?;
        let (frame, trailing): (Self, _) = postcard::take_from_bytes(payload)?;
        if !trailing.is_empty() {
            return Err(invalid("桌面帧含多余字节"));
        }
        frame.validate()?;
        Ok(frame)
    }

    fn validate(&self) -> Result<()> {
        if (self.message.task_id().is_some() && self.request_id == 0)
            || (self.message.task_id().is_none() && self.request_id != 0)
        {
            return Err(invalid("桌面请求编号非法"));
        }
        self.message.validate()
    }
}

pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let bytes = read_raw_frame_limited(reader, MAX_FRAME_BYTES)
        .await?
        .ok_or_else(|| invalid("桌面协议流已关闭"))?;
    Frame::decode(&bytes)
}

pub async fn write<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    write_raw_frame_limited(writer, &frame.encode()?, MAX_FRAME_BYTES).await
}

async fn exchange<S: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    send: &mut S,
    recv: &mut R,
) -> Result<()> {
    write(
        send,
        &Frame {
            request_id: 0,
            message: Message::Hello {
                version: VERSION,
                capabilities: REQUIRED_CAPABILITIES,
            },
        },
    )
    .await?;
    match read(recv).await?.message {
        Message::Hello {
            version,
            capabilities,
        } if version == VERSION
            && capabilities & REQUIRED_CAPABILITIES == REQUIRED_CAPABILITIES => {}
        _ => return Err(invalid("桌面版本或能力不兼容")),
    }
    write(
        send,
        &Frame {
            request_id: 0,
            message: Message::Ready,
        },
    )
    .await?;
    if read(recv).await?.message != Message::Ready {
        return Err(invalid("桌面能力确认顺序错误"));
    }
    Ok(())
}

/// Must only be called after the existing identity/channel-binding handshake.
pub async fn negotiate(connection: &quinn::Connection, initiator: bool) -> Result<()> {
    let result = tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
        let (mut send, mut recv) = if initiator {
            connection.open_bi().await
        } else {
            connection.accept_bi().await
        }
        .map_err(|_| invalid("桌面能力流不可用"))?;
        exchange(&mut send, &mut recv).await?;
        send.finish()
            .map_err(|_| invalid("桌面能力确认流关闭失败"))?;
        Ok::<(), Error>(())
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(()),
        _ => {
            connection.close(3u32.into(), b"desktop protocol incompatible");
            Err(invalid("桌面版本或能力不兼容，或协商超时"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Actor {
    Local,
    Remote,
}
impl Actor {
    fn index(self) -> usize {
        match self {
            Self::Local => 0,
            Self::Remote => 1,
        }
    }
    fn opposite(self) -> Self {
        match self {
            Self::Local => Self::Remote,
            Self::Remote => Self::Local,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireTaskState {
    Offered,
    Transferring,
    Pausing,
    Paused,
    Interrupted,
    ResumeRequested,
    Completed,
    Failed,
}

#[derive(Clone, Debug)]
struct Binding {
    sender: Actor,
    root: ChunkHash,
    chunks: usize,
    state: WireTaskState,
    sequence: [u64; 2],
    pauses: [Option<u64>; 2],
}

/// A connection's authenticated peer is fixed. There is no remote path lookup API.
#[derive(Debug)]
pub struct TaskProtocol {
    peer: NodeId,
    tasks: HashMap<TaskId, Binding>,
}

impl TaskProtocol {
    pub fn new(authenticated_peer: NodeId) -> Self {
        Self {
            peer: authenticated_peer,
            tasks: HashMap::new(),
        }
    }
    pub fn state(&self, task: &TaskId) -> Option<WireTaskState> {
        self.tasks.get(task).map(|binding| binding.state)
    }

    /// Caller restores only task IDs already authorized in its durable store.
    pub fn restore(
        &mut self,
        task: TaskId,
        sender: Actor,
        root: ChunkHash,
        chunks: usize,
        paused: bool,
    ) -> Result<()> {
        if self.tasks.len() >= MAX_TASKS_PER_PEER
            || self.tasks.contains_key(&task)
            || chunks > MAX_CHUNKS
        {
            return Err(invalid("已授权桌面任务恢复冲突或超限"));
        }
        self.tasks.insert(
            task,
            Binding {
                sender,
                root,
                chunks,
                state: if paused {
                    WireTaskState::Paused
                } else {
                    WireTaskState::Interrupted
                },
                sequence: [0; 2],
                pauses: [None; 2],
            },
        );
        Ok(())
    }

    /// Validate before any disk write or state mutation. Failed validation is atomic.
    pub fn observe(
        &mut self,
        authenticated_peer: NodeId,
        actor: Actor,
        frame: &Frame,
    ) -> Result<()> {
        if authenticated_peer != self.peer {
            return Err(invalid("桌面任务对端身份不符"));
        }
        frame.validate()?;
        let task = frame
            .message
            .task_id()
            .ok_or_else(|| invalid("业务流不能重复协商能力"))?;
        if let Message::Offer {
            relative_path,
            entry,
            ..
        } = &frame.message
        {
            if self.tasks.contains_key(task)
                || self.tasks.len() >= MAX_TASKS_PER_PEER
                || frame.request_id != 1
            {
                return Err(invalid("重复、乱序或超限的桌面 Offer"));
            }
            let (root, chunks) = entry.identity(relative_path);
            let mut sequence = [0; 2];
            sequence[actor.index()] = 1;
            self.tasks.insert(
                task.clone(),
                Binding {
                    sender: actor,
                    root,
                    chunks,
                    state: WireTaskState::Offered,
                    sequence,
                    pauses: [None; 2],
                },
            );
            return Ok(());
        }
        let mut binding = self
            .tasks
            .get(task)
            .cloned()
            .ok_or_else(|| invalid("未授权或未知的桌面任务"))?;
        if binding.sequence[actor.index()].checked_add(1) != Some(frame.request_id) {
            return Err(invalid("重复或乱序的桌面任务请求"));
        }
        match &frame.message {
            Message::Resume {
                root_hash, have, ..
            } => {
                if actor == binding.sender
                    || *root_hash != binding.root
                    || !matches!(
                        binding.state,
                        WireTaskState::Offered
                            | WireTaskState::ResumeRequested
                            | WireTaskState::Interrupted
                    )
                    || have.len() != binding.chunks.div_ceil(8)
                    || (binding.chunks % 8 != 0
                        && have
                            .last()
                            .is_some_and(|last| *last >> (binding.chunks % 8) != 0))
                {
                    return Err(invalid("恢复位图、清单身份或任务状态不符"));
                }
                binding.state = WireTaskState::Transferring;
            }
            Message::Pause { .. } => {
                if !matches!(
                    binding.state,
                    WireTaskState::Transferring | WireTaskState::Pausing
                ) || binding.pauses[actor.index()].is_some()
                {
                    return Err(invalid("暂停请求状态不符"));
                }
                binding.pauses[actor.index()] = Some(frame.request_id);
                binding.state = WireTaskState::Pausing;
            }
            Message::Paused {
                pause_request_id, ..
            } => {
                let request = &mut binding.pauses[actor.opposite().index()];
                if binding.state != WireTaskState::Pausing || *request != Some(*pause_request_id) {
                    return Err(invalid("暂停确认未绑定对应请求"));
                }
                *request = None;
                if binding.pauses == [None; 2] {
                    binding.state = WireTaskState::Paused;
                }
            }
            Message::ResumeTask { .. } => {
                if !matches!(
                    binding.state,
                    WireTaskState::Paused | WireTaskState::Interrupted
                ) {
                    return Err(invalid("只能继续已授权的暂停或中断任务"));
                }
                binding.state = WireTaskState::ResumeRequested;
            }
            Message::Completed { root_hash, .. } => {
                if actor == binding.sender
                    || binding.root != *root_hash
                    || !matches!(
                        binding.state,
                        WireTaskState::Transferring | WireTaskState::Pausing
                    )
                {
                    return Err(invalid("完成回执身份、方向或任务状态不符"));
                }
                binding.state = WireTaskState::Completed;
                binding.pauses = [None; 2];
            }
            Message::Error { .. } => {
                if matches!(
                    binding.state,
                    WireTaskState::Completed | WireTaskState::Failed
                ) {
                    return Err(invalid("终态任务不能重复失败"));
                }
                binding.state = WireTaskState::Failed;
            }
            _ => return Err(invalid("桌面消息顺序错误")),
        }
        binding.sequence[actor.index()] = frame.request_id;
        self.tasks.insert(task.clone(), binding);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SpeedDirection {
    Upload,
    Download,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpeedLease {
    pub test_id: TaskId,
    pub owner: NodeId,
    pub direction: SpeedDirection,
    pub seconds: u16,
    pub stream_token: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SpeedControl {
    Request {
        test_id: TaskId,
        direction: SpeedDirection,
        seconds: u16,
    },
    Granted(SpeedLease),
    Busy {
        test_id: TaskId,
    },
    Cancel(SpeedLease),
    Finished(SpeedLease),
}

impl SpeedControl {
    fn test_id(&self) -> &TaskId {
        match self {
            Self::Request { test_id, .. } | Self::Busy { test_id } => test_id,
            Self::Granted(lease) | Self::Cancel(lease) | Self::Finished(lease) => &lease.test_id,
        }
    }
    fn validate(&self) -> Result<()> {
        let seconds = match self {
            Self::Request { seconds, .. } => *seconds,
            Self::Granted(lease) | Self::Cancel(lease) | Self::Finished(lease) => lease.seconds,
            Self::Busy { .. } => return Ok(()),
        };
        validate_speed_seconds(seconds)
    }
}

fn validate_speed_seconds(seconds: u16) -> Result<()> {
    if seconds != 30 && (!(60..=600).contains(&seconds) || !seconds.is_multiple_of(60)) {
        return Err(invalid("测速时长非法"));
    }
    Ok(())
}

/// Only the lower NodeId grants leases. Both UIs route requests to that one owner.
/// T009 must keep one accept_uni dispatcher and claim its stream using this lease.
#[derive(Debug)]
pub struct SpeedArbiter {
    local: NodeId,
    peer: NodeId,
    active: Option<SpeedLease>,
    stream_claimed: bool,
}

impl SpeedArbiter {
    pub fn new(local: NodeId, peer: NodeId) -> Self {
        Self {
            local,
            peer,
            active: None,
            stream_claimed: false,
        }
    }
    pub fn request(
        &mut self,
        requester: NodeId,
        test_id: TaskId,
        direction: SpeedDirection,
        seconds: u16,
        active_files: usize,
    ) -> Result<SpeedLease> {
        if self.local >= self.peer {
            return Err(invalid("测速请求必须交给较小 NodeId 的协调者"));
        }
        if requester != self.local && requester != self.peer {
            return Err(invalid("测速请求对端身份不符"));
        }
        validate_speed_seconds(seconds)?;
        if active_files != 0 || self.active.is_some() {
            return Err(invalid("测速或文件任务正在进行"));
        }
        let lease = SpeedLease {
            test_id,
            owner: requester,
            direction,
            seconds,
            stream_token: rand::random(),
        };
        self.active = Some(lease.clone());
        self.stream_claimed = false;
        Ok(lease)
    }
    pub fn accept_grant(
        &mut self,
        authenticated_grantor: NodeId,
        lease: SpeedLease,
        active_files: usize,
    ) -> Result<()> {
        if self.peer >= self.local
            || authenticated_grantor != self.peer
            || (lease.owner != self.local && lease.owner != self.peer)
            || self.active.is_some()
            || active_files != 0
        {
            return Err(invalid("测速授权来源、归属或状态非法"));
        }
        validate_speed_seconds(lease.seconds)?;
        self.active = Some(lease);
        self.stream_claimed = false;
        Ok(())
    }

    pub fn claim_stream(&mut self, authenticated_sender: NodeId, lease: &SpeedLease) -> Result<()> {
        let source = match lease.direction {
            SpeedDirection::Upload => lease.owner,
            SpeedDirection::Download if lease.owner == self.local => self.peer,
            SpeedDirection::Download => self.local,
        };
        if self.active.as_ref() != Some(lease)
            || self.stream_claimed
            || authenticated_sender != source
        {
            return Err(invalid("测速数据流归属或令牌不符"));
        }
        self.stream_claimed = true;
        Ok(())
    }
    pub fn finish(&mut self, authenticated_actor: NodeId, lease: &SpeedLease) -> Result<()> {
        if (authenticated_actor != self.local && authenticated_actor != self.peer)
            || self.active.as_ref() != Some(lease)
        {
            return Err(invalid("测速任务身份不符"));
        }
        self.active = None;
        self.stream_claimed = false;
        Ok(())
    }
    pub fn can_start_file(&self) -> bool {
        self.active.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::protocol::manifest::{MIN_CHUNK_SIZE, root_hash_of};
    use crate::protocol::message::ControlMessage;
    use tokio::io::{AsyncWriteExt, split};

    fn task() -> TaskId {
        TaskId::parse("00112233445566778899aabbccddeeff").unwrap()
    }
    fn offer(id: TaskId) -> Frame {
        Frame {
            request_id: 1,
            message: Message::Offer {
                task_id: id,
                group_id: None,
                relative_path: "选定目录/empty.txt".into(),
                entry: Entry::File(Box::new(
                    FileManifest::new("empty.txt", 0, MIN_CHUNK_SIZE, vec![]).unwrap(),
                )),
            },
        }
    }
    fn transferring() -> (NodeId, TaskProtocol, ChunkHash) {
        let peer = Identity::generate().node_id();
        let mut gate = TaskProtocol::new(peer);
        let frame = offer(task());
        let root = if let Message::Offer {
            entry,
            relative_path,
            ..
        } = &frame.message
        {
            entry.identity(relative_path).0
        } else {
            unreachable!()
        };
        gate.observe(peer, Actor::Local, &frame).unwrap();
        gate.observe(
            peer,
            Actor::Remote,
            &Frame {
                request_id: 1,
                message: Message::Resume {
                    task_id: task(),
                    root_hash: root,
                    have: vec![],
                },
            },
        )
        .unwrap();
        (peer, gate, root)
    }

    #[test]
    fn golden_desktop_frames_and_legacy_discriminants_are_stable() {
        let hello = Frame {
            request_id: 0,
            message: Message::Hello {
                version: VERSION,
                capabilities: REQUIRED_CAPABILITIES,
            },
        };
        assert_eq!(hello.encode().unwrap(), b"P2PD\x01\x00\x00\x01\x0f");
        assert_eq!(
            Frame {
                request_id: 0,
                message: Message::Ready
            }
            .encode()
            .unwrap(),
            b"P2PD\x01\x00\x01"
        );
        let resume = Frame {
            request_id: 7,
            message: Message::ResumeTask { task_id: task() },
        };
        let mut expected = b"P2PD\x01\x07\x06\x20".to_vec();
        expected.extend_from_slice(task().as_str().as_bytes());
        assert_eq!(resume.encode().unwrap(), expected);
        assert_eq!(Frame::decode(&expected).unwrap(), resume);
        assert_eq!(ControlMessage::Ready.encode().unwrap(), [3]);
        assert_eq!(ControlMessage::Bye.encode().unwrap(), [15]);
        assert_eq!(ControlMessage::SpeedTestReady.encode().unwrap(), [17]);
        assert_eq!(
            ControlMessage::SpeedTestResult {
                bytes: 1,
                elapsed_ms: 2
            }
            .encode()
            .unwrap(),
            [18, 1, 2]
        );
        assert!(ControlMessage::decode(&hello.encode().unwrap()).is_err());
        assert!(Frame::decode(&ControlMessage::Ready.encode().unwrap()).is_err());
    }

    #[test]
    fn paths_are_relative_portable_and_never_silently_rewritten() {
        for path in ["文件夹/你好.txt", "a/b/c", "empty", "COM10.txt"] {
            validate_relative_path(path).unwrap();
        }
        for path in [
            "",
            "/a",
            "a/",
            "a//b",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "C:/x",
            "C:x",
            "//host/share",
            "a\\b",
            "x:stream",
            "nul.txt",
            "CON",
            "LPT9.bin",
            "COM¹",
            "a.",
            "a ",
            "a\0b",
            "a\nb",
            "a?b",
        ] {
            assert!(
                validate_relative_path(path).is_err(),
                "unsafe path accepted: {path:?}"
            );
        }
        assert!(validate_relative_path(&"a".repeat(256)).is_err());
        assert!(validate_relative_path(&vec!["a"; 65].join("/")).is_err());
    }

    #[test]
    fn malicious_manifest_path_trailing_bytes_and_bitmap_are_rejected() {
        let mut frame = offer(task());
        if let Message::Offer {
            entry: Entry::File(manifest),
            ..
        } = &mut frame.message
        {
            manifest.chunk_size = 0;
            manifest.root_hash = root_hash_of(&manifest.file_name, 0, 0, &[]);
        }
        let mut raw = MAGIC.to_vec();
        raw.extend(postcard::to_allocvec(&frame).unwrap());
        assert!(Frame::decode(&raw).is_err());
        let mut valid = offer(task()).encode().unwrap();
        valid.push(0);
        assert!(Frame::decode(&valid).is_err());
        let mut frame = offer(task());
        if let Message::Offer { relative_path, .. } = &mut frame.message {
            *relative_path = "private/other.txt".into();
        }
        assert!(frame.encode().is_err());
        assert!(
            Frame {
                request_id: 1,
                message: Message::Resume {
                    task_id: task(),
                    root_hash: ChunkHash::of(b"x"),
                    have: vec![0; MAX_CHUNKS.div_ceil(8) + 1]
                }
            }
            .encode()
            .is_err()
        );
    }

    #[tokio::test]
    async fn oversized_length_header_fails_without_waiting_for_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(8);
        writer
            .write_all(&(MAX_FRAME_BYTES + 1).to_le_bytes())
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_millis(100), read(&mut reader))
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }

    #[tokio::test]
    async fn capability_exchange_requires_both_hello_and_ready() {
        let (a, b) = tokio::io::duplex(128);
        let (mut ar, mut aw) = split(a);
        let (mut br, mut bw) = split(b);
        let (a, b) = tokio::join!(exchange(&mut aw, &mut ar), exchange(&mut bw, &mut br));
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn unsupported_version_missing_capability_and_old_cli_are_explicit_errors() {
        for response in [
            Frame {
                request_id: 0,
                message: Message::Hello {
                    version: 99,
                    capabilities: REQUIRED_CAPABILITIES,
                },
            }
            .encode()
            .unwrap(),
            Frame {
                request_id: 0,
                message: Message::Hello {
                    version: VERSION,
                    capabilities: CAP_TASK_PROTOCOL,
                },
            }
            .encode()
            .unwrap(),
            ControlMessage::Ready.encode().unwrap(),
        ] {
            let (a, b) = tokio::io::duplex(128);
            let (mut ar, mut aw) = split(a);
            let (mut br, mut bw) = split(b);
            let remote = async {
                read(&mut br).await.unwrap();
                write_raw_frame_limited(&mut bw, &response, MAX_FRAME_BYTES)
                    .await
                    .unwrap();
            };
            let (result, ()) = tokio::join!(exchange(&mut aw, &mut ar), remote);
            assert!(matches!(result, Err(Error::Protocol(_))));
        }
    }

    #[test]
    fn peer_task_sequence_and_direction_are_enforced_without_mutating_on_error() {
        let (peer, mut gate, root) = transferring();
        let pause = Frame {
            request_id: 2,
            message: Message::Pause { task_id: task() },
        };
        assert!(
            gate.observe(Identity::generate().node_id(), Actor::Remote, &pause)
                .is_err()
        );
        assert!(
            gate.observe(
                peer,
                Actor::Local,
                &Frame {
                    request_id: 4,
                    ..pause.clone()
                }
            )
            .is_err()
        );
        assert!(
            gate.observe(
                peer,
                Actor::Remote,
                &Frame {
                    request_id: 2,
                    message: Message::Pause {
                        task_id: TaskId::generate()
                    }
                }
            )
            .is_err()
        );
        assert!(
            gate.observe(
                peer,
                Actor::Local,
                &Frame {
                    request_id: 2,
                    message: Message::Completed {
                        task_id: task(),
                        root_hash: root,
                        receipt_version: 1
                    }
                }
            )
            .is_err()
        );
        assert_eq!(gate.state(&task()), Some(WireTaskState::Transferring));
        gate.observe(peer, Actor::Local, &pause).unwrap();
        assert!(gate.observe(peer, Actor::Local, &pause).is_err());
        assert!(
            gate.observe(
                peer,
                Actor::Remote,
                &Frame {
                    request_id: 2,
                    message: Message::Paused {
                        task_id: task(),
                        pause_request_id: 99
                    }
                }
            )
            .is_err()
        );
        assert_eq!(gate.state(&task()), Some(WireTaskState::Pausing));
        gate.observe(
            peer,
            Actor::Remote,
            &Frame {
                request_id: 2,
                message: Message::Paused {
                    task_id: task(),
                    pause_request_id: 2,
                },
            },
        )
        .unwrap();
        assert_eq!(gate.state(&task()), Some(WireTaskState::Paused));
        gate.observe(
            peer,
            Actor::Remote,
            &Frame {
                request_id: 3,
                message: Message::ResumeTask { task_id: task() },
            },
        )
        .unwrap();
        assert_eq!(gate.state(&task()), Some(WireTaskState::ResumeRequested));
    }

    #[test]
    fn simultaneous_pause_requires_both_bound_acknowledgements_and_completion_wins_race() {
        let (peer, mut gate, root) = transferring();
        for actor in [Actor::Local, Actor::Remote] {
            gate.observe(
                peer,
                actor,
                &Frame {
                    request_id: 2,
                    message: Message::Pause { task_id: task() },
                },
            )
            .unwrap();
        }
        gate.observe(
            peer,
            Actor::Local,
            &Frame {
                request_id: 3,
                message: Message::Paused {
                    task_id: task(),
                    pause_request_id: 2,
                },
            },
        )
        .unwrap();
        assert_eq!(gate.state(&task()), Some(WireTaskState::Pausing));
        gate.observe(
            peer,
            Actor::Remote,
            &Frame {
                request_id: 3,
                message: Message::Paused {
                    task_id: task(),
                    pause_request_id: 2,
                },
            },
        )
        .unwrap();
        assert_eq!(gate.state(&task()), Some(WireTaskState::Paused));
        let (peer, mut gate, _) = transferring();
        gate.observe(
            peer,
            Actor::Local,
            &Frame {
                request_id: 2,
                message: Message::Pause { task_id: task() },
            },
        )
        .unwrap();
        gate.observe(
            peer,
            Actor::Remote,
            &Frame {
                request_id: 2,
                message: Message::Completed {
                    task_id: task(),
                    root_hash: root,
                    receipt_version: 1,
                },
            },
        )
        .unwrap();
        assert_eq!(gate.state(&task()), Some(WireTaskState::Completed));
        assert!(
            gate.observe(
                peer,
                Actor::Remote,
                &Frame {
                    request_id: 3,
                    message: Message::Paused {
                        task_id: task(),
                        pause_request_id: 2
                    }
                }
            )
            .is_err()
        );
    }

    #[test]
    fn resume_only_uses_pre_authorized_ids_and_bounds_task_resources() {
        let peer = Identity::generate().node_id();
        let mut gate = TaskProtocol::new(peer);
        let resume = Frame {
            request_id: 1,
            message: Message::ResumeTask { task_id: task() },
        };
        assert!(gate.observe(peer, Actor::Remote, &resume).is_err());
        gate.restore(task(), Actor::Local, ChunkHash::of(b"content"), 1, true)
            .unwrap();
        gate.observe(peer, Actor::Remote, &resume).unwrap();
        for _ in 1..MAX_TASKS_PER_PEER {
            gate.observe(peer, Actor::Local, &offer(TaskId::generate()))
                .unwrap();
        }
        assert!(
            gate.observe(peer, Actor::Local, &offer(TaskId::generate()))
                .is_err()
        );
    }

    #[test]
    fn resume_bitmap_checks_identity_exact_length_and_unused_bits() {
        let peer = Identity::generate().node_id();
        let mut gate = TaskProtocol::new(peer);
        let root = ChunkHash::of(b"content");
        gate.restore(task(), Actor::Local, root, 1, false).unwrap();
        for (root_hash, have) in [
            (ChunkHash::of(b"wrong"), vec![1]),
            (root, vec![]),
            (root, vec![2]),
            (root, vec![1, 0]),
        ] {
            assert!(
                gate.observe(
                    peer,
                    Actor::Remote,
                    &Frame {
                        request_id: 1,
                        message: Message::Resume {
                            task_id: task(),
                            root_hash,
                            have
                        }
                    }
                )
                .is_err()
            );
        }
        gate.observe(
            peer,
            Actor::Remote,
            &Frame {
                request_id: 1,
                message: Message::Resume {
                    task_id: task(),
                    root_hash: root,
                    have: vec![1],
                },
            },
        )
        .unwrap();
    }

    #[test]
    fn only_one_speed_coordinator_can_grant_and_stream_claim_is_bound() {
        let a = Identity::generate().node_id();
        let b = Identity::generate().node_id();
        let (lower, higher) = if a < b { (a, b) } else { (b, a) };
        let mut coordinator = SpeedArbiter::new(lower, higher);
        let mut follower = SpeedArbiter::new(higher, lower);
        assert!(
            follower
                .request(higher, task(), SpeedDirection::Upload, 30, 0)
                .is_err()
        );
        assert!(
            coordinator
                .request(higher, task(), SpeedDirection::Upload, 30, 1)
                .is_err()
        );
        assert!(
            coordinator
                .request(higher, task(), SpeedDirection::Upload, 31, 0)
                .is_err()
        );
        let lease = coordinator
            .request(higher, task(), SpeedDirection::Upload, 600, 0)
            .unwrap();
        assert!(!coordinator.can_start_file());
        assert!(
            coordinator
                .request(lower, TaskId::generate(), SpeedDirection::Download, 30, 0)
                .is_err()
        );
        let mut stale = lease.clone();
        stale.stream_token[0] ^= 1;
        assert!(coordinator.claim_stream(higher, &stale).is_err());
        assert!(coordinator.claim_stream(lower, &lease).is_err());
        coordinator.claim_stream(higher, &lease).unwrap();
        assert!(coordinator.claim_stream(higher, &lease).is_err());
        assert!(coordinator.finish(higher, &stale).is_err());
        assert!(
            coordinator
                .finish(Identity::generate().node_id(), &lease)
                .is_err()
        );
        follower.accept_grant(lower, lease.clone(), 0).unwrap();
        assert!(!follower.can_start_file());
        assert!(follower.accept_grant(lower, lease.clone(), 0).is_err());
        coordinator.finish(higher, &lease).unwrap();
        follower.finish(lower, &lease).unwrap();
        let new_lease = coordinator
            .request(higher, task(), SpeedDirection::Upload, 30, 0)
            .unwrap();
        assert!(coordinator.finish(higher, &lease).is_err());
        coordinator.finish(higher, &new_lease).unwrap();
        assert!(coordinator.can_start_file());
    }
}
