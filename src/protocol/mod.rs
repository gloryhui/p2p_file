//! 应用层协议：控制消息、文件清单、帧编解码。

pub mod frame;
pub mod manifest;
pub mod message;

pub use frame::{MAX_FRAME_LEN, read_frame, read_raw_frame, write_frame, write_raw_frame};
pub use manifest::{ChunkHash, DEFAULT_CHUNK_SIZE, FileManifest};
pub use message::{ControlMessage, PROTOCOL_VERSION};
