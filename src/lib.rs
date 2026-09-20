//! p2p_file —— 点对点文件传输。
//!
//! 模块划分见 `docs/ARCHITECTURE.md`：
//!
//! - [`identity`]   长期密钥与节点 ID
//! - [`protocol`]   应用层消息、文件清单、帧编解码
//! - [`nat`]        STUN 查询、NAT 类型判定、打洞、端口映射
//! - [`discovery`]  局域网 mDNS 发现、公网信令
//! - [`transport`]  QUIC 数据通道
//! - [`transfer`]   分片、续传、发送端与接收端
//! - [`storage`]    落盘与续传状态

pub mod cli;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod nat;
pub mod protocol;
pub mod storage;
pub mod transfer;
pub mod transport;

pub use error::{Error, Result};
