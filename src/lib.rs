//! p2p_file —— 点对点文件传输。
//!
//! 模块划分见 `docs/ARCHITECTURE.md`：
//!
//! - [`identity`]   长期密钥与节点 ID
//! - [`protocol`]   应用层消息、文件清单、帧编解码
//! - [`nat`]        STUN 查询、NAT 类型判定、打洞、端口映射
//! - [`discovery`]  局域网 mDNS 发现、公网信令
//! - [`net`]        建立直连：STUN → 信令 → 打洞 → 交给 QUIC
//! - [`transport`]  QUIC 数据通道
//! - [`transfer`]   分片、续传、发送端与接收端
//! - [`tunnel`]     TCP-over-QUIC 端口转发
//! - [`storage`]    落盘与续传状态

pub mod cli;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod nat;
pub mod net;
pub mod protocol;
pub mod speedtest;
pub mod storage;
pub mod transfer;
pub mod transport;
pub mod tunnel;

#[cfg(feature = "gui")]
pub mod desktop;

pub use error::{Error, Result};
