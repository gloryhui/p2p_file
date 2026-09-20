//! 统一错误类型。

use thiserror::Error;

/// 本项目统一使用的错误类型。
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("序列化错误: {0}")]
    Encode(#[from] postcard::Error),

    #[error("STUN 协议错误: {0}")]
    Stun(String),

    #[error("协议错误: {0}")]
    Protocol(String),

    #[error("身份错误: {0}")]
    Identity(String),

    #[error("发现错误: {0}")]
    Discovery(String),

    #[error("传输错误: {0}")]
    Transport(String),

    #[error("未实现: {0}")]
    Unimplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
