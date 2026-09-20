//! 数据通道：基于 QUIC 的加密多路复用连接。

pub mod handshake;
pub mod quic;

pub use handshake::{HandshakeOutcome, handshake_initiator, handshake_responder};
pub use quic::{ALPN, client_endpoint, connect, install_crypto_provider, server_endpoint};
