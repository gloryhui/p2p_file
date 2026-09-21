//! 数据通道：基于 QUIC 的加密多路复用连接。

pub mod handshake;
pub mod quic;

pub use handshake::{HandshakeOutcome, handshake_initiator, handshake_responder};
pub use quic::{
    ALPN, CHANNEL_BINDING_LABEL, CHANNEL_BINDING_LEN, ChannelBinding, KEEP_ALIVE_INTERVAL,
    MAX_IDLE_TIMEOUT, client_endpoint, connect, endpoint_from_socket, install_crypto_provider,
    server_endpoint,
};
