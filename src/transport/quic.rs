//! QUIC 端点与连接。
//!
//! # 关于跳过 TLS 证书校验
//!
//! P2P 场景里没有 CA，也不该有：节点身份由 Ed25519 公钥决定，公钥到节点 ID
//! 的映射是自证的。所以这里**故意**装了一个不校验证书的 verifier，信任建立
//! 推迟到应用层握手（见 [`crate::transport::handshake`]）。
//!
//! 成立的前提是：**任何连接都必须先跑完应用层握手**。QUIC 提供的是加密和
//! 完整性，握手提供的是身份确认；少了握手，中间人就挡不住了。
//! 这条约束不能省。

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use quinn::{
    ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarIntBoundsExceeded,
};

use crate::error::{Error, Result};

/// ALPN 标识，防止连到别的 QUIC 服务上。
pub const ALPN: &[u8] = b"p2pfile/1";

/// 空闲多久发一次 keepalive。NAT 映射通常 30~120 秒超时，10 秒足够稳。
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// 空闲超时。超过这个时间没有任何活动就认为连接死了。
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

static CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

/// 安装 rustls 的默认加密后端。
///
/// rustls 要求进程内只装一次。重复调用是安全的：已经装过就什么也不做。
pub fn install_crypto_provider() {
    CRYPTO_PROVIDER.get_or_init(|| {
        // 失败只可能是别的库先装过了，那也算装好了。
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 共享的传输参数：keepalive + 空闲超时。
fn transport_config() -> Result<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    let idle: IdleTimeout = MAX_IDLE_TIMEOUT
        .try_into()
        .map_err(|err: VarIntBoundsExceeded| Error::Transport(format!("空闲超时非法: {err}")))?;
    transport.max_idle_timeout(Some(idle));
    Ok(transport)
}

/// 创建服务端端点，绑定到 `bind`。
///
/// 每次启动生成一张新的自签证书。这不影响身份安全——身份由应用层握手保证。
pub fn server_endpoint(bind: SocketAddr) -> Result<Endpoint> {
    install_crypto_provider();

    let certified = rcgen::generate_simple_self_signed(vec!["p2pfile".to_string()])
        .map_err(|err| Error::Transport(format!("生成自签证书失败: {err}")))?;
    let cert_der: CertificateDer<'static> = certified.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|err| Error::Transport(format!("TLS 服务端配置失败: {err}")))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|err| Error::Transport(format!("QUIC 服务端配置失败: {err}")))?;

    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));

    Endpoint::server(config, bind)
        .map_err(|err| Error::Transport(format!("绑定 {bind} 失败: {err}")))
}

/// 创建客户端端点，绑定到 `bind`（通常写 `0.0.0.0:0`）。
pub fn client_endpoint(bind: SocketAddr) -> Result<Endpoint> {
    install_crypto_provider();

    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| Error::Transport(format!("QUIC 客户端配置失败: {err}")))?;

    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));

    let mut endpoint = Endpoint::client(bind)
        .map_err(|err| Error::Transport(format!("绑定 {bind} 失败: {err}")))?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

/// 连到 `remote`。`server_name` 只用于 TLS SNI，因为不校验证书，随便传。
pub async fn connect(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
) -> Result<quinn::Connection> {
    let connecting = endpoint
        .connect(remote, server_name)
        .map_err(|err| Error::Transport(format!("发起连接到 {remote} 失败: {err}")))?;

    connecting
        .await
        .map_err(|err| Error::Transport(format!("与 {remote} 建立连接失败: {err}")))
}

/// **不安全**的证书校验器：一律放行。
///
/// 见本模块顶部的说明——身份确认靠应用层握手，不靠证书链。
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frame::{read_frame, write_frame};
    use crate::protocol::message::ControlMessage;

    #[test]
    fn 加密后端可以重复安装() {
        install_crypto_provider();
        install_crypto_provider();
    }

    #[test]
    fn 传输参数合法() {
        // 字段是 crate 私有的，只能确认构造本身不失败。
        assert!(transport_config().is_ok());
    }

    #[tokio::test]
    async fn 端点能在环回地址上收发数据() {
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("应当收到连接");
            let connection = incoming.await.expect("握手应当成功");

            let (mut send, mut recv) = connection.accept_bi().await.expect("应当收到流");
            let request = read_frame(&mut recv).await.unwrap().unwrap();
            assert_eq!(request, ControlMessage::RequestChunk { index: 5 });

            write_frame(
                &mut send,
                &ControlMessage::Chunk {
                    index: 5,
                    data: b"hello from server".to_vec(),
                },
            )
            .await
            .unwrap();
            send.finish().unwrap();

            // 等客户端确认收到，避免连接被提前关掉。
            connection.closed().await;
            server.wait_idle().await;
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_frame(&mut send, &ControlMessage::RequestChunk { index: 5 })
            .await
            .unwrap();

        let response = read_frame(&mut recv).await.unwrap().unwrap();
        match response {
            ControlMessage::Chunk { index, data } => {
                assert_eq!(index, 5);
                assert_eq!(data, b"hello from server");
            }
            other => panic!("意料之外的消息: {other:?}"),
        }

        connection.close(0u32.into(), b"bye");
        client.wait_idle().await;
        server_task.await.unwrap();
    }
}
