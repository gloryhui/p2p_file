//! Optional, verified TLS around the unchanged signaling frames. There is no
//! insecure verifier, protocol sniffing, or automatic downgrade to plaintext.
use crate::error::{Error, Result};
use quinn::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_PEM_BYTES: u64 = 4 * 1024 * 1024;
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalTlsClient {
    /// None uses bundled Mozilla roots; Some uses only the specified PEM roots.
    pub ca_file: Option<PathBuf>,
    /// None verifies the host from HOST:PORT (including IP SANs).
    pub server_name: Option<String>,
}
#[derive(Clone, Debug)]
pub struct SignalTlsServer {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
fn invalid(message: &'static str) -> Error {
    Error::Discovery(message.into())
}
fn read_pem(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let metadata = std::fs::metadata(path).map_err(|_| invalid("读取信令 TLS PEM 文件失败"))?;
    if !metadata.is_file() || metadata.len() > MAX_PEM_BYTES {
        return Err(invalid("信令 TLS PEM 必须是最大 4 MiB 的普通文件"));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .map_err(|_| invalid("打开信令 TLS PEM 文件失败"))?
        .take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("读取信令 TLS PEM 文件失败"))?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(invalid("信令 TLS PEM 文件超过大小上限"));
    }
    Ok(bytes)
}
fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = read_pem(path)?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| invalid("信令 TLS 证书 PEM 格式无效"))?;
    if certificates.is_empty() {
        return Err(invalid("信令 TLS PEM 未包含证书"));
    }
    Ok(certificates)
}
pub fn server_name(server: &str, override_name: Option<&str>) -> Result<ServerName<'static>> {
    let inferred;
    let name = if let Some(name) = override_name {
        name
    } else {
        let (host, port) = server
            .rsplit_once(':')
            .ok_or_else(|| invalid("TLS 信令地址须为 HOST:PORT"))?;
        if port.parse::<u16>().is_err() || host.is_empty() {
            return Err(invalid("TLS 信令地址或端口无效"));
        }
        inferred = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        &inferred
    };
    if name.is_empty() || name.len() > 253 || name.chars().any(char::is_whitespace) {
        return Err(invalid("信令 TLS 校验主机名无效"));
    }
    ServerName::try_from(name.to_owned())
        .map_err(|_| invalid("信令 TLS 校验主机名须为 DNS 名称或 IP"))
}
impl SignalTlsClient {
    pub(crate) fn prepare(&self, server: &str) -> Result<(TlsConnector, ServerName<'static>)> {
        let name = server_name(server, self.server_name.as_deref())?;
        let mut roots = rustls::RootCertStore::empty();
        if let Some(path) = &self.ca_file {
            for certificate in certificates(path)? {
                roots
                    .add(certificate)
                    .map_err(|_| invalid("信令 TLS CA 证书无效"))?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("信令 TLS 协议配置无效"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok((TlsConnector::from(Arc::new(config)), name))
    }
}
impl SignalTlsServer {
    pub(crate) fn prepare(&self) -> Result<TlsAcceptor> {
        let chain = certificates(&self.certificate)?;
        let bytes = read_pem(&self.private_key)?;
        let key = PrivateKeyDer::from_pem_slice(&bytes)
            .map_err(|_| invalid("信令 TLS 私钥 PEM 格式无效"))?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("信令 TLS 协议配置无效"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_| invalid("信令 TLS 证书与私钥不匹配或无效"))?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        discovery::signal::{
            Candidate, SignalMessage, SignalServerConfig, SignalingClient,
            run_signal_server_on_with,
        },
        identity::Identity,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };
    pub(crate) struct Fixture {
        pub dir: PathBuf,
        pub server: SignalTlsServer,
        pub client: SignalTlsClient,
    }
    impl Fixture {
        pub fn new(expired: bool) -> Self {
            let dir =
                std::env::temp_dir().join(format!("p2p-signal-tls-{}", rand::random::<u64>()));
            std::fs::create_dir(&dir).unwrap();
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
            if expired {
                params.not_before = rcgen::date_time_ymd(2000, 1, 1);
                params.not_after = rcgen::date_time_ymd(2001, 1, 1);
            }
            let cert = params.self_signed(&key).unwrap();
            let certificate = dir.join("cert.pem");
            let private_key = dir.join("key.pem");
            std::fs::write(&certificate, cert.pem()).unwrap();
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            options
                .open(&private_key)
                .unwrap()
                .write_all(key.serialize_pem().as_bytes())
                .unwrap();
            Self {
                dir,
                server: SignalTlsServer {
                    certificate: certificate.clone(),
                    private_key,
                },
                client: SignalTlsClient {
                    ca_file: Some(certificate),
                    server_name: Some("localhost".into()),
                },
            }
        }
        pub async fn start(&self) -> (std::net::SocketAddr, tokio::task::JoinHandle<Result<()>>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let config = SignalServerConfig {
                tls: Some(self.server.clone()),
                ..SignalServerConfig::for_tests()
            };
            (
                address,
                tokio::spawn(run_signal_server_on_with(listener, config)),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    #[tokio::test]
    async fn signaling_tls_keeps_registration_lookup_short_ids_heartbeat_and_reconnect() {
        let fixture = Fixture::new(false);
        let (address, server) = fixture.start().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let mut first = SignalingClient::connect_desktop_with_tls(
            &address.to_string(),
            &a,
            vec![Candidate::host("127.0.0.1:11001".parse().unwrap())],
            Some(&fixture.client),
        )
        .await
        .unwrap();
        let mut second = SignalingClient::connect_desktop_with_tls(
            &address.to_string(),
            &b,
            vec![Candidate::host("127.0.0.1:11002".parse().unwrap())],
            Some(&fixture.client),
        )
        .await
        .unwrap();
        let short = first.short_id().unwrap();
        first.ping().await.unwrap();
        assert!(matches!(
            timeout(Duration::from_secs(2), first.next_event())
                .await
                .unwrap(),
            Ok(SignalMessage::Pong)
        ));
        second.request_short_lookup(short).await.unwrap();
        assert!(
            matches!(timeout(Duration::from_secs(2), second.next_event()).await.unwrap(), Ok(SignalMessage::ShortResolved { node_id: Some(id), .. }) if id == a.node_id())
        );
        let offer = first
            .resolve_peer(b.node_id(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(offer.candidates[0].addr, "127.0.0.1:11002".parse().unwrap());
        assert_eq!(offer.candidates.len(), 1);
        drop(first);
        let fresh = SignalingClient::connect_desktop_with_tls(
            &address.to_string(),
            &a,
            Vec::new(),
            Some(&fixture.client),
        )
        .await
        .unwrap();
        assert_eq!(fresh.short_id(), Some(short));
        drop((fresh, second));
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn signaling_tls_rejects_unknown_ca_wrong_name_and_expired_certificates() {
        let fixture = Fixture::new(false);
        let other = Fixture::new(false);
        let (address, server) = fixture.start().await;
        let id = Identity::generate();
        for client in [
            SignalTlsClient::default(),
            other.client.clone(),
            SignalTlsClient {
                server_name: Some("wrong.invalid".into()),
                ..fixture.client.clone()
            },
        ] {
            let error = SignalingClient::connect_with_tls(
                &address.to_string(),
                &id,
                Vec::new(),
                Some(&client),
            )
            .await
            .err()
            .unwrap()
            .to_string();
            assert!(
                error.contains("证书/主机名校验失败") && error.contains("未降级为明文"),
                "{error}"
            );
        }
        server.abort();
        let _ = server.await;
        let expired = Fixture::new(true);
        let (address, server) = expired.start().await;
        assert!(
            SignalingClient::connect_with_tls(
                &address.to_string(),
                &id,
                Vec::new(),
                Some(&expired.client)
            )
            .await
            .is_err()
        );
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn signaling_tls_never_retries_plaintext_and_bad_ca_fails_before_connect() {
        let fixture = Fixture::new(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = fixture.client.clone();
        let attempt = tokio::spawn(async move {
            SignalingClient::connect_with_tls(
                &address.to_string(),
                &Identity::generate(),
                Vec::new(),
                Some(&client),
            )
            .await
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut prefix = [0; 5];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(
            prefix[0], 0x16,
            "TLS handshake, never a signaling Hello frame"
        );
        drop(stream);
        assert!(attempt.await.unwrap().is_err());
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let bad_ca = SignalTlsClient {
            ca_file: Some(fixture.dir.join("missing-ca.pem")),
            ..fixture.client.clone()
        };
        assert!(
            SignalingClient::connect_with_tls(
                &address.to_string(),
                &Identity::generate(),
                Vec::new(),
                Some(&bad_ca)
            )
            .await
            .is_err()
        );
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let (address, server) = fixture.start().await;
        assert!(
            SignalingClient::connect(&address.to_string(), &Identity::generate(), Vec::new())
                .await
                .is_err()
        ); // TLS-only port rejects legacy plaintext.
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn signaling_tls_handshake_capacity_and_timeout_release_the_slot() {
        let fixture = Fixture::new(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = SignalServerConfig {
            tls: Some(fixture.server.clone()),
            max_tls_handshakes: 1,
            tls_handshake_timeout: Duration::from_secs(2),
            ..SignalServerConfig::for_tests()
        };
        let server = tokio::spawn(run_signal_server_on_with(listener, config));
        let mut stalled = TcpStream::connect(address).await.unwrap();
        stalled
            .write_all(&[0x16, 0x03, 0x03, 0, 16, 1])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            SignalingClient::connect_with_tls(
                &address.to_string(),
                &Identity::generate(),
                Vec::new(),
                Some(&fixture.client)
            )
            .await
            .is_err()
        );
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(3), stalled.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let connected = SignalingClient::connect_with_tls(
            &address.to_string(),
            &Identity::generate(),
            Vec::new(),
            Some(&fixture.client),
        )
        .await
        .unwrap();
        drop(connected);
        server.abort();
        let _ = server.await;
    }
    #[test]
    fn signaling_tls_invalid_pem_mismatched_key_and_hostnames_fail_closed() {
        let fixture = Fixture::new(false);
        let other = Fixture::new(false);
        assert!(
            SignalTlsServer {
                private_key: other.server.private_key.clone(),
                ..fixture.server.clone()
            }
            .prepare()
            .is_err()
        );
        std::fs::write(&fixture.server.private_key, "private-invalid-material").unwrap();
        let error = fixture.server.prepare().err().unwrap().to_string();
        assert!(!error.contains("private-invalid-material"));
        let ca = fixture.dir.join("empty.pem");
        std::fs::write(&ca, "").unwrap();
        assert!(
            SignalTlsClient {
                ca_file: Some(ca.clone()),
                ..fixture.client.clone()
            }
            .prepare("127.0.0.1:7000")
            .is_err()
        );
        std::fs::File::create(&ca)
            .unwrap()
            .set_len(MAX_PEM_BYTES + 1)
            .unwrap();
        assert!(
            SignalTlsClient {
                ca_file: Some(ca),
                ..fixture.client.clone()
            }
            .prepare("127.0.0.1:7000")
            .is_err()
        );
        for valid in ["localhost:7000", "127.0.0.1:7000", "[::1]:7000"] {
            assert!(server_name(valid, None).is_ok());
        }
        for invalid in ["", "bad/name", "example:7000", "foo bar"] {
            assert!(server_name("localhost:7000", Some(invalid)).is_err());
        }
    }
}
