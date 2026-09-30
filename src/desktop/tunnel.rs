//! Desktop protocol adapter for the shared TCP-over-QUIC tunnel core.

use std::net::SocketAddr;
use std::time::Duration;

use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::error::{Error, Result};
use crate::identity::NodeId;

use super::protocol::{self, Frame, Message};

const STREAM_LIMIT: usize = 8;
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Open one tunnel stream on a peer connection already authenticated and
/// negotiated by the desktop session.
pub(super) async fn open_tunnel(
    tcp: tokio::net::TcpStream,
    connection: &Connection,
    target: SocketAddr,
) -> Result<()> {
    let (mut send, mut recv) = tokio::time::timeout(STREAM_OPEN_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| Error::Transport("打开隧道流超时".into()))?
        .map_err(|error| Error::Transport(format!("打开隧道流失败: {error}")))?;
    protocol::write(
        &mut send,
        &Frame {
            request_id: 0,
            message: Message::TunnelOpen { target },
        },
    )
    .await?;

    match tokio::time::timeout(STREAM_OPEN_TIMEOUT, protocol::read(&mut recv))
        .await
        .map_err(|_| Error::Protocol("等待远端隧道响应超时".into()))??
        .message
    {
        Message::TunnelReady => crate::tunnel::bridge_tcp(tcp, send, recv).await,
        Message::TunnelError { reason } => {
            let _ = send.finish();
            Err(Error::Transport(reason))
        }
        _ => Err(Error::Protocol("期待远端隧道响应，收到其它桌面消息".into())),
    }
}

/// Accept one desktop tunnel request and delegate target authorization,
/// TCP connection, and bidirectional copying to the shared tunnel core.
pub(super) async fn serve_open(
    mut send: SendStream,
    recv: RecvStream,
    target: SocketAddr,
    allowed_targets: &[SocketAddr],
) -> Result<()> {
    let tcp = match crate::tunnel::connect_allowed_target(target, allowed_targets).await {
        Ok(tcp) => tcp,
        Err(error) => {
            protocol::write(
                &mut send,
                &Frame {
                    request_id: 0,
                    message: Message::TunnelError {
                        reason: error.to_string(),
                    },
                },
            )
            .await?;
            let _ = send.finish();
            return Err(error);
        }
    };

    protocol::write(
        &mut send,
        &Frame {
            request_id: 0,
            message: Message::TunnelReady,
        },
    )
    .await?;
    crate::tunnel::bridge_tcp(tcp, send, recv).await
}

/// Serve tunnel streams when the task store is unavailable. This preserves
/// TCP forwarding as an independent service while retaining structured cleanup.
pub(super) async fn serve_peer(
    connection: Connection,
    peer: NodeId,
    allowed_updates: watch::Receiver<Vec<SocketAddr>>,
) -> Result<()> {
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            accepted = connection.accept_bi() => {
                let (send, mut recv) = match accepted {
                    Ok(streams) => streams,
                    Err(_) => break,
                };
                if streams.len() >= STREAM_LIMIT {
                    let mut send = send;
                    let _ = protocol::write(
                        &mut send,
                        &Frame {
                            request_id: 0,
                            message: Message::TunnelError {
                                reason: "对端隧道流并发达到上限".into(),
                            },
                        },
                    )
                    .await;
                    let _ = send.finish();
                    let _ = recv.stop(4u32.into());
                    continue;
                }
                let allowed = allowed_updates.borrow().clone();
                streams.spawn(async move {
                    let mut send = send;
                    let frame = tokio::time::timeout(STREAM_OPEN_TIMEOUT, protocol::read(&mut recv))
                        .await
                        .map_err(|_| Error::Protocol("等待隧道请求超时".into()))??;
                    match frame.message {
                        Message::TunnelOpen { target } => {
                            if let Err(error) = serve_open(send, recv, target, &allowed).await {
                                tracing::debug!(peer = %peer.short(), %target, error = %error, "桌面隧道请求结束");
                            }
                            Ok(())
                        }
                        _ => {
                            let _ = send.reset(4u32.into());
                            let _ = recv.stop(4u32.into());
                            Err(Error::Protocol("未配置任务存储，仅接受 TCP 隧道请求".into()))
                        }
                    }
                });
            }
            result = streams.join_next(), if !streams.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::debug!(%error, "无任务存储的 peer 流 task 结束");
                }
            }
        }
    }
    streams.abort_all();
    while let Some(result) = streams.join_next().await {
        if let Err(error) = result {
            tracing::debug!(%error, "无任务存储的 peer 流 task 已取消");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::transport::quic::{client_endpoint, connect, server_endpoint};

    async fn exercise_forwarding(allowed: bool) {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });

        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_for_accept = server.clone();
        let server_connection_task =
            tokio::spawn(async move { server_for_accept.accept().await.unwrap().await.unwrap() });
        let client_connection = connect(&client, server_addr, "p2pfile").await.unwrap();
        let server_connection = server_connection_task.await.unwrap();

        let server_allowed = if allowed { vec![target] } else { Vec::new() };
        let server_task_connection = server_connection.clone();
        let server_task = tokio::spawn(async move {
            let (send, recv) = server_task_connection.accept_bi().await.unwrap();
            let mut recv = recv;
            let frame = protocol::read(&mut recv).await.unwrap();
            match frame.message {
                Message::TunnelOpen { target } => {
                    serve_open(send, recv, target, &server_allowed).await
                }
                _ => panic!("expected a tunnel open frame"),
            }
        });

        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let (peer_updates, peer_connection) = watch::channel(Some(client_connection.clone()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (errors_tx, mut errors_rx) = tokio::sync::mpsc::unbounded_channel();
        let forwarder = tokio::spawn(crate::tunnel::forward_on_authenticated_session(
            local_listener,
            target,
            peer_connection,
            shutdown_rx,
            errors_tx,
            |tcp, connection, target| async move { open_tunnel(tcp, &connection, target).await },
        ));

        let mut local = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        local.write_all(b"desktop tcp tunnel").await.unwrap();
        if allowed {
            let mut echoed = [0; 18];
            local.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"desktop tcp tunnel");
            local.shutdown().await.unwrap();
            let mut tail = Vec::new();
            local.read_to_end(&mut tail).await.unwrap();
            server_task.await.unwrap().unwrap();
        } else {
            let mut rejected = Vec::new();
            let _ = local.read_to_end(&mut rejected).await;
            assert!(rejected.is_empty(), "denied targets must not return bytes");
            let detail = tokio::time::timeout(Duration::from_secs(2), errors_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(detail.contains("不在允许转发的列表里"), "{detail}");
            assert!(server_task.await.unwrap().is_err());
        }

        shutdown_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), forwarder)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        client_connection.close(0u32.into(), b"test complete");
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
        let _ = peer_updates;
    }

    #[tokio::test]
    async fn desktop_stream_reuses_core_for_allowed_target_and_reports_whitelist_denial() {
        exercise_forwarding(true).await;
        exercise_forwarding(false).await;
    }
}
