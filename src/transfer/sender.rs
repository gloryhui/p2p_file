//! 发送端。

use std::fs::File;
use std::path::Path;

use quinn::Connection;

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::message::ControlMessage;
use crate::transfer::chunker::{manifest_from_path, read_chunk};
use crate::transfer::resume::ChunkBitmap;
use crate::transport::handshake::handshake_initiator;
use crate::transport::quic::ChannelBinding;

/// 发送结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendReport {
    pub peer_node_id: NodeId,
    pub file_name: String,
    pub total_len: u64,
    pub chunk_count: u32,
    /// 这次真正发出去的分片数。
    pub chunks_sent: u32,
    /// 对端已有、跳过不发的分片数（断点续传省下的部分）。
    pub chunks_skipped: u32,
}

/// 通过 `connection` 把 `path` 发给对端。
///
/// 流程：握手 → 发清单 → 收对端的续传位图 → 按需回片 → 等对端回报根哈希。
///
/// 用的是「拉」模型：由接收端发 `RequestChunk`，发送端才回数据。这样接收端
/// 能自己控制并发窗口，不会被发送端灌爆内存。
pub async fn send_file(
    connection: &Connection,
    identity: &Identity,
    path: &Path,
    chunk_size: u32,
) -> Result<SendReport> {
    // 1. 握手（占第一条双向流）。会话绑定值必须从**这条**连接导出，
    //    签名才会被钉死在这条 TLS 会话上，挡住透明 MITM 转发。
    let binding = ChannelBinding::from_connection(connection)?;
    let (mut handshake_send, mut handshake_recv) = connection
        .open_bi()
        .await
        .map_err(|err| Error::Transport(format!("打开握手流失败: {err}")))?;
    let outcome =
        handshake_initiator(&mut handshake_send, &mut handshake_recv, identity, &binding).await?;
    // 握手流用完就关，让对端的读取干净结束。
    let _ = handshake_send.finish();

    send_file_after_handshake(connection, path, chunk_size, outcome.peer_node_id).await
}

/// 在**已经完成握手**的连接上把文件发出去。
///
/// 单独拆出来是为了让 `serve` 这种常驻服务复用：它先自己完成握手并核对对端
/// 身份，再决定这条连接是收文件还是做隧道。
pub async fn send_file_after_handshake(
    connection: &Connection,
    path: &Path,
    chunk_size: u32,
    peer_node_id: NodeId,
) -> Result<SendReport> {
    // 2. 生成清单并开数据流。
    let manifest = manifest_from_path(path, chunk_size)?;
    tracing::info!(
        peer = %peer_node_id.short(),
        file = %manifest.file_name,
        total_len = manifest.total_len,
        chunks = manifest.chunk_count(),
        "开始发送"
    );

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| Error::Transport(format!("打开数据流失败: {err}")))?;

    write_frame(
        &mut send,
        &ControlMessage::Manifest(Box::new(manifest.clone())),
    )
    .await?;

    // 3. 收对端的续传位图。
    let resume = read_frame(&mut recv)
        .await?
        .ok_or_else(|| Error::Protocol("对端没有回报续传进度就关闭了连接".into()))?;
    let peer_bitmap = match resume {
        ControlMessage::Resume { have } => ChunkBitmap::from_bytes(manifest.chunk_count(), &have)?,
        ControlMessage::Abort { reason } => {
            return Err(Error::Protocol(format!("对端拒绝接收: {reason}")));
        }
        other => {
            return Err(Error::Protocol(format!(
                "期待 Resume，收到 {}",
                other.kind()
            )));
        }
    };

    let chunks_skipped = peer_bitmap.count_set();
    if chunks_skipped > 0 {
        tracing::info!(chunks_skipped, "对端已有部分分片，续传");
    }

    // 4. 按请求回片。文件用同步 IO 读——分片读写很快，但严格说应该
    //    放进 spawn_blocking 里，见 storage 模块的说明（TODO）。
    let mut file = File::open(path)?;
    let mut chunks_sent: u32 = 0;

    loop {
        let message = match read_frame(&mut recv).await? {
            Some(message) => message,
            // 对端直接断了。
            None => {
                return Err(Error::Protocol("对端在传完之前关闭了连接".into()));
            }
        };

        match message {
            ControlMessage::RequestChunk { index } => {
                let (offset, len) = manifest
                    .chunk_range(index)
                    .ok_or_else(|| Error::Protocol(format!("对端请求了不存在的分片 {index}")))?;

                // 对端说已经有了的，就别重复发（可能是它自己的位图更新了）。
                if peer_bitmap.is_set(index) {
                    tracing::debug!(index, "对端已有该分片，跳过");
                    continue;
                }

                let data = read_chunk(&mut file, offset, len)?;
                write_frame(&mut send, &ControlMessage::Chunk { index, data }).await?;
                chunks_sent += 1;
            }
            ControlMessage::Complete { root_hash } => {
                if root_hash != manifest.root_hash {
                    return Err(Error::Protocol(format!(
                        "对端回报的根哈希与本地不符：对端 {}，本地 {}",
                        root_hash.to_hex(),
                        manifest.root_hash.to_hex()
                    )));
                }
                break;
            }
            ControlMessage::KeepAlive => {}
            ControlMessage::Abort { reason } => {
                return Err(Error::Protocol(format!("对端中止传输: {reason}")));
            }
            ControlMessage::Bye => {
                return Err(Error::Protocol("对端在发送 Complete 前结束传输".into()));
            }
            other => {
                return Err(Error::Protocol(format!(
                    "发送过程中收到意外消息 {}",
                    other.kind()
                )));
            }
        }
    }

    let _ = send.finish();

    tracing::info!(
        peer = %peer_node_id.short(),
        chunks_sent,
        chunks_skipped,
        "发送完成"
    );

    Ok(SendReport {
        peer_node_id,
        file_name: manifest.file_name.clone(),
        total_len: manifest.total_len,
        chunk_count: manifest.chunk_count(),
        chunks_sent,
        chunks_skipped,
    })
}
