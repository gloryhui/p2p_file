//! 接收端。

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use quinn::{Connection, RecvStream, SendStream};

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::manifest::FileManifest;
use crate::protocol::message::ControlMessage;
use crate::storage::PartialDownload;
use crate::transport::handshake::handshake_responder;
use crate::transport::quic::{
    ACCEPT_FIRST_BI_STREAM_TIMEOUT, ChannelBinding, STREAM_FIRST_FRAME_TIMEOUT,
    TRANSFER_IDLE_TIMEOUT,
};

/// 同时在途的请求数。
///
/// 太小会浪费带宽（等一个来回才发下一个），太大则会在内存里堆很多分片。
/// 16 个 256 KiB 分片大约 4 MiB，是个保守的起点。
pub const DEFAULT_WINDOW: usize = 16;

#[derive(Default)]
struct OutstandingChunks {
    indexes: HashSet<u32>,
}

impl OutstandingChunks {
    fn request(&mut self, index: u32) {
        self.indexes.insert(index);
    }

    fn contains(&self, index: u32) -> bool {
        self.indexes.contains(&index)
    }

    fn complete(&mut self, index: u32) -> bool {
        self.indexes.remove(&index)
    }

    fn len(&self) -> usize {
        self.indexes.len()
    }

    fn is_empty(&self) -> bool {
        self.indexes.is_empty()
    }
}

/// 接收结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveReport {
    pub peer_node_id: NodeId,
    pub file_name: String,
    pub total_len: u64,
    pub chunk_count: u32,
    /// 这次真正收到的分片数。
    pub chunks_received: u32,
    /// 落盘的正式文件路径。
    pub output_path: PathBuf,
}

/// 在 `connection` 上接收一个文件，存到 `out_dir`。
///
/// 流程：握手 → 收清单 → 回报续传位图 → 按窗口请求分片 → 校验落盘 → 收尾改名。
pub async fn receive_file(
    connection: &Connection,
    identity: &Identity,
    out_dir: &Path,
) -> Result<ReceiveReport> {
    // 1. 握手（对上发送端的第一条双向流）。会话绑定值取自这条连接本身。
    let binding = ChannelBinding::from_connection(connection)?;
    let (mut handshake_send, mut handshake_recv) =
        tokio::time::timeout(ACCEPT_FIRST_BI_STREAM_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| Error::Transport("等待握手流超时".into()))?
            .map_err(|err| Error::Transport(format!("接受握手流失败: {err}")))?;
    let outcome =
        handshake_responder(&mut handshake_send, &mut handshake_recv, identity, &binding).await?;
    let _ = handshake_send.finish();

    // 2. 收清单并开数据流。
    let (send, mut recv) =
        tokio::time::timeout(ACCEPT_FIRST_BI_STREAM_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| Error::Transport("等待文件数据流超时".into()))?
            .map_err(|err| Error::Transport(format!("接受数据流失败: {err}")))?;

    let manifest = match tokio::time::timeout(STREAM_FIRST_FRAME_TIMEOUT, read_frame(&mut recv))
        .await
        .map_err(|_| Error::Protocol("等待文件流首帧超时".into()))??
        .ok_or_else(|| Error::Protocol("对端没有发清单就关闭了连接".into()))?
    {
        ControlMessage::Manifest(manifest) => *manifest,
        other => {
            return Err(Error::Protocol(format!(
                "期待 Manifest，收到 {}",
                other.kind()
            )));
        }
    };

    // `read_frame` 已经通过 `ControlMessage::decode` 校验过，这里再挡一次：
    // 这条路径将来可能换成别的解码方式，而它下面就是「按清单分配文件」。
    manifest.validate()?;

    receive_file_on_stream(send, recv, manifest, out_dir, outcome.peer_node_id).await
}

/// 在**已经收好清单**的数据流上把文件收完。
///
/// 单独拆出来是为了让常驻的 `serve` 复用：`serve` 先读每条新流的第一个消息，
/// 是 `Manifest` 就交给这里，是 `TunnelOpen` 就交给隧道处理，两条路都能走。
pub async fn receive_file_on_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    manifest: FileManifest,
    out_dir: &Path,
    peer_node_id: NodeId,
) -> Result<ReceiveReport> {
    // 入口防御性校验：这个函数的契约是「只接受已经 validate 过的清单」，
    // 但它是对外的 pub 入口，未来新增调用点时不应该有踩坑的机会。
    manifest.validate()?;

    tracing::info!(
        peer = %peer_node_id.short(),
        file = %manifest.file_name,
        total_len = manifest.total_len,
        chunks = manifest.chunk_count(),
        "开始接收"
    );

    // 3. 打开（或恢复）临时下载。
    let mut download = PartialDownload::create(out_dir, manifest.clone())?;
    tokio::time::timeout(
        TRANSFER_IDLE_TIMEOUT,
        write_frame(
            &mut send,
            &ControlMessage::Resume {
                have: download.bitmap().to_bytes(),
            },
        ),
    )
    .await
    .map_err(|_| Error::Protocol("发送 Resume 超时".into()))??;

    let already_have = download.bitmap().count_set();
    if already_have > 0 {
        tracing::info!(already_have, "从上次中断处继续");
    }

    // 4. 按窗口拉取缺失分片。
    let missing = download.missing();
    let mut pending: VecDeque<u32> = missing.into_iter().collect();
    let mut outstanding = OutstandingChunks::default();
    let mut chunks_received: u32 = 0;

    loop {
        while outstanding.len() < DEFAULT_WINDOW {
            let Some(index) = pending.pop_front() else {
                break;
            };
            tokio::time::timeout(
                TRANSFER_IDLE_TIMEOUT,
                write_frame(&mut send, &ControlMessage::RequestChunk { index }),
            )
            .await
            .map_err(|_| Error::Protocol("发送 RequestChunk 超时".into()))??;
            outstanding.request(index);
        }

        if outstanding.is_empty() {
            break;
        }

        let message = tokio::time::timeout(TRANSFER_IDLE_TIMEOUT, read_frame(&mut recv))
            .await
            .map_err(|_| Error::Protocol("等待 Chunk 超时".into()))??
            .ok_or_else(|| Error::Protocol("分片还没收完，对端就关闭了连接".into()))?;

        match message {
            ControlMessage::Chunk { index, data } => {
                if !outstanding.contains(index) {
                    download.discard()?;
                    return Err(Error::Protocol(format!("收到未请求或重复的分片 {index}")));
                }
                download.write_chunk(index, &data)?;
                outstanding.complete(index);
                chunks_received += 1;

                if chunks_received.is_multiple_of(64) {
                    tracing::debug!(
                        received = chunks_received,
                        remaining = pending.len() + outstanding.len(),
                        "接收中"
                    );
                }
            }
            ControlMessage::KeepAlive => {}
            ControlMessage::Abort { reason } => {
                download.discard()?;
                return Err(Error::Protocol(format!("对端中止传输: {reason}")));
            }
            other => {
                download.discard()?;
                return Err(Error::Protocol(format!(
                    "接收过程中收到意外消息 {}",
                    other.kind()
                )));
            }
        }
    }

    if !download.is_complete() {
        let missing = download.missing();
        download.discard()?;
        return Err(Error::Protocol(format!(
            "传输结束但仍有 {} 片缺失（例如 {:?}）",
            missing.len(),
            &missing[..missing.len().min(8)]
        )));
    }

    // 5. 先同步并 finalize。只有正式文件已经成功落盘、改名后，才允许发
    // Complete；否则发送端会把一个尚未保存成功的文件当成成功。
    let output_path = match download.finalize() {
        Ok(path) => path,
        Err(err) => {
            let reason = format!("接收端 finalize 失败，文件未确认保存: {err}");
            // 保留 .part/.bitmap 以便下次恢复；发送端必须看到明确失败，而不是
            // 因为一个先发出的 Complete 错误地返回成功。
            if let Err(send_err) = write_frame(&mut send, &ControlMessage::Abort { reason }).await {
                tracing::warn!(error = %send_err, "无法把 finalize 失败通知发送端");
            }
            let _ = send.finish();
            return Err(err);
        }
    };

    // 6. 回报根哈希，让发送端也能确认这次传的是同一份文件。
    tokio::time::timeout(
        TRANSFER_IDLE_TIMEOUT,
        write_frame(
            &mut send,
            &ControlMessage::Complete {
                root_hash: manifest.root_hash,
            },
        ),
    )
    .await
    .map_err(|_| Error::Protocol("发送 Complete 超时".into()))??;
    let _ = send.finish();

    tracing::info!(
        peer = %peer_node_id.short(),
        path = %output_path.display(),
        "接收完成"
    );

    Ok(ReceiveReport {
        peer_node_id,
        file_name: manifest.file_name.clone(),
        total_len: manifest.total_len,
        chunk_count: manifest.chunk_count(),
        chunks_received,
        output_path,
    })
}

#[cfg(test)]
mod tests {
    use super::OutstandingChunks;

    #[test]
    fn 重复和未请求分片不会污染在途集合() {
        let mut outstanding = OutstandingChunks::default();
        outstanding.request(3);
        outstanding.request(7);
        assert_eq!(outstanding.len(), 2);

        assert!(!outstanding.complete(99));
        assert_eq!(outstanding.len(), 2);
        assert!(outstanding.contains(3));

        assert!(outstanding.complete(3));
        assert!(!outstanding.complete(3));
        assert_eq!(outstanding.len(), 1);
        assert!(!outstanding.is_empty());
    }
}
