//! 接收端。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use quinn::Connection;

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::message::ControlMessage;
use crate::storage::PartialDownload;
use crate::transport::handshake::handshake_responder;

/// 同时在途的请求数。
///
/// 太小会浪费带宽（等一个来回才发下一个），太大则会在内存里堆很多分片。
/// 16 个 256 KiB 分片大约 4 MiB，是个保守的起点。
pub const DEFAULT_WINDOW: usize = 16;

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
    // 1. 握手（对上发送端的第一条双向流）。
    let (mut handshake_send, mut handshake_recv) = connection
        .accept_bi()
        .await
        .map_err(|err| Error::Transport(format!("接受握手流失败: {err}")))?;
    let outcome = handshake_responder(&mut handshake_send, &mut handshake_recv, identity).await?;
    let _ = handshake_send.finish();

    // 2. 收清单并开数据流。
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|err| Error::Transport(format!("接受数据流失败: {err}")))?;

    let manifest = match read_frame(&mut recv)
        .await?
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

    tracing::info!(
        peer = %outcome.peer_node_id.short(),
        file = %manifest.file_name,
        total_len = manifest.total_len,
        chunks = manifest.chunk_count(),
        "开始接收"
    );

    // 3. 打开（或恢复）临时下载。
    let mut download = PartialDownload::create(out_dir, manifest.clone())?;
    write_frame(
        &mut send,
        &ControlMessage::Resume {
            have: download.bitmap().to_bytes(),
        },
    )
    .await?;

    let already_have = download.bitmap().count_set();
    if already_have > 0 {
        tracing::info!(already_have, "从上次中断处继续");
    }

    // 4. 按窗口拉取缺失分片。
    let missing = download.missing();
    let mut pending: VecDeque<u32> = missing.into_iter().collect();
    let mut in_flight: usize = 0;
    let mut chunks_received: u32 = 0;

    loop {
        while in_flight < DEFAULT_WINDOW {
            let Some(index) = pending.pop_front() else {
                break;
            };
            write_frame(&mut send, &ControlMessage::RequestChunk { index }).await?;
            in_flight += 1;
        }

        if in_flight == 0 {
            break;
        }

        let message = read_frame(&mut recv)
            .await?
            .ok_or_else(|| Error::Protocol("分片还没收完，对端就关闭了连接".into()))?;

        match message {
            ControlMessage::Chunk { index, data } => {
                download.write_chunk(index, &data)?;
                in_flight -= 1;
                chunks_received += 1;

                if chunks_received.is_multiple_of(64) {
                    tracing::debug!(
                        received = chunks_received,
                        remaining = pending.len() + in_flight,
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

    // 5. 回报根哈希，让发送端也能确认这次传的是同一份文件。
    write_frame(
        &mut send,
        &ControlMessage::Complete {
            root_hash: manifest.root_hash,
        },
    )
    .await?;
    let _ = send.finish();

    let output_path = download.finalize()?;
    tracing::info!(
        peer = %outcome.peer_node_id.short(),
        path = %output_path.display(),
        "接收完成"
    );

    Ok(ReceiveReport {
        peer_node_id: outcome.peer_node_id,
        file_name: manifest.file_name.clone(),
        total_len: manifest.total_len,
        chunk_count: manifest.chunk_count(),
        chunks_received,
        output_path,
    })
}
