//! 长度前缀帧：`[u32 小端长度][postcard 载荷]`。
//!
//! QUIC 的流是字节流，本身不保留消息边界，所以自己做一层定长头。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::protocol::message::ControlMessage;

/// 单帧上限 16 MiB。分片大小上限也是 16 MiB，留出 postcard 自身的编码开销。
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024 + 4096;

/// 写一帧原始载荷并 flush。
///
/// 控制消息和信令消息共用这一层：信令走 TCP，控制消息走 QUIC。
pub async fn write_raw_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_raw_frame_limited(writer, payload, MAX_FRAME_LEN).await
}

/// 写一帧原始载荷，并指定这一层协议自己的长度上限。
///
/// 信令是公网上的小控制消息，不该复用业务分片那 16 MiB 的上限；调用方传一个
/// 远小的 `max_len`，避免对端用长度头逼着服务端提前分配大缓冲。
pub async fn write_raw_frame_limited<W>(writer: &mut W, payload: &[u8], max_len: u32) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = payload.len();
    if len > max_len as usize {
        return Err(Error::Protocol(format!(
            "帧过大：{len} 字节，上限 {max_len}"
        )));
    }
    writer.write_all(&(len as u32).to_le_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// 读一帧原始载荷。
///
/// 对端干净关闭（连长度头都没读到就 EOF）时返回 `Ok(None)`；
/// 只读到一半就断开视为协议错误。
pub async fn read_raw_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    read_raw_frame_limited(reader, MAX_FRAME_LEN).await
}

/// 读一帧原始载荷，并指定这一层协议自己的长度上限。
///
/// 长度头必须先于分配被检查：超限直接报错，绝不按对端声称的长度去 `Vec` 分配。
pub async fn read_raw_frame_limited<R>(reader: &mut R, max_len: u32) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let len = u32::from_le_bytes(len_bytes);
    if len > max_len {
        return Err(Error::Protocol(format!(
            "帧长度 {len} 超过上限 {max_len}，可能不是本协议的流"
        )));
    }

    let mut payload = vec![0u8; len as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::Protocol("帧读到一半连接就断了".into()),
            _ => err.into(),
        })?;

    Ok(Some(payload))
}

/// 写一帧控制消息。
pub async fn write_frame<W>(writer: &mut W, message: &ControlMessage) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = message.encode()?;
    if payload.len() > MAX_FRAME_LEN as usize {
        return Err(Error::Protocol(format!(
            "{} 帧过大：{} 字节，上限 {MAX_FRAME_LEN}",
            message.kind(),
            payload.len()
        )));
    }
    write_raw_frame(writer, &payload).await
}

/// 读一帧控制消息。
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<ControlMessage>>
where
    R: AsyncRead + Unpin,
{
    match read_raw_frame(reader).await? {
        Some(payload) => Ok(Some(ControlMessage::decode(&payload)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::PROTOCOL_VERSION;

    #[tokio::test]
    async fn 多帧往返() {
        let (mut a, mut b) = tokio::io::duplex(1024);

        let sent = vec![
            ControlMessage::Ready,
            ControlMessage::RequestChunk { index: 7 },
            ControlMessage::Chunk {
                index: 7,
                data: vec![0x5a; 5000],
            },
            ControlMessage::KeepAlive,
        ];

        let sent_to_peer = sent.clone();

        let writer = tokio::spawn(async move {
            for message in &sent_to_peer {
                write_frame(&mut a, message).await.unwrap();
            }
        });

        for expected in &sent {
            let got = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(&got, expected);
        }

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn 干净关闭返回_none() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn 半截帧报错() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // 声称有 100 字节，实际只给 3 字节就关闭。
        tokio::spawn(async move {
            a.write_all(&100u32.to_le_bytes()).await.unwrap();
            a.write_all(&[1, 2, 3]).await.unwrap();
            drop(a);
        });
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(
            matches!(err, Error::Protocol(_)),
            "应报协议错误，实际 {err:?}"
        );
    }

    #[tokio::test]
    async fn 超大长度头被拒绝() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            a.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
            // 停在把长度头写完的状态
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "实际 {err:?}");
    }

    #[tokio::test]
    async fn 自定义上限比通用上限更严() {
        // 信令用小上限：同一个载荷在通用上限下能过，在小上限下必须被拒。
        let payload = vec![0u8; 1024];
        let (mut a, mut b) = tokio::io::duplex(4096);

        let outgoing = payload.clone();
        tokio::spawn(async move {
            write_raw_frame(&mut a, &outgoing).await.unwrap();
        });
        assert!(
            read_raw_frame_limited(&mut b, 4096)
                .await
                .unwrap()
                .is_some()
        );

        // 声称 1 KiB 但上限只有 64 字节，必须在分配前报错。
        let (mut a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            a.write_all(&1024u32.to_le_bytes()).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let err = read_raw_frame_limited(&mut b, 64).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "实际 {err:?}");

        // 写方向同样受上限约束。
        let (mut a, _b) = tokio::io::duplex(4096);
        let err = write_raw_frame_limited(&mut a, &payload, 64)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "实际 {err:?}");
    }

    #[tokio::test]
    async fn 版本号字段能穿过帧() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let message = ControlMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            node_id: crate::identity::NodeId::from_hex("00000000000000000000000000000001").unwrap(),
            public_key: [3u8; 32],
            nonce: [4u8; 32],
        };
        let clone = message.clone();
        tokio::spawn(async move { write_frame(&mut a, &message).await.unwrap() });
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), clone);
    }
}
