//! 分片、续传、发送与接收。

pub mod chunker;
pub mod receiver;
pub mod resume;
pub mod sender;

pub use chunker::{
    manifest_from_path, manifest_from_path_default, manifest_from_reader, read_chunk,
};
pub use receiver::{DEFAULT_WINDOW, ReceiveReport, receive_file};
pub use resume::ChunkBitmap;
pub use sender::{SendReport, send_file};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::protocol::manifest::MIN_CHUNK_SIZE;
    use crate::transport::quic::{client_endpoint, connect, server_endpoint};
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("p2p_file_e2e_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 端到端：真实的 QUIC 连接 + 握手 + 清单 + 分片 + 校验 + 落盘。
    #[tokio::test]
    async fn 环回地址上端到端传一个文件() {
        let dir = temp_dir("roundtrip");
        let send_dir = dir.join("send");
        let recv_dir = dir.join("recv");
        fs::create_dir_all(&send_dir).unwrap();
        fs::create_dir_all(&recv_dir).unwrap();

        // 两片多一点，确保跨分片边界。
        let content: Vec<u8> = (0..(MIN_CHUNK_SIZE as usize * 2 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        let source = send_dir.join("payload.bin");
        fs::write(&source, &content).unwrap();

        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_id = alice.node_id();
        let bob_id = bob.node_id();

        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let recv_dir_for_task = recv_dir.clone();

        let receiver_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let report = receive_file(&connection, &bob, &recv_dir_for_task).await;
            // 等发送端主动关闭，避免提前把连接拆了。
            connection.closed().await;
            report
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let send_report = send_file(&connection, &alice, &source, MIN_CHUNK_SIZE)
            .await
            .unwrap();
        connection.close(0u32.into(), b"done");
        client.wait_idle().await;

        let receive_report = tokio::time::timeout(Duration::from_secs(10), receiver_task)
            .await
            .expect("接收端应在 10 秒内结束")
            .unwrap()
            .expect("接收应当成功");

        // 双方对文件的认知一致。
        assert_eq!(send_report.peer_node_id, bob_id);
        assert_eq!(receive_report.peer_node_id, alice_id);
        assert_eq!(send_report.file_name, "payload.bin");
        assert_eq!(receive_report.file_name, "payload.bin");
        assert_eq!(send_report.total_len, content.len() as u64);
        assert_eq!(receive_report.total_len, content.len() as u64);
        assert_eq!(send_report.chunk_count, 3);
        assert_eq!(receive_report.chunk_count, 3);
        assert_eq!(send_report.chunks_sent, 3);
        assert_eq!(receive_report.chunks_received, 3);
        assert_eq!(send_report.chunks_skipped, 0, "首次传输没有可跳过的分片");

        // 落盘内容逐字节一致。
        let received = fs::read(&receive_report.output_path).unwrap();
        assert_eq!(received.len(), content.len());
        assert_eq!(received, content);

        // 临时文件和位图应当都清理干净了。
        let leftovers: Vec<_> = fs::read_dir(&recv_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".part") || name.ends_with(".bitmap"))
            .collect();
        assert!(leftovers.is_empty(), "残留文件未清理: {leftovers:?}");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// 对端中途断线时，已收到的分片必须留在盘上，下次能接着传。
    #[tokio::test]
    async fn 断线后能续传剩下的分片() {
        let dir = temp_dir("resume");
        let send_dir = dir.join("send");
        let recv_dir = dir.join("recv");
        fs::create_dir_all(&send_dir).unwrap();
        fs::create_dir_all(&recv_dir).unwrap();

        let content: Vec<u8> = (0..(MIN_CHUNK_SIZE as usize * 4 + 3))
            .map(|i| (i % 239) as u8)
            .collect();
        let source = send_dir.join("resume.bin");
        fs::write(&source, &content).unwrap();

        let manifest = manifest_from_path(&source, MIN_CHUNK_SIZE).unwrap();
        assert_eq!(manifest.chunk_count(), 5);

        // 先手工造一个「传了两片就断了」的现场。
        {
            let mut download =
                crate::storage::PartialDownload::create(&recv_dir, manifest.clone()).unwrap();
            let mut file = fs::File::open(&source).unwrap();
            for index in 0..2u32 {
                let (offset, len) = manifest.chunk_range(index).unwrap();
                let data = read_chunk(&mut file, offset, len).unwrap();
                download.write_chunk(index, &data).unwrap();
            }
        }

        // 现在重新走一次完整传输：对端应当跳过已有的两片。
        let alice = Identity::generate();
        let bob = Identity::generate();
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let recv_dir_clone = recv_dir.clone();

        let receiver_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let report = receive_file(&connection, &bob, &recv_dir_clone).await;
            connection.closed().await;
            report
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let send_report = send_file(&connection, &alice, &source, MIN_CHUNK_SIZE)
            .await
            .unwrap();
        connection.close(0u32.into(), b"done");
        client.wait_idle().await;

        let receive_report = tokio::time::timeout(Duration::from_secs(10), receiver_task)
            .await
            .expect("接收端应在 10 秒内结束")
            .unwrap()
            .expect("接收应当成功");

        assert_eq!(send_report.chunks_skipped, 2, "对端已有的两片不该重发");
        assert_eq!(send_report.chunks_sent, 3, "只该发缺的三片");
        assert_eq!(receive_report.chunks_received, 3);
        assert_eq!(fs::read(&receive_report.output_path).unwrap(), content);

        fs::remove_dir_all(&dir).unwrap();
    }

    /// 对端声明自己有某片、实际却没有，收尾时必须报错而不是产出坏文件。
    #[tokio::test]
    async fn 收尾时发现缺片会报错() {
        let dir = temp_dir("missing");
        let send_dir = dir.join("send");
        let recv_dir = dir.join("recv");
        fs::create_dir_all(&send_dir).unwrap();
        fs::create_dir_all(&recv_dir).unwrap();

        let content = vec![1u8; MIN_CHUNK_SIZE as usize * 2];
        let source = send_dir.join("partial.bin");
        fs::write(&source, &content).unwrap();
        let manifest = manifest_from_path(&source, MIN_CHUNK_SIZE).unwrap();

        // 只写第一片，制造「缺片」现场。
        {
            let mut download =
                crate::storage::PartialDownload::create(&recv_dir, manifest.clone()).unwrap();
            download
                .write_chunk(0, &content[..MIN_CHUNK_SIZE as usize])
                .unwrap();
        }

        // 单侧验证：没传完的下载不允许收尾。
        let download =
            crate::storage::PartialDownload::create(&recv_dir, manifest.clone()).unwrap();
        assert!(!download.is_complete());
        assert_eq!(download.missing(), vec![1]);
        assert!(download.finalize().is_err(), "缺片时 finalize 必须失败");

        // 磁盘上不应该出现正式文件名。
        assert!(!recv_dir.join("partial.bin").exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
