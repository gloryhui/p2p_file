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
    use crate::protocol::frame::{read_frame, write_frame};
    use crate::protocol::manifest::MIN_CHUNK_SIZE;
    use crate::protocol::message::ControlMessage;
    use crate::transport::handshake::{handshake_initiator, handshake_responder};
    use crate::transport::quic::ChannelBinding;
    use crate::transport::quic::{
        ACCEPT_FIRST_BI_STREAM_TIMEOUT, STREAM_FIRST_FRAME_TIMEOUT, TRANSFER_IDLE_TIMEOUT,
        client_endpoint, connect, server_endpoint,
    };
    use std::fs;
    use std::io::Write;
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

    /// bitmap 声称已有的分片如果磁盘内容已损坏，恢复时必须清位并再次请求。
    #[tokio::test]
    async fn 损坏的续传分片会被重新请求() {
        let dir = temp_dir("resume_corrupt_chunk");
        let send_dir = dir.join("send");
        let recv_dir = dir.join("recv");
        fs::create_dir_all(&send_dir).unwrap();
        fs::create_dir_all(&recv_dir).unwrap();

        let content: Vec<u8> = (0..(MIN_CHUNK_SIZE as usize * 2))
            .map(|i| (i % 233) as u8)
            .collect();
        let source = send_dir.join("corrupt-resume.bin");
        fs::write(&source, &content).unwrap();
        let manifest = manifest_from_path(&source, MIN_CHUNK_SIZE).unwrap();

        {
            let mut download =
                crate::storage::PartialDownload::create(&recv_dir, manifest.clone()).unwrap();
            download
                .write_chunk(0, &content[..MIN_CHUNK_SIZE as usize])
                .unwrap();
        }
        let temp = crate::storage::PartialDownload::temp_path_for(&recv_dir, &manifest);
        let mut file = fs::OpenOptions::new().write(true).open(&temp).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();

        let alice = Identity::generate();
        let bob = Identity::generate();
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let recv_dir_for_task = recv_dir.clone();
        let receiver_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let report = receive_file(&connection, &bob, &recv_dir_for_task).await;
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
        assert_eq!(send_report.chunks_skipped, 0, "损坏分片不能被跳过");
        assert_eq!(send_report.chunks_sent, 2, "两片都应重新发送");
        assert_eq!(fs::read(receive_report.output_path).unwrap(), content);

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

    /// finalize/rename 失败时，接收端只能发送 Abort；发送端绝不能收到成功报告。
    ///
    /// 让 unique_path 穷尽候选名后把 `.part` 改名到一个目录，稳定地产生 rename
    /// 失败，不依赖运行用户是否有权限修改目录。
    #[tokio::test]
    async fn finalize失败时发送端能感知失败() {
        let dir = temp_dir("finalize_failure");
        let send_dir = dir.join("send");
        let recv_dir = dir.join("recv");
        fs::create_dir_all(&send_dir).unwrap();
        fs::create_dir_all(&recv_dir).unwrap();

        let content = vec![0x5au8; MIN_CHUNK_SIZE as usize];
        let source = send_dir.join("finalize.bin");
        fs::write(&source, &content).unwrap();

        fs::create_dir(recv_dir.join("finalize.bin")).unwrap();
        for counter in 1..10_000u32 {
            fs::create_dir(recv_dir.join(format!("finalize ({counter}).bin"))).unwrap();
        }

        let alice = Identity::generate();
        let bob = Identity::generate();
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let recv_dir_for_task = recv_dir.clone();

        let receiver_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let result = receive_file(&connection, &bob, &recv_dir_for_task).await;
            // 等发送端读完 Abort 后主动关闭连接。
            connection.closed().await;
            result
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let send_result = send_file(&connection, &alice, &source, MIN_CHUNK_SIZE).await;
        let send_error = send_result.expect_err("receiver finalize 失败时 sender 不能成功");
        assert!(
            send_error.to_string().contains("finalize")
                || send_error.to_string().contains("保存")
                || send_error.to_string().contains("rename"),
            "sender 应看到 finalize 失败原因，实际: {send_error}"
        );
        connection.close(0u32.into(), b"finalize failed");
        client.wait_idle().await;

        let receive_error = tokio::time::timeout(Duration::from_secs(10), receiver_task)
            .await
            .expect("接收端应在 10 秒内结束")
            .unwrap()
            .expect_err("receiver finalize 失败必须返回错误");
        assert!(
            receive_error.to_string().contains("I/O")
                || receive_error.to_string().contains("os error")
        );
        assert!(!recv_dir.join("finalize.bin").is_file());

        fs::remove_dir_all(&dir).unwrap();
    }

    /// 没有 finalize 成功证明时，receiver 发送 Bye 不能让 sender 假报成功。
    #[tokio::test]
    async fn receiver_only_sends_bye_sender_fails() {
        let dir = temp_dir("sender_bye_without_complete");
        let source = dir.join("payload.bin");
        fs::write(&source, vec![0x37u8; MIN_CHUNK_SIZE as usize]).unwrap();

        let sender_identity = Identity::generate();
        let receiver_identity = Identity::generate();
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let receiver_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let binding = ChannelBinding::from_connection(&connection).unwrap();
            let (mut handshake_send, mut handshake_recv) = connection.accept_bi().await.unwrap();
            handshake_responder(
                &mut handshake_send,
                &mut handshake_recv,
                &receiver_identity,
                &binding,
            )
            .await
            .unwrap();
            let _ = handshake_send.finish();

            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let manifest = match read_frame(&mut recv).await.unwrap().unwrap() {
                ControlMessage::Manifest(manifest) => *manifest,
                other => panic!("sender 应先发送 Manifest，实际 {}", other.kind()),
            };
            write_frame(
                &mut send,
                &ControlMessage::Resume {
                    have: ChunkBitmap::new(manifest.chunk_count()).to_bytes(),
                },
            )
            .await
            .unwrap();
            write_frame(&mut send, &ControlMessage::Bye).await.unwrap();
            let _ = send.finish();
            connection.closed().await;
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let result = send_file(&connection, &sender_identity, &source, MIN_CHUNK_SIZE).await;
        let error = result.expect_err("没有 Complete 时 sender 必须失败");
        assert!(
            error.to_string().contains("Complete"),
            "应明确说明缺少 Complete，实际: {error}"
        );
        connection.close(0u32.into(), b"test complete required");
        client.wait_idle().await;
        tokio::time::timeout(Duration::from_secs(10), receiver_task)
            .await
            .expect("伪 receiver 应在 10 秒内结束")
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn receiver_handshake_silence_times_out() {
        let dir = temp_dir("receiver_handshake_timeout");
        let receiver = Identity::generate();
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let recv_dir = dir.clone();
        let task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            receive_file(&connection, &receiver, &recv_dir).await
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(ACCEPT_FIRST_BI_STREAM_TIMEOUT + Duration::from_secs(1)).await;
        let error = task.await.unwrap().expect_err("静默连接必须超时");
        assert!(error.to_string().contains("握手流超时"));
        connection.close(0u32.into(), b"timeout");
        client.wait_idle().await;
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stream_first_frame_silence_times_out() {
        let dir = temp_dir("stream_first_frame_timeout");
        let sender = Identity::generate();
        let receiver = Identity::generate();
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let recv_dir = dir.clone();
        let task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            receive_file(&connection, &receiver, &recv_dir).await
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let binding = ChannelBinding::from_connection(&connection).unwrap();
        let (mut handshake_send, mut handshake_recv) = connection.open_bi().await.unwrap();
        handshake_initiator(&mut handshake_send, &mut handshake_recv, &sender, &binding)
            .await
            .unwrap();
        handshake_send.finish().unwrap();
        let (_send, _recv) = connection.open_bi().await.unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(STREAM_FIRST_FRAME_TIMEOUT + Duration::from_secs(1)).await;
        let error = task.await.unwrap().expect_err("没有首帧必须超时");
        assert!(
            error.to_string().contains("超时"),
            "应当是首帧阶段超时，实际: {error}"
        );
        connection.close(0u32.into(), b"timeout");
        client.wait_idle().await;
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn transfer_silence_times_out_but_is_not_a_total_file_timeout() {
        let dir = temp_dir("transfer_idle_timeout");
        let sender = Identity::generate();
        let receiver = Identity::generate();
        let source = dir.join("payload.bin");
        fs::write(&source, vec![0x42u8; MIN_CHUNK_SIZE as usize]).unwrap();
        let manifest = manifest_from_path(&source, MIN_CHUNK_SIZE).unwrap();
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let recv_dir = dir.clone();
        let task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            receive_file(&connection, &receiver, &recv_dir).await
        });

        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = connect(&client, server_addr, "127.0.0.1").await.unwrap();
        let binding = ChannelBinding::from_connection(&connection).unwrap();
        let (mut handshake_send, mut handshake_recv) = connection.open_bi().await.unwrap();
        handshake_initiator(&mut handshake_send, &mut handshake_recv, &sender, &binding)
            .await
            .unwrap();
        handshake_send.finish().unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_frame(&mut send, &ControlMessage::Manifest(Box::new(manifest)))
            .await
            .unwrap();
        assert!(matches!(
            read_frame(&mut recv).await.unwrap(),
            Some(ControlMessage::Resume { .. })
        ));
        assert!(matches!(
            read_frame(&mut recv).await.unwrap(),
            Some(ControlMessage::RequestChunk { .. })
        ));
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(TRANSFER_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        let error = task.await.unwrap().expect_err("没有分片流量必须超时");
        assert!(
            error.to_string().contains("超时"),
            "应当是传输空闲超时，实际: {error}"
        );
        connection.close(0u32.into(), b"timeout");
        client.wait_idle().await;
        fs::remove_dir_all(&dir).unwrap();
    }
}
