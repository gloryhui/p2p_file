//! P2P / QUIC 内存到内存测速。
//!
//! 测速只使用固定的内存 pattern：控制双向流负责协商和结果，数据使用独立的
//! QUIC 单向流连续发送/读取。这里不触碰文件、manifest、分片、BLAKE3 或 bitmap。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use clap::ValueEnum;
use quinn::{Connection, RecvStream, SendStream};

use crate::error::{Error, Result};
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::message::{ControlMessage, SpeedTestWireDirection};
use crate::transport::quic::{STREAM_FIRST_FRAME_TIMEOUT, TRANSFER_IDLE_TIMEOUT};

pub const DEFAULT_DURATION_SECS: u64 = 10;
pub const MIN_DURATION_SECS: u64 = 1;
pub const MAX_DURATION_SECS: u64 = 300;
pub const DEFAULT_BLOCK_SIZE: u32 = 1024 * 1024;
pub const MIN_BLOCK_SIZE: u32 = 16 * 1024;
pub const MAX_BLOCK_SIZE: u32 = 16 * 1024 * 1024;

const SPEEDTEST_PATTERN: u8 = 0xa5;

/// CLI 的测速方向。线上协议每次只跑一个方向，`Both` 在客户端顺序拆成两轮。
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SpeedTestDirection {
    #[value(name = "upload")]
    Upload,
    #[value(name = "download")]
    Download,
    #[value(name = "both")]
    Both,
}

impl SpeedTestDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Both => "both",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SpeedTestProgress {
    pub direction: SpeedTestDirection,
    pub elapsed: Duration,
    pub bytes: u64,
    pub mib_per_sec: f64,
    pub mbps: f64,
    pub rtt: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SpeedTestStats {
    pub sent_datagrams: u64,
    pub sent_bytes: u64,
    pub received_datagrams: u64,
    pub received_bytes: u64,
    pub cwnd: u64,
    pub current_mtu: u16,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub congestion_events: u64,
    pub rtt: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct SpeedTestReport {
    pub direction: SpeedTestDirection,
    pub remote: SocketAddr,
    pub bytes: u64,
    pub elapsed: Duration,
    pub stats: SpeedTestStats,
}

impl SpeedTestReport {
    pub fn mib_per_sec(self) -> f64 {
        rate_mib(self.bytes, self.elapsed)
    }

    pub fn mbps(self) -> f64 {
        rate_mbps(self.bytes, self.elapsed)
    }
}

/// 在客户端跑一轮或两轮测速。`progress` 只在大约每秒一次的节奏被调用。
pub async fn run_speedtest<F>(
    connection: &Connection,
    direction: SpeedTestDirection,
    duration: Duration,
    block_size: usize,
    mut progress: F,
) -> Result<Vec<SpeedTestReport>>
where
    F: FnMut(SpeedTestProgress),
{
    validate_options(duration, block_size)?;

    let directions = match direction {
        SpeedTestDirection::Upload => [Some(SpeedTestWireDirection::Upload), None],
        SpeedTestDirection::Download => [Some(SpeedTestWireDirection::Download), None],
        SpeedTestDirection::Both => [
            Some(SpeedTestWireDirection::Upload),
            Some(SpeedTestWireDirection::Download),
        ],
    };

    let mut reports = Vec::with_capacity(if direction == SpeedTestDirection::Both {
        2
    } else {
        1
    });
    for wire_direction in directions.into_iter().flatten() {
        reports.push(
            run_phase(
                connection,
                wire_direction,
                duration,
                block_size,
                &mut progress,
            )
            .await?,
        );
    }
    Ok(reports)
}

/// 服务端处理一条已经通过 QUIC、Ed25519 和 allow 校验的测速业务流。
pub async fn serve_speedtest(
    connection: &Connection,
    mut control_send: SendStream,
    mut control_recv: RecvStream,
    direction: SpeedTestWireDirection,
    duration_ms: u64,
    block_size: u32,
) -> Result<()> {
    let duration = match validate_wire_options(duration_ms, block_size) {
        Ok(duration) => duration,
        Err(err) => {
            let _ = write_control(
                &mut control_send,
                &ControlMessage::Abort {
                    reason: err.to_string(),
                },
            )
            .await;
            let _ = control_send.finish();
            return Err(err);
        }
    };
    write_control(&mut control_send, &ControlMessage::SpeedTestReady).await?;

    match direction {
        SpeedTestWireDirection::Upload => {
            let mut data_recv = accept_uni(connection).await?;
            let (observed_bytes, observed_elapsed) = tokio::time::timeout(
                duration + TRANSFER_IDLE_TIMEOUT,
                receive_payload(
                    connection,
                    SpeedTestDirection::Upload,
                    &mut data_recv,
                    block_size as usize,
                    &mut |_| {},
                ),
            )
            .await
            .map_err(|_| Error::Transport("测速 upload 超过声明时长仍未结束".into()))??;
            let claimed = read_speedtest_result(&mut control_recv).await?;
            if claimed.0 != observed_bytes {
                return Err(Error::Protocol(format!(
                    "测速 upload 字节数不一致：发送端 {}，接收端 {}",
                    claimed.0, observed_bytes
                )));
            }
            write_control(
                &mut control_send,
                &ControlMessage::SpeedTestResult {
                    bytes: observed_bytes,
                    elapsed_ms: elapsed_millis(observed_elapsed),
                },
            )
            .await?;
        }
        SpeedTestWireDirection::Download => {
            let mut data_send = open_uni(connection).await?;
            let (sent_bytes, sent_elapsed) = send_payload(
                connection,
                SpeedTestDirection::Download,
                &mut data_send,
                duration,
                block_size as usize,
                &mut |_| {},
            )
            .await?;
            finish_stream(&mut data_send, "关闭测速数据流")?;
            write_control(
                &mut control_send,
                &ControlMessage::SpeedTestResult {
                    bytes: sent_bytes,
                    elapsed_ms: elapsed_millis(sent_elapsed),
                },
            )
            .await?;
            let claimed = read_speedtest_result(&mut control_recv).await?;
            if claimed.0 != sent_bytes {
                return Err(Error::Protocol(format!(
                    "测速 download 字节数不一致：发送端 {}，接收端 {}",
                    sent_bytes, claimed.0
                )));
            }
        }
    }

    finish_stream(&mut control_send, "关闭测速控制流")?;
    Ok(())
}

fn validate_options(duration: Duration, block_size: usize) -> Result<()> {
    let millis = duration.as_millis();
    let min = u128::from(MIN_DURATION_SECS) * 1_000;
    let max = u128::from(MAX_DURATION_SECS) * 1_000;
    if !(min..=max).contains(&millis) {
        return Err(Error::Protocol(format!(
            "测速 duration 必须在 {MIN_DURATION_SECS}..={MAX_DURATION_SECS} 秒范围内"
        )));
    }
    if !(MIN_BLOCK_SIZE as usize..=MAX_BLOCK_SIZE as usize).contains(&block_size) {
        return Err(Error::Protocol(format!(
            "测速 block-size 必须在 {MIN_BLOCK_SIZE}..={MAX_BLOCK_SIZE} 字节范围内"
        )));
    }
    Ok(())
}

fn validate_wire_options(duration_ms: u64, block_size: u32) -> Result<Duration> {
    let duration = Duration::from_millis(duration_ms);
    validate_options(duration, block_size as usize)?;
    Ok(duration)
}

async fn run_phase<F>(
    connection: &Connection,
    direction: SpeedTestWireDirection,
    duration: Duration,
    block_size: usize,
    progress: &mut F,
) -> Result<SpeedTestReport>
where
    F: FnMut(SpeedTestProgress),
{
    let (mut control_send, mut control_recv) = open_bi(connection).await?;
    write_control(
        &mut control_send,
        &ControlMessage::SpeedTestOpen {
            direction,
            duration_ms: duration.as_millis() as u64,
            block_size: block_size as u32,
        },
    )
    .await?;
    expect_speedtest_ready(&mut control_recv).await?;

    // 这里才截取 stats 起点：QUIC / 应用握手与测速控制协商都不进入数据阶段。
    let before = connection.stats();
    let (bytes, elapsed) = match direction {
        SpeedTestWireDirection::Upload => {
            let mut data_send = open_uni(connection).await?;
            let result = send_payload(
                connection,
                SpeedTestDirection::Upload,
                &mut data_send,
                duration,
                block_size,
                progress,
            )
            .await?;
            finish_stream(&mut data_send, "关闭测速数据流")?;
            write_control(
                &mut control_send,
                &ControlMessage::SpeedTestResult {
                    bytes: result.0,
                    elapsed_ms: elapsed_millis(result.1),
                },
            )
            .await?;
            finish_stream(&mut control_send, "关闭测速控制流")?;
            let peer = read_speedtest_result(&mut control_recv).await?;
            let result = upload_result_from_peer(result, peer)?;
            wait_control_eof(&mut control_recv).await?;
            result
        }
        SpeedTestWireDirection::Download => {
            let mut data_recv = accept_uni(connection).await?;
            let result = receive_payload(
                connection,
                SpeedTestDirection::Download,
                &mut data_recv,
                block_size,
                progress,
            )
            .await?;
            let peer = read_speedtest_result(&mut control_recv).await?;
            if peer.0 != result.0 {
                return Err(Error::Protocol(format!(
                    "测速 download 字节数不一致：对端 {}，本机 {}",
                    peer.0, result.0
                )));
            }
            write_control(
                &mut control_send,
                &ControlMessage::SpeedTestResult {
                    bytes: result.0,
                    elapsed_ms: elapsed_millis(result.1),
                },
            )
            .await?;
            finish_stream(&mut control_send, "关闭测速控制流")?;
            wait_control_eof(&mut control_recv).await?;
            result
        }
    };

    let after = connection.stats();
    Ok(SpeedTestReport {
        direction: match direction {
            SpeedTestWireDirection::Upload => SpeedTestDirection::Upload,
            SpeedTestWireDirection::Download => SpeedTestDirection::Download,
        },
        remote: connection.remote_address(),
        bytes,
        elapsed,
        stats: stats_delta(&before, &after, connection.rtt()),
    })
}

async fn open_bi(connection: &Connection) -> Result<(SendStream, RecvStream)> {
    tokio::time::timeout(STREAM_FIRST_FRAME_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| Error::Transport("打开测速控制流超时".into()))?
        .map_err(|err| Error::Transport(format!("打开测速控制流失败: {err}")))
}

async fn open_uni(connection: &Connection) -> Result<SendStream> {
    tokio::time::timeout(TRANSFER_IDLE_TIMEOUT, connection.open_uni())
        .await
        .map_err(|_| Error::Transport("打开测速数据流超时".into()))?
        .map_err(|err| Error::Transport(format!("打开测速数据流失败: {err}")))
}

async fn accept_uni(connection: &Connection) -> Result<RecvStream> {
    tokio::time::timeout(TRANSFER_IDLE_TIMEOUT, connection.accept_uni())
        .await
        .map_err(|_| Error::Transport("等待测速数据流超时".into()))?
        .map_err(|err| Error::Transport(format!("接受测速数据流失败: {err}")))
}

async fn write_control(send: &mut SendStream, message: &ControlMessage) -> Result<()> {
    tokio::time::timeout(TRANSFER_IDLE_TIMEOUT, write_frame(send, message))
        .await
        .map_err(|_| Error::Transport("测速控制消息写入超时".into()))??;
    Ok(())
}

async fn expect_speedtest_ready(recv: &mut RecvStream) -> Result<()> {
    match read_speedtest_control(recv).await? {
        ControlMessage::SpeedTestReady => Ok(()),
        ControlMessage::Abort { reason } => Err(Error::Protocol(format!("对端拒绝测速: {reason}"))),
        other => Err(Error::Protocol(format!(
            "期待 SpeedTestReady，收到 {}",
            other.kind()
        ))),
    }
}

async fn read_speedtest_result(recv: &mut RecvStream) -> Result<(u64, u64)> {
    match read_speedtest_control(recv).await? {
        ControlMessage::SpeedTestResult { bytes, elapsed_ms } => {
            if bytes == 0 || elapsed_ms == 0 {
                return Err(Error::Protocol(
                    "测速结果必须包含正数 bytes 和 elapsed_ms".into(),
                ));
            }
            Ok((bytes, elapsed_ms))
        }
        other => Err(Error::Protocol(format!(
            "期待 SpeedTestResult，收到 {}",
            other.kind()
        ))),
    }
}

async fn read_speedtest_control(recv: &mut RecvStream) -> Result<ControlMessage> {
    tokio::time::timeout(TRANSFER_IDLE_TIMEOUT, read_frame(recv))
        .await
        .map_err(|_| Error::Transport("等待测速控制消息超时".into()))??
        .ok_or_else(|| Error::Protocol("测速控制流提前关闭".into()))
}

async fn wait_control_eof(recv: &mut RecvStream) -> Result<()> {
    let next = tokio::time::timeout(TRANSFER_IDLE_TIMEOUT, read_frame(recv))
        .await
        .map_err(|_| Error::Transport("等待测速控制流关闭超时".into()))??;
    match next {
        None => Ok(()),
        Some(message) => Err(Error::Protocol(format!(
            "测速结果后收到意外控制消息 {}",
            message.kind()
        ))),
    }
}

async fn send_payload<F>(
    connection: &Connection,
    direction: SpeedTestDirection,
    send: &mut SendStream,
    duration: Duration,
    block_size: usize,
    progress: &mut F,
) -> Result<(u64, Duration)>
where
    F: FnMut(SpeedTestProgress),
{
    let buffer = vec![SPEEDTEST_PATTERN; block_size];
    let start = Instant::now();
    let deadline = start + duration;
    let mut bytes = 0u64;
    let mut next_progress = Duration::from_secs(1);

    while Instant::now() < deadline {
        tokio::time::timeout(
            TRANSFER_IDLE_TIMEOUT,
            tokio::io::AsyncWriteExt::write_all(send, &buffer),
        )
        .await
        .map_err(|_| Error::Transport("测速数据流写入空闲超时".into()))??;
        bytes = bytes.saturating_add(buffer.len() as u64);
        emit_progress_if_due(
            progress,
            direction,
            bytes,
            start.elapsed(),
            &mut next_progress,
            connection.rtt(),
        );
    }

    Ok((bytes, start.elapsed()))
}

async fn receive_payload<F>(
    connection: &Connection,
    direction: SpeedTestDirection,
    recv: &mut RecvStream,
    block_size: usize,
    progress: &mut F,
) -> Result<(u64, Duration)>
where
    F: FnMut(SpeedTestProgress),
{
    let mut buffer = vec![0u8; block_size];
    let start = Instant::now();
    let mut bytes = 0u64;
    let mut next_progress = Duration::from_secs(1);

    loop {
        let read = tokio::time::timeout(
            TRANSFER_IDLE_TIMEOUT,
            tokio::io::AsyncReadExt::read(&mut *recv, &mut buffer),
        )
        .await
        .map_err(|_| Error::Transport("测速数据流读取空闲超时".into()))??;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        emit_progress_if_due(
            progress,
            direction,
            bytes,
            start.elapsed(),
            &mut next_progress,
            connection.rtt(),
        );
    }

    let elapsed = start.elapsed();
    if bytes == 0 {
        return Err(Error::Protocol("测速数据流没有收到 payload".into()));
    }
    Ok((bytes, elapsed))
}

fn emit_progress_if_due<F>(
    progress: &mut F,
    direction: SpeedTestDirection,
    bytes: u64,
    elapsed: Duration,
    next_progress: &mut Duration,
    rtt: Duration,
) where
    F: FnMut(SpeedTestProgress),
{
    if elapsed < *next_progress {
        return;
    }
    let rate = elapsed.max(Duration::from_nanos(1));
    progress(SpeedTestProgress {
        direction,
        elapsed,
        bytes,
        mib_per_sec: rate_mib(bytes, rate),
        mbps: rate_mbps(bytes, rate),
        rtt,
    });
    *next_progress = elapsed + Duration::from_secs(1);
}

fn finish_stream(stream: &mut SendStream, what: &str) -> Result<()> {
    stream
        .finish()
        .map_err(|_| Error::Transport(format!("{what}失败：连接已关闭")))
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().max(1) as u64
}

/// upload 的吞吐必须以接收端实际观测到的数据阶段耗时为准。
///
/// 发送端的 `write_all` / `finish` 只表示本端完成写入或提交发送，不能证明对端
/// 已经完整收到 payload；因此这里只用发送端 bytes 做一致性校验，最终 elapsed
/// 来自 peer 返回的 receiver observation。
fn upload_result_from_peer(sender: (u64, Duration), peer: (u64, u64)) -> Result<(u64, Duration)> {
    if peer.0 != sender.0 {
        return Err(Error::Protocol(format!(
            "测速 upload 字节数不一致：本机 {}，对端 {}",
            sender.0, peer.0
        )));
    }
    if peer.1 == 0 {
        return Err(Error::Protocol(
            "测速 upload 对端返回了无效的 elapsed_ms".into(),
        ));
    }
    Ok((peer.0, Duration::from_millis(peer.1)))
}

fn rate_mib(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64().max(f64::MIN_POSITIVE)
}

fn rate_mbps(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 * 8.0 / 1_000_000.0 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE)
}

fn stats_delta(
    before: &quinn::ConnectionStats,
    after: &quinn::ConnectionStats,
    rtt: Duration,
) -> SpeedTestStats {
    SpeedTestStats {
        sent_datagrams: after
            .udp_tx
            .datagrams
            .saturating_sub(before.udp_tx.datagrams),
        sent_bytes: after.udp_tx.bytes.saturating_sub(before.udp_tx.bytes),
        received_datagrams: after
            .udp_rx
            .datagrams
            .saturating_sub(before.udp_rx.datagrams),
        received_bytes: after.udp_rx.bytes.saturating_sub(before.udp_rx.bytes),
        cwnd: after.path.cwnd,
        current_mtu: after.path.current_mtu,
        lost_packets: after
            .path
            .lost_packets
            .saturating_sub(before.path.lost_packets),
        lost_bytes: after.path.lost_bytes.saturating_sub(before.path.lost_bytes),
        congestion_events: after
            .path
            .congestion_events
            .saturating_sub(before.path.congestion_events),
        rtt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::transport::handshake::{handshake_initiator, handshake_responder};
    use crate::transport::quic::{ChannelBinding, client_endpoint, server_endpoint};

    #[test]
    fn 方向字符串稳定() {
        assert_eq!(SpeedTestDirection::Upload.as_str(), "upload");
        assert_eq!(SpeedTestDirection::Download.as_str(), "download");
        assert_eq!(SpeedTestDirection::Both.as_str(), "both");
    }

    #[test]
    fn 参数边界明确() {
        assert!(
            validate_options(
                Duration::from_secs(MIN_DURATION_SECS),
                MIN_BLOCK_SIZE as usize
            )
            .is_ok()
        );
        assert!(
            validate_options(
                Duration::from_secs(MAX_DURATION_SECS),
                MAX_BLOCK_SIZE as usize
            )
            .is_ok()
        );
        assert!(validate_options(Duration::from_millis(999), MIN_BLOCK_SIZE as usize).is_err());
        assert!(validate_options(Duration::from_secs(1), (MIN_BLOCK_SIZE - 1) as usize).is_err());
        assert!(validate_options(Duration::from_secs(1), (MAX_BLOCK_SIZE + 1) as usize).is_err());
    }

    #[test]
    fn upload最终结果使用接收端elapsed而不是发送端elapsed() {
        let sender = (1024, Duration::from_secs(99));
        let peer = (1024, 37);
        let result = upload_result_from_peer(sender, peer).unwrap();
        assert_eq!(result.0, 1024);
        assert_eq!(result.1, Duration::from_millis(37));
        assert_ne!(result.1, sender.1);
    }

    #[tokio::test]
    async fn 本地_quic_测速支持两方向且both顺序执行() {
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("服务端应收到连接");
            let connection = incoming.await.expect("QUIC 握手应成功");
            let binding = ChannelBinding::from_connection(&connection).unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            handshake_responder(&mut send, &mut recv, &server_identity, &binding)
                .await
                .unwrap();
            let _ = send.finish();

            loop {
                let Ok((send, mut recv)) = connection.accept_bi().await else {
                    break;
                };
                let Ok(ControlMessage::SpeedTestOpen {
                    direction,
                    duration_ms,
                    block_size,
                }) = read_speedtest_control(&mut recv).await
                else {
                    break;
                };
                serve_speedtest(&connection, send, recv, direction, duration_ms, block_size)
                    .await
                    .unwrap();
            }
        });

        let connection = crate::transport::quic::connect(&client, server_addr, "p2pfile")
            .await
            .unwrap();
        let binding = ChannelBinding::from_connection(&connection).unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        handshake_initiator(&mut send, &mut recv, &client_identity, &binding)
            .await
            .unwrap();
        let reports = tokio::time::timeout(
            Duration::from_secs(10),
            run_speedtest(
                &connection,
                SpeedTestDirection::Both,
                Duration::from_secs(1),
                MIN_BLOCK_SIZE as usize,
                |_| {},
            ),
        )
        .await
        .expect("测速不应挂死")
        .unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].direction, SpeedTestDirection::Upload);
        assert_eq!(reports[1].direction, SpeedTestDirection::Download);
        assert!(reports.iter().all(|report| report.bytes > 0));
        assert!(reports.iter().all(|report| report.stats.current_mtu > 0));
        connection.close(0u32.into(), b"test done");
        client.wait_idle().await;
        server_task.abort();
    }

    #[tokio::test]
    async fn 对端断开时测速返回错误而不是挂死() {
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let binding = ChannelBinding::from_connection(&connection).unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            handshake_responder(&mut send, &mut recv, &server_identity, &binding)
                .await
                .unwrap();
            let _ = send.finish();
            // 让客户端有机会读到 Ready，随后再模拟测速前的连接断开。
            tokio::time::sleep(Duration::from_millis(50)).await;
            connection.close(0u32.into(), b"disconnect test");
        });

        let connection = crate::transport::quic::connect(&client, server_addr, "p2pfile")
            .await
            .unwrap();
        let binding = ChannelBinding::from_connection(&connection).unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        handshake_initiator(&mut send, &mut recv, &client_identity, &binding)
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_speedtest(
                &connection,
                SpeedTestDirection::Upload,
                Duration::from_secs(1),
                MIN_BLOCK_SIZE as usize,
                |_| {},
            ),
        )
        .await
        .expect("对端断开后测速不应挂死");
        assert!(result.is_err(), "连接关闭后测速必须返回明确错误");
        server_task.await.unwrap();
        client.wait_idle().await;
    }
}
