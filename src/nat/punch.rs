//! UDP 打洞：双方同时向对方的公网端点发包，让各自的 NAT 建立映射并放行回包。
//!
//! 关键在「同时」。NAT 只在**出站包**穿过时建立映射；如果只有一方先发，
//! 它的包会被对方的 NAT 丢掉，而且很多 NAT 的入站包不会主动建映射。
//! 两边都在发，两边的 pinhole 就会在同一时间窗内打开。
//!
//! 现实中通常需要一个中继节点帮忙对齐时机（libp2p 的 DCUtR 就是这么做的）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::error::{Error, Result};

/// 探测包的魔术前缀，用来把自己发的包和别人的数据区分开。
pub const PROBE_MAGIC: &[u8] = b"P2PF-PUNCH/1";

/// 打洞参数。
#[derive(Clone, Copy, Debug)]
pub struct PunchConfig {
    /// 每次尝试之间等多久。
    pub interval: Duration,
    /// 最多尝试多少次。
    pub attempts: u32,
}

impl Default for PunchConfig {
    fn default() -> Self {
        // 大约 6 秒；对端若在这段时间里没回，基本可以认为打不通了。
        Self {
            interval: Duration::from_millis(200),
            attempts: 30,
        }
    }
}

/// 构造一个探测包。
pub fn probe_packet() -> Vec<u8> {
    let mut packet = PROBE_MAGIC.to_vec();
    let padding: [u8; 16] = rand::random();
    packet.extend_from_slice(&padding);
    packet
}

/// 判断是不是本协议的探测包。
pub fn is_probe(data: &[u8]) -> bool {
    data.starts_with(PROBE_MAGIC)
}

/// 向 `remote` 打洞，直到收到回应。
///
/// 返回实际收到回包的那个地址（正常情况下等于 `remote`）。
///
/// `socket` 必须是**已经确定了本地端口**的那个 socket——映射是按本地端口
/// 分配的，临时新建一个 socket 问出来的地址对打洞没有意义。
pub async fn simultaneous_open(
    socket: &UdpSocket,
    remote: SocketAddr,
    config: &PunchConfig,
) -> Result<SocketAddr> {
    let probe = probe_packet();
    let mut buffer = vec![0u8; 2048];

    for attempt in 0..config.attempts {
        socket.send_to(&probe, remote).await?;

        match tokio::time::timeout(config.interval, socket.recv_from(&mut buffer)).await {
            // 收到包了。判断是不是我们期待的一方。
            Ok(Ok((len, from))) => {
                if from == remote {
                    if is_probe(&buffer[..len]) {
                        tracing::debug!(%remote, attempt, "打洞成功，收到对端探测包");
                    } else {
                        tracing::debug!(%remote, attempt, "打洞成功，收到对端数据包");
                    }
                    return Ok(from);
                }
                // 别人发来的包（比如 STUN 响应）不是成功信号，继续等。
                tracing::trace!(%from, "忽略来自非目标地址的包");
            }
            Ok(Err(err)) => return Err(err.into()),
            // 超时，再试一次。
            Err(_) => {
                tracing::trace!(%remote, attempt, "本次探测无响应");
            }
        }
    }

    Err(Error::Transport(format!(
        "打洞失败：向 {remote} 尝试 {} 次（{:?}）都没收到回应",
        config.attempts, config.interval
    )))
}

/// 保活循环：定期发探测包，维持 NAT 映射不被回收。
///
/// UDP 映射的空闲超时通常在 30~120 秒，具体看 NAT 实现。`shutdown` 收到
/// `true` 时退出。
pub async fn keepalive_loop(
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let probe = probe_packet();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                socket.send_to(&probe, remote).await?;
            }
            result = shutdown.changed() => {
                // 发送端被 drop 也算该退出了。
                if result.is_err() || *shutdown.borrow() {
                    tracing::debug!(%remote, "保活循环退出");
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 探测包可识别() {
        let probe = probe_packet();
        assert!(is_probe(&probe));
        assert!(probe.len() > PROBE_MAGIC.len());
        assert!(!is_probe(b"hello"));
        assert!(!is_probe(b""));
        // 每次的填充不同，避免被中间设备按固定内容去重或缓存。
        assert_ne!(probe_packet(), probe_packet());
    }

    #[tokio::test]
    async fn 双方同时打洞能打通() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let config = PunchConfig {
            interval: Duration::from_millis(100),
            attempts: 20,
        };

        let (result_a, result_b) = tokio::join!(
            simultaneous_open(&a, b_addr, &config),
            simultaneous_open(&b, a_addr, &config),
        );

        assert_eq!(result_a.unwrap(), b_addr);
        assert_eq!(result_b.unwrap(), a_addr);
    }

    #[tokio::test]
    async fn 对端无响应则最终失败() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // 一个没人监听的本地端口。
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let config = PunchConfig {
            interval: Duration::from_millis(20),
            attempts: 3,
        };
        // 收不到回应，或者收到 ICMP 端口不可达，两种都算失败。
        assert!(
            simultaneous_open(&socket, dead_addr, &config)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn 忽略无关地址发来的包() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger_addr = stranger.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_addr = socket.local_addr().unwrap();

        // 陌生人往我们的 socket 上灌包，不应被当成打洞成功。
        let noise = tokio::spawn(async move {
            for _ in 0..5 {
                let _ = stranger.send_to(b"noise", socket_addr).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        // 目标在稍后回应。
        let responder = tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            loop {
                let (len, from) = target.recv_from(&mut buffer).await.unwrap();
                if is_probe(&buffer[..len]) {
                    let _ = target.send_to(&probe_packet(), from).await;
                    break;
                }
            }
        });

        let config = PunchConfig {
            interval: Duration::from_millis(50),
            attempts: 30,
        };
        let result = simultaneous_open(&socket, target_addr, &config)
            .await
            .unwrap();
        assert_eq!(result, target_addr);
        assert_ne!(result, stranger_addr);

        noise.abort();
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn 保活循环发心跳并能被叫停() {
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = receiver.local_addr().unwrap();

        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = tokio::spawn(keepalive_loop(
            sender,
            remote,
            Duration::from_millis(50),
            stop_rx,
        ));

        let mut buffer = [0u8; 256];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buffer))
                .await
                .expect("应能在 2 秒内收到心跳")
                .unwrap();
        assert!(is_probe(&buffer[..len]));

        stop_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("叫停后应立即退出")
            .unwrap()
            .unwrap();
    }
}
