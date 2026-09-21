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

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::error::{Error, Result};

/// 探测包的魔术前缀，用来把自己发的包和别人的数据区分开。
pub const PROBE_MAGIC: &[u8] = b"P2PF-PUNCH/1";

/// 探测包的长度：魔术前缀 + 令牌 + 随机填充。
const PROBE_TOKEN_LEN: usize = 16;

/// 打洞令牌。
///
/// 由信令服务器为一对节点随机生成，双方各拿一份。作用是让「接受来自任意
/// 地址的探测包」这件事变得安全：不知道令牌的人发的包一律丢掉。
///
/// # 为什么必须允许「任意地址」
///
/// 某些 NAT 的公网端口是**按目标 IP 分配**的：向 STUN 服务器发包时拿到的是端口 A，
/// 向对端发包时 NAT 可能另分配端口 B。于是双方互相发往「信令里公布的那个端口 A」的
/// 包可能被打掉。
///
/// 但这时对端的探测包仍然能到达我们（因为我们发给它的包已经打开了它那一侧
/// 的映射），只是**源端口是 B 而不是 A**。探测器因此允许在令牌认证通过后记录
/// 意外源地址，但这不是对任何 ADM NAT 都能穿透的保证。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PunchToken([u8; PROBE_TOKEN_LEN]);

impl PunchToken {
    pub fn random() -> Self {
        Self(rand::random())
    }

    pub fn from_bytes(bytes: [u8; PROBE_TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PROBE_TOKEN_LEN] {
        &self.0
    }
}

impl std::fmt::Display for PunchToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只显示前 4 字节，够用来对日志，又不会把令牌泄得到处都是。
        write!(f, "{}", hex::encode(&self.0[..4]))
    }
}

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
pub fn probe_packet(token: &PunchToken) -> Vec<u8> {
    let mut packet = PROBE_MAGIC.to_vec();
    packet.extend_from_slice(token.as_bytes());
    // 随机填充：避免被中间设备按固定内容去重或缓存。
    let padding: [u8; 16] = rand::random();
    packet.extend_from_slice(&padding);
    packet
}

/// 判断是不是本协议的探测包（只看前缀）。
pub fn is_probe(data: &[u8]) -> bool {
    data.starts_with(PROBE_MAGIC)
}

/// 判断是不是**带着正确令牌**的探测包。
pub fn is_probe_with_token(data: &[u8], token: &PunchToken) -> bool {
    let expected = PROBE_MAGIC.len();
    data.len() >= expected + PROBE_TOKEN_LEN
        && data.starts_with(PROBE_MAGIC)
        && &data[expected..expected + PROBE_TOKEN_LEN] == token.as_bytes()
}

/// 向 `remote` 打洞，直到收到回应。
///
/// 返回实际收到回包的那个地址。某些地址相关 mapping 下这个地址可能**不等于**
/// `remote`；探测包实际到达只是连通性证据，不是 NAT 类型或 filtering 的证明。
pub async fn simultaneous_open(
    socket: &UdpSocket,
    remote: SocketAddr,
    token: &PunchToken,
    config: &PunchConfig,
) -> Result<SocketAddr> {
    simultaneous_open_any(socket, &[remote], token, config).await
}

/// 向一组候选地址同时打洞，返回第一个真正回应我们的地址。
///
/// 对端通常有多个候选（公网映射、局域网地址、手动指定的映射地址），
/// 我们不知道哪个能通，所以每一轮都往**所有**候选发探测包。
///
/// 收到回包就说明「我们发给它的包穿过了它的 NAT，它发给我们的包也穿过了
/// 我们的 NAT」，也就是双向的洞都通了，可以直接开始传数据。
///
/// 注意这里**不要求**回包来自候选列表：某些 NAT 会让真实源端口与公布端口不同。
/// 安全性由令牌提供，但令牌不保证 NAT 穿透。
pub async fn simultaneous_open_any(
    socket: &UdpSocket,
    candidates: &[SocketAddr],
    token: &PunchToken,
    config: &PunchConfig,
) -> Result<SocketAddr> {
    if candidates.is_empty() {
        return Err(Error::Transport("没有可用的候选地址，无法打洞".into()));
    }

    let probe = probe_packet(token);
    let mut buffer = vec![0u8; 2048];

    for attempt in 0..config.attempts {
        // 每轮把所有候选都打一遍：候选一般只有几个，代价可以忽略。
        for candidate in candidates {
            if let Err(err) = socket.send_to(&probe, candidate).await {
                // 某个候选不可达不该拖垮整轮，继续试其他的。
                tracing::trace!(%candidate, error = %err, "发送探测包失败");
            }
        }

        let deadline = tokio::time::Instant::now() + config.interval;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
                Ok(Ok((len, from))) => {
                    let data = &buffer[..len];

                    if !is_probe(data) {
                        // 不是探测包（可能是迟到的 STUN 响应），继续等。
                        tracing::trace!(%from, "忽略非探测包");
                        continue;
                    }
                    if !is_probe_with_token(data, token) {
                        // 令牌不对：可能是别人在扫端口，也可能是别的会话的探测包。
                        tracing::debug!(%from, "探测包令牌不匹配，忽略");
                        continue;
                    }

                    let advertised = candidates.contains(&from);
                    if advertised {
                        tracing::info!(%from, attempt, "打洞成功（命中公布的候选地址）");
                    } else {
                        tracing::info!(
                            %from,
                            attempt,
                        "打洞成功（对端真实源地址和公布的候选不同；令牌已认证本次探测）"
                        );
                    }
                    return Ok(from);
                }
                Ok(Err(err)) if is_transient_udp_error(&err) => {
                    // Windows reports an ICMP Port Unreachable for a dead UDP
                    // candidate as WSAECONNRESET. It is a per-candidate signal,
                    // not a failure of the punch session; keep probing the live
                    // candidates in this round.
                    tracing::debug!(error = %err, "忽略候选地址的瞬时 UDP 错误");
                    continue;
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => break,
            }
        }

        tracing::trace!(attempt, candidates = candidates.len(), "本轮探测无响应");
    }

    Err(Error::Transport(format!(
        "打洞失败：向 {} 个候选地址各尝试 {} 次（{:?}）都没收到带正确令牌的回应",
        candidates.len(),
        config.attempts,
        config.interval
    )))
}

fn is_transient_udp_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotConnected
    )
}

/// 保活循环：定期发探测包，维持 NAT 映射不被回收。
///
/// UDP 映射的空闲超时通常在 30~120 秒，具体看 NAT 实现。`shutdown` 收到
/// `true` 时退出。
pub async fn keepalive_loop(
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    token: PunchToken,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let probe = probe_packet(&token);

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

    fn token() -> PunchToken {
        PunchToken::from_bytes([0x42; 16])
    }

    #[test]
    fn 探测包可识别() {
        let probe = probe_packet(&token());
        assert!(is_probe(&probe));
        assert!(probe.len() > PROBE_MAGIC.len());
        assert!(!is_probe(b"hello"));
        assert!(!is_probe(b""));
        // 每次的填充不同，避免被中间设备按固定内容去重或缓存。
        assert_ne!(probe_packet(&token()), probe_packet(&token()));
    }

    #[test]
    fn 令牌不对的探测包不认() {
        let mine = token();
        let other = PunchToken::from_bytes([0x99; 16]);

        assert!(is_probe_with_token(&probe_packet(&mine), &mine));
        assert!(!is_probe_with_token(&probe_packet(&other), &mine));
        assert!(!is_probe_with_token(b"P2PF-PUNCH/1", &mine));
        assert!(!is_probe_with_token(b"", &mine));
        // 前缀对但令牌只有一半，也不能认。
        let mut truncated = PROBE_MAGIC.to_vec();
        truncated.extend_from_slice(&[0x42; 8]);
        assert!(!is_probe_with_token(&truncated, &mine));
    }

    #[test]
    fn 令牌随机且可显示() {
        let a = PunchToken::random();
        let b = PunchToken::random();
        assert_ne!(a, b, "每次配对的令牌必须不同");
        assert_eq!(a.to_string().len(), 8, "展示用短令牌是 4 字节十六进制");
        assert_eq!(PunchToken::from_bytes(*a.as_bytes()), a);
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

        let shared = token();
        let (result_a, result_b) = tokio::join!(
            simultaneous_open(&a, b_addr, &shared, &config),
            simultaneous_open(&b, a_addr, &shared, &config),
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
            simultaneous_open(&socket, dead_addr, &token(), &config)
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
                    let _ = target.send_to(&probe_packet(&token()), from).await;
                    break;
                }
            }
        });

        let config = PunchConfig {
            interval: Duration::from_millis(50),
            attempts: 30,
        };
        let result = simultaneous_open(&socket, target_addr, &token(), &config)
            .await
            .unwrap();
        assert_eq!(result, target_addr);
        assert_ne!(result, stranger_addr);

        noise.abort();
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn 多候选里能打通活的那个() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 两个死地址 + 一个活的，活的那个排在最后。
        let dead_one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_one_addr = dead_one.local_addr().unwrap();
        drop(dead_one);
        let dead_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_two_addr = dead_two.local_addr().unwrap();
        drop(dead_two);

        let alive = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alive_addr = alive.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            loop {
                let (len, from) = alive.recv_from(&mut buffer).await.unwrap();
                if is_probe(&buffer[..len]) {
                    let _ = alive.send_to(&probe_packet(&token()), from).await;
                    break;
                }
            }
        });

        let candidates = vec![dead_one_addr, dead_two_addr, alive_addr];
        let config = PunchConfig {
            interval: Duration::from_millis(80),
            attempts: 20,
        };

        let result = simultaneous_open_any(&socket, &candidates, &token(), &config)
            .await
            .unwrap();
        assert_eq!(result, alive_addr, "应当认出真正能通的那个候选");

        responder.await.unwrap();
    }

    #[tokio::test]
    async fn 未知源地址但令牌正确时可识别探测包() {
        // 令牌只证明探测包属于本次会话：即使源地址不在候选列表里，也可以
        // 记录实际源地址。这个 localhost 测试不声称模拟或证明真实 ADM NAT。
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        let shared = token();

        // A 手上的候选是错的：指向一个没人用的端口。
        let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let sender = tokio::spawn(async move {
            let probe = probe_packet(&shared);
            for _ in 0..20 {
                let _ = b.send_to(&probe, a_addr).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let config = PunchConfig {
            interval: Duration::from_millis(100),
            attempts: 30,
        };
        let learned = simultaneous_open_any(&a, &[bogus], &shared, &config)
            .await
            .expect("应当靠令牌认下对端真实的源地址");

        assert_eq!(learned, b_addr, "学到的必须是对端真实地址，不是公布的那个");
        assert_ne!(learned, bogus);

        sender.abort();
    }

    #[tokio::test]
    async fn 令牌不对的探测包打不通() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let mine = PunchToken::from_bytes([0x11; 16]);
        let theirs = PunchToken::from_bytes([0x22; 16]);

        let sender = tokio::spawn(async move {
            let probe = probe_packet(&theirs);
            for _ in 0..10 {
                let _ = b.send_to(&probe, a_addr).await;
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });

        let config = PunchConfig {
            interval: Duration::from_millis(50),
            attempts: 3,
        };
        // 地址是对的，但令牌不对，不能算打通。
        let err = simultaneous_open_any(&a, &[b_addr], &mine, &config)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "实际 {err:?}");

        sender.abort();
    }

    #[tokio::test]
    async fn 没有候选时直接报错() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let err = simultaneous_open_any(&socket, &[], &token(), &PunchConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "实际 {err:?}");
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
            token(),
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
