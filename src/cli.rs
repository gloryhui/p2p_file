//! 命令行界面。

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::discovery::signal::DEFAULT_SIGNAL_PORT;
use crate::identity::NodeId;
use crate::protocol::manifest::{DEFAULT_CHUNK_SIZE, validate_chunk_size};
use crate::speedtest::{
    DEFAULT_BLOCK_SIZE, DEFAULT_DURATION_SECS, MAX_BLOCK_SIZE, MAX_DURATION_SECS, MIN_BLOCK_SIZE,
    MIN_DURATION_SECS, SpeedTestDirection,
};

/// clap 的 `--chunk-size` 解析器。
///
/// 在这里就拒绝非法值：等进了 `manifest_from_reader` 再报错的话，`0` 之外的
/// 超大值（例如 4 GiB）会先触发一次真实的大分配。放在 value parser 里，
/// 参数一解析完进程就退出，什么都不会分配。
fn parse_chunk_size(raw: &str) -> std::result::Result<u32, String> {
    let value: u32 = raw
        .parse()
        .map_err(|_| format!("分片大小必须是 0..={} 的整数，收到 {raw}", u32::MAX))?;
    validate_chunk_size(value).map_err(|err| err.to_string())?;
    Ok(value)
}

fn parse_speedtest_duration(raw: &str) -> std::result::Result<u64, String> {
    let value: u64 = raw
        .parse()
        .map_err(|_| format!("测速 duration 必须是整数，收到 {raw}"))?;
    if !(MIN_DURATION_SECS..=MAX_DURATION_SECS).contains(&value) {
        return Err(format!(
            "测速 duration 必须在 {MIN_DURATION_SECS}..={MAX_DURATION_SECS} 秒范围内，收到 {value}"
        ));
    }
    Ok(value)
}

fn parse_speedtest_block_size(raw: &str) -> std::result::Result<u32, String> {
    let value: u32 = raw
        .parse()
        .map_err(|_| format!("测速 block-size 必须是整数，收到 {raw}"))?;
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&value) {
        return Err(format!(
            "测速 block-size 必须在 {MIN_BLOCK_SIZE}..={MAX_BLOCK_SIZE} 字节范围内，收到 {value}"
        ));
    }
    Ok(value)
}

/// 点对点文件传输。
///
/// 目标是在公网上把文件直接发给对方：STUN 探出各自的公网映射，双方同时
/// 打洞，打通后走 QUIC 加密通道传数据。打洞不成时才退回中继。
#[derive(Debug, Parser)]
#[command(
    name = "p2p_file",
    version,
    about = "点对点直连：NAT 穿透 + 文件传输 + 通用 TCP 隧道",
    propagate_version = true
)]
pub struct Cli {
    /// 身份密钥文件（默认在 ~/.config/p2p_file/identity.key）
    #[arg(long, global = true, value_name = "FILE")]
    pub key_file: Option<PathBuf>,

    /// 日志级别：trace / debug / info / warn / error
    #[arg(long, global = true, value_name = "LEVEL", default_value = "info")]
    pub log: String,

    #[command(subcommand)]
    pub command: Command,
}

/// 打洞相关的公共参数。`serve` / `tunnel` / `push` 都要用。
#[derive(Debug, Args, Clone)]
pub struct DirectOpts {
    /// 信令服务器地址（跑在阿里云那台上的 `signal-server`）
    #[arg(long, value_name = "HOST:PORT")]
    pub signal: String,

    /// 本机打洞用的 UDP 端口
    ///
    /// 固定端口能复用 NAT 上的映射，重复连接更快。
    #[arg(long, default_value_t = 9000, value_name = "PORT")]
    pub port: u16,

    /// STUN 服务器，可重复指定
    #[arg(long, value_name = "HOST:PORT")]
    pub stun: Vec<String>,

    /// 手动指定本机对外的公网地址，可重复指定
    ///
    /// 在路由器上做了端口映射（公网 UDP 端口 → 本机）时填这里，
    /// 这样对称型 NAT 也能连上。
    #[arg(long, value_name = "ADDR")]
    pub advertise: Vec<SocketAddr>,

    /// 等对端上线的最长时间（秒）
    #[arg(long, default_value_t = 60, value_name = "SECONDS")]
    pub wait: u64,

    /// 打洞重试次数
    #[arg(long, default_value_t = 30, value_name = "N")]
    pub punch_attempts: u32,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 显示本机身份（不存在则生成一个）
    Id,

    /// 监听端口，等待对端连接并接收文件（局域网直连用）
    Recv {
        /// 监听地址
        #[arg(long, default_value = "0.0.0.0:9000", value_name = "ADDR")]
        listen: SocketAddr,

        /// 文件保存目录
        #[arg(long, default_value = ".", value_name = "DIR")]
        out_dir: PathBuf,
    },

    /// 连接对端并发送文件（局域网直连用）
    Send {
        /// 要发送的文件
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// 对端地址，比如 203.0.113.7:9000
        #[arg(value_name = "HOST:PORT")]
        peer: SocketAddr,

        /// 分片大小（字节），必须在 16 KiB..=16 MiB 之间
        #[arg(
            long,
            default_value_t = DEFAULT_CHUNK_SIZE,
            value_name = "BYTES",
            value_parser = parse_chunk_size
        )]
        chunk_size: u32,
    },

    /// 查 STUN，看看本机在公网上是什么样子
    Stun {
        /// STUN 服务器，可重复指定。给多个才能判断 NAT 类型
        #[arg(long, value_name = "HOST:PORT")]
        server: Vec<String>,

        /// 超时（秒）
        #[arg(long, default_value_t = 3, value_name = "SECONDS")]
        timeout: u64,
    },

    /// 在局域网里发现其他节点
    Discover {
        /// 持续监听多少秒
        #[arg(long, default_value_t = 5, value_name = "SECONDS")]
        timeout: u64,

        /// 本机对外公告的端口
        #[arg(long, default_value_t = 9000, value_name = "PORT")]
        port: u16,
    },

    /// 跑信令服务器（放在有公网 IP 的机器上，只牵线，不过数据）
    SignalServer {
        /// 监听地址
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_SIGNAL_PORT)), value_name = "ADDR")]
        listen: SocketAddr,
    },

    /// 家里那台：等对端连上来，提供端口转发和收文件
    ///
    /// 数据走 P2P 直连，信令服务器只参与牵线。
    Serve {
        #[command(flatten)]
        direct: DirectOpts,

        /// 只允许这个节点连进来（本机 `id` 或对方 `id` 的输出），可重复指定
        #[arg(long = "allow", value_name = "NODE_ID")]
        allow: Vec<NodeId>,

        /// 允许转发到的目标，比如 127.0.0.1:22，可重复指定
        #[arg(long = "forward", value_name = "ADDR")]
        forward: Vec<SocketAddr>,

        /// 接收到的文件存这个目录
        #[arg(long, value_name = "DIR")]
        recv_dir: Option<PathBuf>,

        /// 空闲多少秒后重新打洞（NAT 映射会过期，重新打一次更保险）
        #[arg(long, value_name = "SECS", default_value_t = 60)]
        re_punch_after: u64,
    },

    /// 本机开一个监听端口，转发到对端的某个服务
    ///
    /// 例：--listen 127.0.0.1:2222 --to 127.0.0.1:22，然后 ssh -p 2222
    Tunnel {
        #[command(flatten)]
        direct: DirectOpts,

        /// 对端节点 ID
        #[arg(long, value_name = "NODE_ID")]
        peer: NodeId,

        /// 本机监听地址
        #[arg(long, value_name = "ADDR")]
        listen: SocketAddr,

        /// 要连对端的哪个服务（必须在对方的 --forward 白名单里）
        #[arg(long, value_name = "ADDR")]
        to: SocketAddr,
    },

    /// 把文件直接推到对端（走直连）
    Push {
        #[command(flatten)]
        direct: DirectOpts,

        /// 对端节点 ID
        #[arg(long, value_name = "NODE_ID")]
        peer: NodeId,

        /// 要发送的文件
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// 分片大小（字节），必须在 16 KiB..=16 MiB 之间
        #[arg(
            long,
            default_value_t = DEFAULT_CHUNK_SIZE,
            value_name = "BYTES",
            value_parser = parse_chunk_size
        )]
        chunk_size: u32,
    },

    /// 测量已经认证的 P2P / QUIC 内存到内存吞吐，不访问文件系统。
    Speedtest {
        #[command(flatten)]
        direct: DirectOpts,

        /// 对端节点 ID
        #[arg(long, value_name = "NODE_ID")]
        peer: NodeId,

        /// 测速时长（秒）
        #[arg(
            long,
            default_value_t = DEFAULT_DURATION_SECS,
            value_name = "SECONDS",
            value_parser = parse_speedtest_duration
        )]
        duration: u64,

        /// 方向：upload / download / both（both 按顺序执行）
        #[arg(long, value_enum, default_value = "both", value_name = "MODE")]
        direction: SpeedTestDirection,

        /// 每次写入/读取的固定内存 block 大小（字节）
        #[arg(
            long,
            default_value_t = DEFAULT_BLOCK_SIZE,
            value_name = "BYTES",
            value_parser = parse_speedtest_block_size
        )]
        block_size: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn 命令行定义本身是合法的() {
        Cli::command().debug_assert();
    }

    #[test]
    fn 解析_id_子命令() {
        let cli = Cli::parse_from(["p2p_file", "id"]);
        assert!(matches!(cli.command, Command::Id));
        assert_eq!(cli.log, "info");
        assert!(cli.key_file.is_none());
    }

    #[test]
    fn 解析_send_子命令() {
        let cli = Cli::parse_from([
            "p2p_file",
            "--log",
            "debug",
            "send",
            "/tmp/a.bin",
            "203.0.113.7:9000",
        ]);
        match cli.command {
            Command::Send {
                file,
                peer,
                chunk_size,
            } => {
                assert_eq!(file, PathBuf::from("/tmp/a.bin"));
                assert_eq!(peer, "203.0.113.7:9000".parse().unwrap());
                assert_eq!(chunk_size, DEFAULT_CHUNK_SIZE);
            }
            other => panic!("解析结果不对: {other:?}"),
        }
        assert_eq!(cli.log, "debug");
    }

    #[test]
    fn 解析_stun_子命令带自定义服务器() {
        let cli = Cli::parse_from([
            "p2p_file",
            "stun",
            "--server",
            "stun.example.com:3478",
            "--timeout",
            "7",
        ]);
        match cli.command {
            Command::Stun { server, timeout } => {
                assert_eq!(server, vec!["stun.example.com:3478".to_string()]);
                assert_eq!(timeout, 7);
            }
            other => panic!("解析结果不对: {other:?}"),
        }
    }

    #[test]
    fn 解析_recv_子命令带输出目录() {
        let cli = Cli::parse_from([
            "p2p_file",
            "recv",
            "--listen",
            "0.0.0.0:8000",
            "--out-dir",
            "/tmp/dl",
        ]);
        match cli.command {
            Command::Recv { listen, out_dir } => {
                assert_eq!(listen, "0.0.0.0:8000".parse().unwrap());
                assert_eq!(out_dir, PathBuf::from("/tmp/dl"));
            }
            other => panic!("解析结果不对: {other:?}"),
        }
    }

    #[test]
    fn 缺少必填参数会报错() {
        assert!(Cli::try_parse_from(["p2p_file", "send"]).is_err());
        assert!(Cli::try_parse_from(["p2p_file", "send", "/tmp/a.bin"]).is_err());
        assert!(Cli::try_parse_from(["p2p_file"]).is_err());
    }

    #[test]
    fn 地址非法会报错() {
        assert!(Cli::try_parse_from(["p2p_file", "send", "/tmp/a.bin", "not-an-addr"]).is_err());
    }

    #[test]
    fn 解析信令服务器子命令() {
        let cli = Cli::parse_from(["p2p_file", "signal-server"]);
        match cli.command {
            Command::SignalServer { listen } => {
                assert_eq!(listen.port(), DEFAULT_SIGNAL_PORT);
                assert!(listen.ip().is_unspecified());
            }
            other => panic!("解析结果不对: {other:?}"),
        }

        let cli = Cli::parse_from(["p2p_file", "signal-server", "--listen", "0.0.0.0:8000"]);
        match cli.command {
            Command::SignalServer { listen } => {
                assert_eq!(listen, "0.0.0.0:8000".parse().unwrap());
            }
            other => panic!("解析结果不对: {other:?}"),
        }
    }

    #[test]
    fn 解析_serve_子命令() {
        let peer = "00112233445566778899aabbccddeeff";
        let cli = Cli::parse_from([
            "p2p_file",
            "serve",
            "--signal",
            "1.2.3.4:7000",
            "--allow",
            peer,
            "--forward",
            "127.0.0.1:22",
            "--forward",
            "127.0.0.1:3389",
            "--recv-dir",
            "/tmp/dl",
            "--port",
            "9100",
        ]);

        match cli.command {
            Command::Serve {
                direct,
                allow,
                forward,
                recv_dir,
                re_punch_after,
            } => {
                assert_eq!(re_punch_after, 60);
                assert_eq!(direct.signal, "1.2.3.4:7000");
                assert_eq!(direct.port, 9100);
                assert_eq!(allow.len(), 1);
                assert_eq!(allow[0].to_hex(), peer);
                assert_eq!(forward.len(), 2);
                assert_eq!(forward[0], "127.0.0.1:22".parse().unwrap());
                assert_eq!(recv_dir, Some(PathBuf::from("/tmp/dl")));
            }
            other => panic!("解析结果不对: {other:?}"),
        }
    }

    #[test]
    fn 解析_tunnel_子命令() {
        let peer = "00112233445566778899aabbccddeeff";
        let cli = Cli::parse_from([
            "p2p_file",
            "tunnel",
            "--signal",
            "1.2.3.4:7000",
            "--peer",
            peer,
            "--listen",
            "127.0.0.1:2222",
            "--to",
            "127.0.0.1:22",
            "--advertise",
            "203.0.113.9:4000",
        ]);

        match cli.command {
            Command::Tunnel {
                direct,
                peer: parsed_peer,
                listen,
                to,
            } => {
                assert_eq!(parsed_peer.to_hex(), peer);
                assert_eq!(listen, "127.0.0.1:2222".parse().unwrap());
                assert_eq!(to, "127.0.0.1:22".parse().unwrap());
                assert_eq!(direct.advertise, vec!["203.0.113.9:4000".parse().unwrap()]);
            }
            other => panic!("解析结果不对: {other:?}"),
        }
    }

    #[test]
    fn 解析_push_子命令() {
        let peer = "00112233445566778899aabbccddeeff";
        let cli = Cli::parse_from([
            "p2p_file",
            "push",
            "--signal",
            "1.2.3.4:7000",
            "--peer",
            peer,
            "/tmp/big.bin",
            "--stun",
            "stun.example.com:3478",
        ]);

        match cli.command {
            Command::Push {
                direct,
                peer: parsed_peer,
                file,
                chunk_size,
            } => {
                assert_eq!(parsed_peer.to_hex(), peer);
                assert_eq!(file, PathBuf::from("/tmp/big.bin"));
                assert_eq!(chunk_size, DEFAULT_CHUNK_SIZE);
                assert_eq!(direct.stun, vec!["stun.example.com:3478".to_string()]);
            }
            other => panic!("解析结果不对: {other:?}"),
        }
    }

    #[test]
    fn 解析_speedtest_子命令及默认值() {
        let peer = "00112233445566778899aabbccddeeff";
        let cli = Cli::parse_from([
            "p2p_file",
            "speedtest",
            "--signal",
            "1.2.3.4:7000",
            "--peer",
            peer,
        ]);
        match cli.command {
            Command::Speedtest {
                direct,
                peer: parsed_peer,
                duration,
                direction,
                block_size,
            } => {
                assert_eq!(direct.signal, "1.2.3.4:7000");
                assert_eq!(parsed_peer.to_hex(), peer);
                assert_eq!(duration, DEFAULT_DURATION_SECS);
                assert_eq!(direction, SpeedTestDirection::Both);
                assert_eq!(block_size, DEFAULT_BLOCK_SIZE);
            }
            other => panic!("解析结果不对: {other:?}"),
        }
    }

    #[test]
    fn 解析_speedtest_方向和参数边界() {
        let peer = "00112233445566778899aabbccddeeff";
        for (direction, expected) in [
            ("upload", SpeedTestDirection::Upload),
            ("download", SpeedTestDirection::Download),
            ("both", SpeedTestDirection::Both),
        ] {
            let cli = Cli::parse_from([
                "p2p_file",
                "speedtest",
                "--signal",
                "1.2.3.4:7000",
                "--peer",
                peer,
                "--direction",
                direction,
                "--duration",
                "300",
                "--block-size",
                "16777216",
            ]);
            match cli.command {
                Command::Speedtest { direction, .. } => assert_eq!(direction, expected),
                other => panic!("解析结果不对: {other:?}"),
            }
        }

        for seconds in ["301", "599", "600"] {
            assert!(
                Cli::try_parse_from([
                    "p2p_file",
                    "speedtest",
                    "--signal",
                    "1.2.3.4:7000",
                    "--peer",
                    peer,
                    "--duration",
                    seconds
                ])
                .is_ok()
            );
        }
        for bad in ["", "0", "601", "99999999999999999999"] {
            assert!(
                Cli::try_parse_from([
                    "p2p_file",
                    "speedtest",
                    "--signal",
                    "1.2.3.4:7000",
                    "--peer",
                    peer,
                    "--duration",
                    bad,
                ])
                .is_err(),
                "非法 duration {bad} 应当被拒绝"
            );
        }
        for bad in ["0", "16383", "16777217", "abc", "4294967295"] {
            assert!(
                Cli::try_parse_from([
                    "p2p_file",
                    "speedtest",
                    "--signal",
                    "1.2.3.4:7000",
                    "--peer",
                    peer,
                    "--block-size",
                    bad,
                ])
                .is_err(),
                "非法 block-size {bad} 应当被拒绝"
            );
        }
        assert!(
            Cli::try_parse_from([
                "p2p_file",
                "speedtest",
                "--signal",
                "1.2.3.4:7000",
                "--peer",
                peer,
                "--direction",
                "sideways",
            ])
            .is_err()
        );
    }

    #[test]
    fn 节点_id_格式不对会报错() {
        assert!(
            Cli::try_parse_from([
                "p2p_file",
                "tunnel",
                "--signal",
                "1.2.3.4:7000",
                "--peer",
                "太短了",
                "--listen",
                "127.0.0.1:2222",
                "--to",
                "127.0.0.1:22",
            ])
            .is_err()
        );
    }

    #[test]
    fn tunnel_缺少必填参数会报错() {
        assert!(
            Cli::try_parse_from([
                "p2p_file",
                "tunnel",
                "--signal",
                "1.2.3.4:7000",
                "--peer",
                "00112233445566778899aabbccddeeff",
            ])
            .is_err(),
            "缺少 --listen / --to 应当报错"
        );
    }

    /// Issue #3：非法的 `--chunk-size` 必须在参数解析阶段就失败，
    /// 不能等到发送端 `vec![0u8; chunk_size as usize]` 去申请 4 GiB。
    #[test]
    fn 非法分片大小在解析阶段就被拒绝() {
        for bad in [
            "0",
            "1",
            "16383",
            "16777217",
            "4294967295",
            "abc",
            "-1",
            "99999999999999999999",
        ] {
            let send = Cli::try_parse_from([
                "p2p_file",
                "send",
                "/tmp/a.bin",
                "203.0.113.7:9000",
                "--chunk-size",
                bad,
            ]);
            assert!(send.is_err(), "send --chunk-size {bad} 应当被拒绝");

            let push = Cli::try_parse_from([
                "p2p_file",
                "push",
                "--signal",
                "1.2.3.4:7000",
                "--peer",
                "00112233445566778899aabbccddeeff",
                "/tmp/b.bin",
                "--chunk-size",
                bad,
            ]);
            assert!(push.is_err(), "push --chunk-size {bad} 应当被拒绝");
        }
    }

    #[test]
    fn 合法分片大小能被解析() {
        use crate::protocol::manifest::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};

        for good in [MIN_CHUNK_SIZE, 65536, MAX_CHUNK_SIZE] {
            let cli = Cli::parse_from([
                "p2p_file",
                "send",
                "/tmp/a.bin",
                "203.0.113.7:9000",
                "--chunk-size",
                &good.to_string(),
            ]);
            match cli.command {
                Command::Send { chunk_size, .. } => assert_eq!(chunk_size, good),
                other => panic!("解析结果不对: {other:?}"),
            }
        }
    }
}
