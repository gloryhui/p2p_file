//! 命令行界面。

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::discovery::signal::DEFAULT_SIGNAL_PORT;
use crate::identity::NodeId;
use crate::protocol::manifest::DEFAULT_CHUNK_SIZE;

/// 点对点文件传输。
///
/// 目标是在公网上把文件直接发给对方：STUN 探出各自的公网映射，双方同时
/// 打洞，打通后走 QUIC 加密通道传数据。打洞不成时才退回中继。
#[derive(Debug, Parser)]
#[command(
    name = "p2p_file",
    version,
    about = "点对点文件传输",
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

        /// 分片大小（字节）
        #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE, value_name = "BYTES")]
        chunk_size: u32,
    },

    /// 查 STUN，看看本机在公网上是什么样子
    Stun {
        /// STUN 服务器
        #[arg(
            long,
            default_value = "stun.l.google.com:19302",
            value_name = "HOST:PORT"
        )]
        server: String,

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

        /// 分片大小（字节）
        #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE, value_name = "BYTES")]
        chunk_size: u32,
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
                assert_eq!(server, "stun.example.com:3478");
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
}
