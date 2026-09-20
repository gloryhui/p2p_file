//! 命令行界面。

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 显示本机身份（不存在则生成一个）
    Id,

    /// 监听端口，等待对端连接并接收文件
    Recv {
        /// 监听地址
        #[arg(long, default_value = "0.0.0.0:9000", value_name = "ADDR")]
        listen: SocketAddr,

        /// 文件保存目录
        #[arg(long, default_value = ".", value_name = "DIR")]
        out_dir: PathBuf,
    },

    /// 连接对端并发送文件
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
}
