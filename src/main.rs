//! 命令行入口。

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use p2p_file::cli::{Cli, Command};
use p2p_file::discovery::{LanDiscovery, parse_announcement};
use p2p_file::error::{Error, Result};
use p2p_file::identity::Identity;
use p2p_file::nat::stun::{query_binding, resolve_server};
use p2p_file::transfer::{receive_file, send_file};
use p2p_file::transport::quic::{client_endpoint, connect, server_endpoint};

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("启动异步运行时失败: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("错误: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    // 先把 CLI 拆开，子命令按值取走，避免后续还要借用整个结构体。
    let Cli {
        key_file,
        log: _,
        command,
    } = cli;

    match command {
        Command::Id => cmd_id(&key_file),
        Command::Stun { server, timeout } => cmd_stun(&server, timeout).await,
        Command::Discover { timeout, port } => cmd_discover(&key_file, timeout, port).await,
        Command::Recv { listen, out_dir } => cmd_recv(&key_file, listen, out_dir).await,
        Command::Send {
            file,
            peer,
            chunk_size,
        } => cmd_send(&key_file, file, peer, chunk_size).await,
    }
}

fn cmd_id(key_file: &Option<PathBuf>) -> Result<()> {
    let path = key_path(key_file)?;
    let identity = Identity::load_or_create(&path)?;

    println!("节点 ID:  {}", identity.node_id());
    println!("公钥:     {}", hex::encode(identity.public_key_bytes()));
    println!("密钥文件: {}", path.display());
    println!();
    println!("把节点 ID 告诉对方，双方握手时会核对，对不上就会被拒绝。");
    Ok(())
}

async fn cmd_stun(server: &str, timeout_secs: u64) -> Result<()> {
    let address = resolve_server(server).await?;
    println!("查询 {address} ...");

    let result = query_binding(address, Duration::from_secs(timeout_secs)).await?;

    println!("公网映射:   {}", result.mapped_addr);
    if let Some(origin) = result.response_origin {
        println!("响应来源:   {origin}");
    }
    if let Some(other) = result.other_address {
        println!("备用地址:   {other}");
    }
    if let Some(software) = result.software {
        println!("服务器软件: {software}");
    }

    println!();
    println!("这只是「这一次查询」看到的映射。要用来打洞必须复用同一个本地端口，");
    println!("否则 NAT 给出的会是另一个映射。");
    Ok(())
}

async fn cmd_discover(key_file: &Option<PathBuf>, timeout_secs: u64, port: u16) -> Result<()> {
    let identity = load_identity(key_file)?;
    let discovery = LanDiscovery::announce(identity.node_id(), port)?;
    let events = discovery.browse()?;

    println!(
        "以节点 {} 公告在端口 {port}，监听 {timeout_secs} 秒 ...",
        identity.node_id().short()
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut found = BTreeMap::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, events.recv_async()).await {
            Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(resolved))) => {
                let Some(peer) = parse_announcement(&resolved) else {
                    continue;
                };
                // 别把自己列出来。
                if peer.node_id == identity.node_id() {
                    continue;
                }
                if found.insert(peer.node_id, peer.clone()).is_none() {
                    let first_address = peer
                        .sorted_addresses()
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "无地址".to_string());
                    println!(
                        "发现 {}  {first_address}:{}  ({})",
                        peer.node_id.short(),
                        peer.port,
                        peer.instance
                    );
                }
            }
            Ok(Ok(_)) => {}
            // 事件流断了或超时，都收工。
            Ok(Err(_)) | Err(_) => break,
        }
    }

    discovery.shutdown()?;

    if found.is_empty() {
        println!("没有发现其他节点。确认对方也在这条局域网上，并且已经跑起 recv。");
    } else {
        println!("\n共发现 {} 个节点。", found.len());
    }
    Ok(())
}

async fn cmd_recv(key_file: &Option<PathBuf>, listen: SocketAddr, out_dir: PathBuf) -> Result<()> {
    let identity = load_identity(key_file)?;
    let endpoint = server_endpoint(listen)?;
    let local = endpoint.local_addr()?;

    // 顺便在局域网公告自己，同网段的节点就能直接发现。
    let _discovery = LanDiscovery::announce(identity.node_id(), local.port()).ok();

    println!("节点 ID: {}", identity.node_id());
    println!("监听中:  {local}");
    println!("保存到:  {}", out_dir.display());
    println!("按 Ctrl-C 退出。");

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => return Err(Error::Transport("端点已关闭".into())),
            },
            _ = tokio::signal::ctrl_c() => {
                println!("\n收到中断信号，退出。");
                endpoint.close(0u32.into(), b"bye");
                endpoint.wait_idle().await;
                return Ok(());
            }
        };

        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(err) => {
                eprintln!("握手失败: {err}");
                continue;
            }
        };
        let remote = connection.remote_address();
        tracing::info!(%remote, "收到连接");

        // 初稿：一条连接收一个文件。
        match receive_file(&connection, &identity, &out_dir).await {
            Ok(report) => {
                println!(
                    "已接收 {} （{} 字节，{} 片）→ {}",
                    report.file_name,
                    report.total_len,
                    report.chunk_count,
                    report.output_path.display()
                );
            }
            Err(err) => eprintln!("从 {remote} 接收失败: {err}"),
        }

        connection.close(0u32.into(), b"done");
    }
}

async fn cmd_send(
    key_file: &Option<PathBuf>,
    file: PathBuf,
    peer: SocketAddr,
    chunk_size: u32,
) -> Result<()> {
    let identity = load_identity(key_file)?;
    let endpoint = client_endpoint("0.0.0.0:0".parse().unwrap())?;

    println!("本机节点: {}", identity.node_id());
    println!("连接 {peer} ...");
    let connection = connect(&endpoint, peer, "p2pfile").await?;
    println!("已连接，开始传输。");

    let report = send_file(&connection, &identity, &file, chunk_size).await?;

    println!(
        "发送完成：{} （{} 字节，{} 片，跳过 {} 片）",
        report.file_name, report.total_len, report.chunk_count, report.chunks_skipped
    );
    tracing::debug!(
        chunks_sent = report.chunks_sent,
        chunks_skipped = report.chunks_skipped,
        "本次发送明细"
    );

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

fn load_identity(key_file: &Option<PathBuf>) -> Result<Identity> {
    let path = key_path(key_file)?;
    let identity = Identity::load_or_create(&path)?;
    tracing::debug!(node_id = %identity.node_id().short(), "已加载身份");
    Ok(identity)
}

fn key_path(key_file: &Option<PathBuf>) -> Result<PathBuf> {
    match key_file {
        Some(path) => Ok(path.clone()),
        None => Identity::default_key_path(),
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    // RUST_LOG 优先于 --log，方便临时排查。
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|value| EnvFilter::try_new(value).ok())
        .or_else(|| EnvFilter::try_new(level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    // 已经初始化过（测试里可能发生）就算了。
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
