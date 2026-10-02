//! 命令行入口。

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use p2p_file::cli::{Cli, Command, DirectOpts};
use p2p_file::discovery::signal::{SignalServerConfig, run_signal_server_on_with};
use p2p_file::discovery::{LanDiscovery, parse_announcement};
use p2p_file::error::{Error, Result};
use p2p_file::identity::Identity;
use p2p_file::nat::punch::PunchConfig;
use p2p_file::net::{DirectConfig, establish};
use p2p_file::speedtest::{SpeedTestDirection, SpeedTestReport, SpeedTestStats, run_speedtest};
use p2p_file::transfer::{receive_file, send_file};
use p2p_file::transport::quic::{client_endpoint, connect, server_endpoint};
use p2p_file::tunnel::{ServeConfig, forward_tunnel, push_file, serve_loop};

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

        Command::SignalServer {
            listen,
            short_id_db,
            max_device_ids,
            new_device_ids_per_minute,
            new_device_ids_per_ip_per_minute,
        } => {
            cmd_signal_server(
                listen,
                short_id_db,
                max_device_ids,
                new_device_ids_per_minute,
                new_device_ids_per_ip_per_minute,
            )
            .await
        }
        Command::Serve {
            direct,
            allow,
            forward,
            recv_dir,
            re_punch_after,
        } => cmd_serve(&key_file, direct, allow, forward, recv_dir, re_punch_after).await,
        Command::Tunnel {
            direct,
            peer,
            listen,
            to,
        } => cmd_tunnel(&key_file, direct, peer, listen, to).await,
        Command::Push {
            direct,
            peer,
            file,
            chunk_size,
        } => cmd_push(&key_file, direct, peer, file, chunk_size).await,
        Command::Speedtest {
            direct,
            peer,
            duration,
            direction,
            block_size,
        } => cmd_speedtest(&key_file, direct, peer, duration, direction, block_size).await,
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

async fn cmd_stun(servers: &[String], timeout_secs: u64) -> Result<()> {
    let mut config = p2p_file::net::DesktopNetworkConfig::default();
    if !servers.is_empty() {
        config.stun_servers = servers.to_vec();
    }
    config.stun_timeout = Duration::from_secs(timeout_secs);
    let network = p2p_file::net::prepare_desktop_network(&config).await?;
    for diagnostic in &network.diagnostics {
        println!("{diagnostic}");
    }
    if let Some(path) = network.path(p2p_file::net::AddressFamily::Ipv4) {
        if let Some(report) = &path.mapping_probe {
            for observation in &report.observations {
                println!(
                    "  {:<28} 看到的是 {}",
                    observation.server, observation.mapped_addr
                );
            }
            println!("NAT 映射行为: {}", report.mapping.describe());
            println!("mapping 证据: {}", report.evidence.describe());
            println!("Filtering behavior: {}", report.filtering.describe());
            println!(
                "{}",
                p2p_file::net::punch_diagnosis(report.mapping, path.public_addr)
            );
        } else {
            println!("IPv4 STUN 没有响应；mapping 证据不足，filtering 未测量。");
        }
    }
    println!("IPv6 STUN 仅用于地址观测；IPv4 NAT mapping 不包含 IPv6 样本。");
    let observed = network.paths.iter().any(|p| p.public_addr.is_some());
    network.close();
    network.wait_idle().await;
    if !observed {
        return Err(Error::Discovery(
            "所有 STUN 服务器都没有响应（Host 候选仍可用于直连）".into(),
        ));
    }
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
            _ = shutdown_signal() => {
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
                // Complete has been queued after durable finalize. Let the sender
                // consume it and close, rather than overtaking it with CONNECTION_CLOSE.
                let _ = tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
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
    let endpoint = client_endpoint(p2p_file::net::AddressFamily::of(peer).wildcard(0))?;

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

// ---------------------------------------------------------------------------
// 公网直连：信令服务器 / serve / tunnel / push
// ---------------------------------------------------------------------------

/// 把命令行参数翻译成打洞配置。
fn direct_config(opts: &DirectOpts, peer: p2p_file::identity::NodeId) -> DirectConfig {
    let mut config = DirectConfig::new(opts.signal.clone(), peer);
    config.local_port = opts.port;
    config.families = opts.ip_family;
    config.advertise = opts.advertise.clone();
    config.signal_timeout = Duration::from_secs(opts.wait);
    config.punch = PunchConfig {
        attempts: opts.punch_attempts,
        ..PunchConfig::default()
    };
    // 没显式指定就用默认那几台。
    if !opts.stun.is_empty() {
        config.stun_servers = opts.stun.clone();
    }
    config
}

/// 等退出信号：终端的 Ctrl-C（SIGINT），或者 systemd 停止服务时的 SIGTERM。
///
/// 只处理 Ctrl-C 是不够的——`kill` 和 `systemctl stop` 发的都是 SIGTERM，
/// 不接住的话进程会被直接干掉，QUIC 连接来不及发关闭帧，对端只能干等
/// 空闲超时（30 秒）才发现我们已经走了。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, "注册 SIGTERM 处理失败，只监听 Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// 关掉 QUIC 端点，让对端立刻知道我们走了。
async fn close_endpoints(endpoints: &[quinn::Endpoint]) {
    for endpoint in endpoints {
        endpoint.close(0u32.into(), b"bye");
    }
    for endpoint in endpoints {
        close_endpoint(endpoint).await;
    }
}

async fn close_endpoint(endpoint: &quinn::Endpoint) {
    endpoint.close(0u32.into(), b"bye");
    // 给关闭帧一点时间发出去；连不上或对端没响应也不必死等。
    let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.wait_idle()).await;
}

async fn cmd_signal_server(
    listen: SocketAddr,
    short_id_db: std::path::PathBuf,
    max_device_ids: u32,
    new_device_ids_per_minute: u32,
    new_device_ids_per_ip_per_minute: u32,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let config = SignalServerConfig {
        short_id_database: Some(short_id_db),
        max_short_id_mappings: max_device_ids,
        short_id_allocations_per_minute: new_device_ids_per_minute,
        short_id_allocations_per_ip_per_minute: new_device_ids_per_ip_per_minute,
        ..SignalServerConfig::default()
    };
    println!("信令服务器监听 {listen}");
    println!("它只负责让双方交换候选地址，业务数据一个字节都不经过这里。");
    println!("记得在云主机安全组里放通这个 TCP 端口。");
    println!("按 Ctrl-C 退出。");

    tokio::select! {
        result = run_signal_server_on_with(listener, config) => result,
        _ = shutdown_signal() => {
            println!("\n收到中断信号，退出。");
            Ok(())
        }
    }
}

async fn cmd_serve(
    key_file: &Option<PathBuf>,
    direct: DirectOpts,
    allow: Vec<p2p_file::identity::NodeId>,
    forward: Vec<SocketAddr>,
    recv_dir: Option<PathBuf>,
    re_punch_after: u64,
) -> Result<()> {
    let identity = load_identity(key_file)?;
    println!("本机节点 ID: {}", identity.node_id());
    println!("（把这个 ID 告诉对方，对方用 --peer 指定）");

    // 打洞必须知道「往哪打」，所以 serve 需要恰好一个对端节点。
    let peer = match allow.as_slice() {
        [peer] => *peer,
        [] => {
            return Err(Error::Discovery(
                "serve 必须用 --allow 指定对端节点 ID：不知道对方是谁就没法打洞".into(),
            ));
        }
        _ => {
            return Err(Error::Discovery(
                "serve 目前只支持一个 --allow 对端：打洞是点对点的，多个对端请各开一个进程".into(),
            ));
        }
    };

    // serve 是常驻的：一直等对端，空闲后重新打洞。
    let mut config = direct_config(&direct, peer);
    config.signal_timeout = Duration::ZERO; // 0 = 一直等，不超时

    if forward.is_empty() && recv_dir.is_none() {
        println!("提示：没有 --forward 也没有 --recv-dir，对端连上来也没事可做。");
    }
    for target in &forward {
        println!("允许转发到 {target}");
    }
    println!();
    println!("常驻等待中。对端上线后会自动打洞并开始服务。");

    let serve_config = ServeConfig {
        allowed_peers: allow,
        forwards: forward,
        recv_dir,
        re_punch_after: Duration::from_secs(re_punch_after),
        ..ServeConfig::new()
    };

    tokio::select! {
        result = serve_loop(identity, config, serve_config) => result,
        _ = shutdown_signal() => {
            println!("\n收到中断信号，退出。");
            Ok(())
        }
    }
}

async fn cmd_tunnel(
    key_file: &Option<PathBuf>,
    direct: DirectOpts,
    peer: p2p_file::identity::NodeId,
    listen: SocketAddr,
    to: SocketAddr,
) -> Result<()> {
    let identity = load_identity(key_file)?;
    println!("本机节点 ID: {}", identity.node_id());
    println!("目标对端:   {} ({})", peer.short(), peer);

    let config = direct_config(&direct, peer);
    let link = establish(&identity, &config).await?;
    println!("直连候选已准备：{}", link.describe());
    println!();
    println!("本地隧道将监听 {listen}，首次访问时认证对端并转发到 {to}。");

    let target = to.to_string();
    let endpoints = link.endpoints();
    tokio::select! {
        result = forward_tunnel(link, identity, target, listen) => result,
        _ = shutdown_signal() => {
            println!("\n收到退出信号，正在关闭隧道……");
            close_endpoints(&endpoints).await;
            Ok(())
        }
    }
}

async fn cmd_push(
    key_file: &Option<PathBuf>,
    direct: DirectOpts,
    peer: p2p_file::identity::NodeId,
    file: PathBuf,
    chunk_size: u32,
) -> Result<()> {
    let identity = load_identity(key_file)?;
    println!("本机节点 ID: {}", identity.node_id());
    println!("目标对端:   {} ({})", peer.short(), peer);

    let config = direct_config(&direct, peer);
    let link = establish(&identity, &config).await?;
    println!("直连候选已准备：{}", link.describe());

    let endpoints = link.endpoints();
    tokio::select! {
        result = push_file(link, identity, file, chunk_size) => {
            let report = result?;
            println!(
                "发送完成：{} （{} 字节，{} 片，跳过 {} 片）",
                report.file_name, report.total_len, report.chunk_count, report.chunks_skipped
            );
            close_endpoints(&endpoints).await;
            Ok(())
        }
        _ = shutdown_signal() => {
            println!("\n收到退出信号，正在收尾……");
            close_endpoints(&endpoints).await;
            Ok(())
        }
    }
}

async fn cmd_speedtest(
    key_file: &Option<PathBuf>,
    direct: DirectOpts,
    peer: p2p_file::identity::NodeId,
    duration_secs: u64,
    direction: SpeedTestDirection,
    block_size: u32,
) -> Result<()> {
    let identity = load_identity(key_file)?;
    println!("本机节点: {}", identity.node_id());
    println!("目标对端:   {} ({})", peer.short(), peer);

    let config = direct_config(&direct, peer);
    let link = establish(&identity, &config).await?;
    println!("直连候选已准备：{}", link.describe());

    let connection = link.connect_authenticated(&identity).await?;
    println!("已完成 QUIC / Ed25519 认证，开始内存到内存测速。\n");

    let result = run_speedtest(
        &connection,
        direction,
        Duration::from_secs(duration_secs),
        block_size as usize,
        |progress| {
            println!(
                "[{:>2}s] {:>8.2} MiB/s {:>8.2} Mbps RTT {:.0} ms ({})",
                progress.elapsed.as_secs(),
                progress.mib_per_sec,
                progress.mbps,
                progress.rtt.as_secs_f64() * 1000.0,
                progress.direction.as_str(),
            );
        },
    )
    .await;

    connection.close(0u32.into(), b"speedtest done");
    close_endpoints(&link.endpoints()).await;

    let reports = result?;
    println!();
    println!("P2P speedtest");
    println!("peer:           {}", peer);
    println!("remote:         {}", connection.remote_address());
    println!("direction:      {}", direction.as_str());
    println!("configured duration: {:.2} s", duration_secs as f64);

    for report in &reports {
        print_speedtest_report(report);
    }
    if reports.len() > 1 {
        let bytes: u64 = reports.iter().map(|report| report.bytes).sum();
        let elapsed: Duration = reports
            .iter()
            .map(|report| report.elapsed)
            .fold(Duration::ZERO, |total, value| total + value);
        println!(
            "both total:      elapsed {:.3} s, {} bytes, {:.2} MiB/s, {:.2} Mbps",
            elapsed.as_secs_f64(),
            bytes,
            bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
            bytes as f64 * 8.0 / 1_000_000.0 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
        );
    }
    Ok(())
}

fn print_speedtest_report(report: &SpeedTestReport) {
    println!("phase:           {}", report.direction.as_str());
    println!("elapsed:         {:.3} s", report.elapsed.as_secs_f64());
    println!(
        "bytes:          {} ({:.2} MiB)",
        report.bytes,
        report.bytes as f64 / (1024.0 * 1024.0)
    );
    println!("throughput:     {:.2} MiB/s", report.mib_per_sec());
    println!("throughput:     {:.2} Mbps", report.mbps());
    print_speedtest_stats(&report.stats);
}

fn print_speedtest_stats(stats: &SpeedTestStats) {
    println!("RTT:            {:.0} ms", stats.rtt.as_secs_f64() * 1000.0);
    println!("cwnd:           {} bytes", stats.cwnd);
    println!("lost packets:   {}", stats.lost_packets);
    println!("lost bytes:     {}", stats.lost_bytes);
    println!("congestion events: {}", stats.congestion_events);
    println!("MTU:            {} bytes", stats.current_mtu);
    println!(
        "UDP sent:       {} datagrams / {} bytes",
        stats.sent_datagrams, stats.sent_bytes
    );
    println!(
        "UDP received:   {} datagrams / {} bytes",
        stats.received_datagrams, stats.received_bytes
    );
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
