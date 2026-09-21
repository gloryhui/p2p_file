//! 命令行入口。

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use p2p_file::cli::{Cli, Command, DirectOpts};
use p2p_file::discovery::signal::run_signal_server;
use p2p_file::discovery::{LanDiscovery, parse_announcement};
use p2p_file::error::{Error, Result};
use p2p_file::identity::Identity;
use p2p_file::nat::punch::PunchConfig;
use p2p_file::net::{DirectConfig, establish};
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

        Command::SignalServer { listen } => cmd_signal_server(listen).await,
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
    use p2p_file::nat::{MappingBehavior, MappingEvidence, probe_rfc5780, resolve_server};

    // 没指定就用默认的那几个。要判断 NAT 类型至少需要两个不同的观测点。
    let specs: Vec<String> = if servers.is_empty() {
        p2p_file::net::DEFAULT_STUN_SERVERS
            .iter()
            .map(|spec| spec.to_string())
            .collect()
    } else {
        servers.to_vec()
    };

    let mut addrs = Vec::new();
    for spec in &specs {
        match resolve_server(spec).await {
            Ok(addr) => addrs.push(addr),
            Err(err) => println!("跳过 {spec}：{err}"),
        }
    }
    if addrs.is_empty() {
        return Err(Error::Discovery("没有一个 STUN 服务器能解析出地址".into()));
    }

    // 所有查询必须共用同一个 socket。换个 socket 就是换个本地端口，
    // 也就换了一个 NAT 映射，观测结果之间就没法比较了。
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    println!(
        "本地端口 {}，向 {} 个 STUN 服务器查询 ...",
        socket.local_addr()?.port(),
        addrs.len()
    );
    println!();

    let timeout = Duration::from_secs(timeout_secs);
    let mut reports = Vec::new();
    for addr in addrs {
        match probe_rfc5780(&socket, addr, timeout).await {
            Ok(report) => {
                for obs in &report.observations {
                    println!("  {:<28} 看到的是 {}", obs.server, obs.mapped_addr);
                }
                reports.push(report);
            }
            Err(err) => println!("跳过 {addr}：{err}"),
        }
    }
    if reports.is_empty() {
        return Err(Error::Discovery(
            "所有 STUN 服务器都没有响应（网络不通或者被防火墙挡了）".into(),
        ));
    }

    let report = reports
        .iter()
        .find(|report| report.evidence == MappingEvidence::Rfc5780)
        .unwrap_or(&reports[0]);
    let behavior = report.mapping;
    println!();
    println!("NAT 映射行为: {}", behavior.describe());
    println!("mapping 证据: {}", report.evidence.describe());
    println!("Filtering behavior: 未测量（当前只测 mapping）");

    match behavior {
        MappingBehavior::EndpointIndependent => {
            println!("mapping 对打洞较有利，但尚未测 filtering，不能保证最终可打洞。")
        }
        MappingBehavior::AddressDependent => {
            println!("mapping 仅呈条件性地址相关；尚未测 filtering，不能宣称可以打洞。")
        }
        MappingBehavior::AddressAndPortDependent => {
            println!("mapping 对直接打洞不利。可考虑端口映射或中继。")
        }
        MappingBehavior::Unknown => {
            println!("证据不足，不能判断 NAT mapping，也不能宣称可以打洞。")
        }
    }

    println!();
    println!("注意：以上端口只是「这一次查询」看到的。打洞必须复用同一个本地端口，");
    println!("否则 NAT 给出的会是另一个映射——这也是本项目把打洞和 QUIC 绑在同一个");
    println!("socket 上的原因。");
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

// ---------------------------------------------------------------------------
// 公网直连：信令服务器 / serve / tunnel / push
// ---------------------------------------------------------------------------

/// 把命令行参数翻译成打洞配置。
fn direct_config(opts: &DirectOpts, peer: p2p_file::identity::NodeId) -> DirectConfig {
    let mut config = DirectConfig::new(opts.signal.clone(), peer);
    config.local_port = opts.port;
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
async fn close_endpoint(endpoint: &quinn::Endpoint) {
    endpoint.close(0u32.into(), b"bye");
    // 给关闭帧一点时间发出去；连不上或对端没响应也不必死等。
    let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.wait_idle()).await;
}

async fn cmd_signal_server(listen: SocketAddr) -> Result<()> {
    println!("信令服务器监听 {listen}");
    println!("它只负责让双方交换候选地址，业务数据一个字节都不经过这里。");
    println!("记得在云主机安全组里放通这个 TCP 端口。");
    println!("按 Ctrl-C 退出。");

    tokio::select! {
        result = run_signal_server(listen) => result,
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
    println!("直连已建立：{}", link.describe());
    println!();
    println!("隧道已就绪：连到 {listen} 就等于连到对端的 {to}");

    let target = to.to_string();
    let endpoint = link.endpoint.clone();
    tokio::select! {
        result = forward_tunnel(link, identity, target, listen) => result,
        _ = shutdown_signal() => {
            println!("\n收到退出信号，正在关闭隧道……");
            close_endpoint(&endpoint).await;
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
    println!("直连已建立：{}", link.describe());

    let endpoint = link.endpoint.clone();
    tokio::select! {
        result = push_file(link, identity, file, chunk_size) => {
            let report = result?;
            println!(
                "发送完成：{} （{} 字节，{} 片，跳过 {} 片）",
                report.file_name, report.total_len, report.chunk_count, report.chunks_skipped
            );
            close_endpoint(&endpoint).await;
            Ok(())
        }
        _ = shutdown_signal() => {
            println!("\n收到退出信号，正在收尾……");
            close_endpoint(&endpoint).await;
            Ok(())
        }
    }
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
