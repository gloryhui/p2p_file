//! Native IPv6 CLI send/recv, including the sender's bind-family regression.
use p2p_file::net::family::bind_udp;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn wait_process(child: &mut Child, log: &PathBuf, recv_log: &PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "send: {}\nrecv: {}",
                fs::read_to_string(log).unwrap(),
                fs::read_to_string(recv_log).unwrap()
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "CLI timeout: {}",
            fs::read_to_string(log).unwrap()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
#[test]
fn ipv6_cli_send_uses_native_ipv6_endpoint_and_recv_writes_verified_file() {
    send_recv(IpAddr::V6(Ipv6Addr::LOCALHOST));
}
#[test]
fn ipv4_cli_send_recv_keeps_complete_confirmation_compatible() {
    send_recv(IpAddr::V4(Ipv4Addr::LOCALHOST));
}
fn send_recv(ip: IpAddr) {
    let socket = match bind_udp(SocketAddr::new(ip, 0)) {
        Ok(socket) => socket,
        Err(error)
            if ip.is_ipv6()
                && (matches!(
                    error.raw_os_error(),
                    Some(97 | 99 | 49 | 47 | 10047 | 10049)
                ) || error.kind() == std::io::ErrorKind::Unsupported) =>
        {
            eprintln!("SKIP IPv6 CLI loopback: runner has no IPv6 capability: {error}");
            return;
        }
        Err(error) => panic!("unexpected IPv6 capability error: {error}"),
    };
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let root = Directory(
        std::env::temp_dir().join(format!("p2p-cli-ipv6-{:032x}", rand::random::<u128>())),
    );
    fs::create_dir_all(&root.0).unwrap();
    let recv_dir = root.0.join("received");
    fs::create_dir(&recv_dir).unwrap();
    let source = root.0.join("native-ipv6.bin");
    let data = vec![83_u8; 160_000];
    fs::write(&source, &data).unwrap();
    let recv_log = root.0.join("recv.log");
    let output = fs::File::create(&recv_log).unwrap();
    let mut receiver = Process(
        Command::new(env!("CARGO_BIN_EXE_p2p_file"))
            .arg("--key-file")
            .arg(root.0.join("recv.key"))
            .args(["recv", "--listen", &addr.to_string(), "--out-dir"])
            .arg(&recv_dir)
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fs::read_to_string(&recv_log).unwrap().contains("监听中") {
        assert!(
            receiver.0.try_wait().unwrap().is_none(),
            "recv failed: {}",
            fs::read_to_string(&recv_log).unwrap()
        );
        assert!(Instant::now() < deadline, "recv never became ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    let send_log = root.0.join("send.log");
    let output = fs::File::create(&send_log).unwrap();
    let mut sender = Process(
        Command::new(env!("CARGO_BIN_EXE_p2p_file"))
            .arg("--key-file")
            .arg(root.0.join("send.key"))
            .arg("send")
            .arg(&source)
            .arg(addr.to_string())
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    );
    wait_process(&mut sender.0, &send_log, &recv_log);
    assert_eq!(fs::read(recv_dir.join("native-ipv6.bin")).unwrap(), data);
}
