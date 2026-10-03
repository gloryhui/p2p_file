//! Actual CLI TLS-only server, serve and push; no public server or STUN service.
use p2p_file::{identity::Identity, net::family::bind_udp};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
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
fn ready(process: &mut Process, log: &Path, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let text = fs::read_to_string(log).unwrap();
        if text.contains(marker) {
            return;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "process stopped: {text}"
        );
        assert!(Instant::now() < deadline, "CLI readiness timeout: {text}");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn run(command: &mut Command, log: &Path) -> Process {
    let output = fs::File::create(log).unwrap();
    Process(
        command
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    )
}
fn finished(process: &mut Process, log: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            return status.success();
        }
        assert!(
            Instant::now() < deadline,
            "CLI completion timeout: {}",
            fs::read_to_string(log).unwrap()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
#[test]
fn signaling_tls_cli_server_serve_push_verify_names_and_preserve_file_transfer() {
    let root = Directory(std::env::temp_dir().join(format!(
        "p2p-cli-signal-tls-{:032x}",
        rand::random::<u128>()
    )));
    fs::create_dir(&root.0).unwrap();
    let received = root.0.join("received");
    fs::create_dir(&received).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_path = root.0.join("server.pem");
    let key_path = root.0.join("server.key");
    fs::write(&cert_path, cert.pem()).unwrap();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(&key_path)
        .unwrap()
        .write_all(key.serialize_pem().as_bytes())
        .unwrap();
    let server_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let signal = server_socket.local_addr().unwrap();
    drop(server_socket);
    let binary = env!("CARGO_BIN_EXE_p2p_file");
    let signal_log = root.0.join("signal.log");
    let mut server = run(
        Command::new(binary)
            .args([
                "signal-server",
                "--listen",
                &signal.to_string(),
                "--tls-cert",
            ])
            .arg(&cert_path)
            .arg("--tls-key")
            .arg(&key_path)
            .arg("--short-id-db")
            .arg(root.0.join("ids.sqlite3")),
        &signal_log,
    );
    ready(&mut server, &signal_log, "信令服务器已启动");
    let sender = Identity::generate();
    let receiver = Identity::generate();
    let sender_key = root.0.join("sender.key");
    let receiver_key = root.0.join("receiver.key");
    sender.save(&sender_key).unwrap();
    receiver.save(&receiver_key).unwrap();
    let receiver_socket = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let receiver_udp = receiver_socket.local_addr().unwrap();
    drop(receiver_socket);
    let receiver_log = root.0.join("receiver.log");
    let mut receiver_process = run(
        Command::new(binary)
            .arg("--key-file")
            .arg(receiver_key)
            .args([
                "serve",
                "--signal",
                &signal.to_string(),
                "--signal-tls",
                "--signal-ca-file",
            ])
            .arg(&cert_path)
            .args([
                "--signal-server-name",
                "localhost",
                "--allow",
                &sender.node_id().to_hex(),
                "--ip-family",
                "ipv4-only",
                "--port",
                &receiver_udp.port().to_string(),
                "--advertise-only",
                "--advertise",
                &receiver_udp.to_string(),
                "--recv-dir",
            ])
            .arg(&received),
        &receiver_log,
    );
    ready(&mut receiver_process, &receiver_log, "常驻等待中");
    let source = root.0.join("tls-transfer.bin");
    let data = vec![69u8; 160_000];
    fs::write(&source, &data).unwrap();
    let socket = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let sender_udp = socket.local_addr().unwrap();
    drop(socket);
    let push = |name: &str| {
        let mut command = Command::new(binary);
        command
            .arg("--key-file")
            .arg(&sender_key)
            .args([
                "push",
                "--signal",
                &signal.to_string(),
                "--signal-tls",
                "--signal-ca-file",
            ])
            .arg(&cert_path)
            .args([
                "--signal-server-name",
                name,
                "--peer",
                &receiver.node_id().to_hex(),
                "--ip-family",
                "ipv4-only",
                "--port",
                &sender_udp.port().to_string(),
                "--advertise-only",
                "--advertise",
                &sender_udp.to_string(),
                "--chunk-size",
                "65536",
            ])
            .arg(&source);
        command
    };
    let bad_log = root.0.join("wrong-name.log");
    let mut failed = run(&mut push("wrong.invalid"), &bad_log);
    assert!(!finished(&mut failed, &bad_log));
    assert!(
        fs::read_to_string(&bad_log)
            .unwrap()
            .contains("证书/主机名校验失败")
    );
    assert!(!received.join("tls-transfer.bin").exists());
    let good_log = root.0.join("push.log");
    let mut sent = run(&mut push("localhost"), &good_log);
    assert!(
        finished(&mut sent, &good_log),
        "push: {}\nserve: {}\nsignal: {}",
        fs::read_to_string(&good_log).unwrap(),
        fs::read_to_string(&receiver_log).unwrap(),
        fs::read_to_string(&signal_log).unwrap()
    );
    assert_eq!(fs::read(received.join("tls-transfer.bin")).unwrap(), data);
    assert!(server.0.try_wait().unwrap().is_none());
    assert!(receiver_process.0.try_wait().unwrap().is_none());
    drop((sent, failed, receiver_process, server));
    eprintln!(
        "CLI_TLS_PROOF verified hostname rejection and TLS-only signaling with authenticated QUIC file transfer"
    );
}
