//! Cross-platform OS-process harness. This whole module is cfg(test): production
//! desktop has no RPC, environment switch, fault injector or alternate network loop.
use super::{
    config::{self, DesktopConfig, SettingsDraft},
    network_state::{NetworkLifecycle, PeerLifecycle},
    session::{self, DesktopSessionConfig, DesktopSessionHandle, SessionEvent},
    task_model::TaskId,
    task_store::TaskStore,
    transfer::TransferService,
};
use crate::{
    identity::{Identity, NodeId},
    net::DesktopNetworkConfig,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
const PREFIX: &str = "DESKTOP_E2E_RPC ";
const ENTRY: &str = "desktop::e2e::tests::actor_process";
const DEADLINE: Duration = Duration::from_secs(60);
fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}
fn peer(v: &Value) -> NodeId {
    NodeId::from_hex(str_field(v, "peer")).unwrap()
}
fn id(v: &Value) -> TaskId {
    TaskId::parse(str_field(v, "id")).unwrap()
}
fn start(
    identity: Identity,
    draft: &SettingsDraft,
    service: TransferService,
) -> (
    DesktopSessionHandle,
    tokio::sync::mpsc::Receiver<SessionEvent>,
) {
    let mut conf = DesktopSessionConfig::new(super::signal_server_spec(
        &draft.signal_host,
        &draft.signal_port,
    ));
    conf.network = DesktopNetworkConfig {
        local_port: 0,
        stun_servers: Vec::new(),
        include_loopback: true,
        ..Default::default()
    };
    conf.transfer = Some(service);
    session::spawn(identity, conf).unwrap()
}
fn actor(root: PathBuf) {
    config::ensure_private_app_dir(&root.join("state")).unwrap();
    fs::create_dir_all(root.join("receive")).unwrap();
    let identity = Identity::load_or_create(&root.join("state/identity.bin")).unwrap();
    let saved = DesktopConfig::load(&root.join("state/config.json")).unwrap();
    let mut draft = saved
        .clone()
        .map(SettingsDraft::from_config)
        .unwrap_or_else(|| SettingsDraft::defaults(Some(root.join("receive"))));
    let (store, _) = TaskStore::open(&root.join("state/tasks.json")).unwrap();
    let service = TransferService::new(store, draft.receive_directory.clone().unwrap());
    service.set_send_limit(draft.send_concurrency).unwrap();
    let mut network = saved.map(|_| start(identity.clone(), &draft, service.clone()));
    let mut online = false;
    let mut peers = HashMap::<NodeId, (u64, String)>::new();
    let mut diagnostics = Vec::<String>::new();
    let mut reached = None::<tokio::sync::oneshot::Receiver<()>>;
    let mut release = None::<tokio::sync::oneshot::Sender<()>>;
    let mut gated = false;
    for line in std::io::stdin().lock().lines() {
        let v: Value = serde_json::from_str(&line.unwrap()).unwrap();
        if let Some((_, events)) = &mut network {
            while let Ok(event) = events.try_recv() {
                match event {
                    SessionEvent::SignalIdentityRegistered(node) => {
                        assert_eq!(node, identity.node_id());
                        online = true;
                    }
                    SessionEvent::Lifecycle(
                        NetworkLifecycle::ReconnectingSignal { .. }
                        | NetworkLifecycle::ConnectingSignal
                        | NetworkLifecycle::Failed { .. },
                    ) => online = false,
                    SessionEvent::PeerState {
                        peer,
                        generation,
                        state,
                    } => {
                        if peers.get(&peer).is_none_or(|(g, _)| generation >= *g) {
                            peers.insert(
                                peer,
                                (
                                    generation,
                                    if matches!(state, PeerLifecycle::Connected) {
                                        "Connected".into()
                                    } else {
                                        format!("{state:?}")
                                    },
                                ),
                            );
                        }
                    }
                    SessionEvent::Diagnostic(s) => {
                        if diagnostics.len() == 32 {
                            diagnostics.remove(0);
                        }
                        diagnostics.push(s);
                    }
                    _ => {}
                }
            }
        }
        if let Some(rx) = &mut reached
            && rx.try_recv().is_ok()
        {
            gated = true;
        }
        let command = str_field(&v, "op");
        let result: Result<Value, String> = (|| match command {
            "configure" => {
                let addr: SocketAddr = str_field(&v, "signal").parse().unwrap();
                draft.signal_host = addr.ip().to_string();
                draft.signal_port = addr.port().to_string();
                draft
                    .save_atomic(&root.join("state/config.json"))
                    .map_err(|e| e.to_string())?;
                assert!(network.is_none());
                network = Some(start(identity.clone(), &draft, service.clone()));
                Ok(json!(true))
            }
            "connect" => network
                .as_ref()
                .unwrap()
                .0
                .connect_peer(peer(&v))
                .map(|_| json!(true)),
            "file" => network
                .as_ref()
                .unwrap()
                .0
                .send_file(peer(&v), PathBuf::from(str_field(&v, "path")))
                .map(|_| json!(true)),
            "directory" => network
                .as_ref()
                .unwrap()
                .0
                .send_directory(peer(&v), PathBuf::from(str_field(&v, "path")))
                .map(|_| json!(true)),
            "pause" => network
                .as_ref()
                .unwrap()
                .0
                .pause_task(id(&v))
                .map(|_| json!(true)),
            "resume" => network
                .as_ref()
                .unwrap()
                .0
                .resume_task(peer(&v), id(&v))
                .map(|_| json!(true)),
            "limit" => {
                let value = v["value"].as_u64().unwrap() as u8;
                let mut changed = draft.clone();
                changed.send_concurrency = value;
                changed
                    .save_atomic(&root.join("state/config.json"))
                    .map_err(|e| e.to_string())?;
                service.set_send_limit(value).map_err(|e| e.to_string())?;
                draft = changed;
                Ok(json!(true))
            }
            "gate" => {
                assert!(release.is_none());
                let (tx, rx) = tokio::sync::oneshot::channel();
                let (send, recv) = tokio::sync::oneshot::channel();
                if v["kind"] == "checkpoint" {
                    *service.checkpoint_gate.lock().unwrap() = Some((tx, recv));
                } else {
                    *service.first_chunk_gate.lock().unwrap() = Some((tx, recv));
                }
                reached = Some(rx);
                release = Some(send);
                gated = false;
                Ok(json!(true))
            }
            "release" => {
                release
                    .take()
                    .unwrap()
                    .send(())
                    .map_err(|_| "gate already ended".to_owned())?;
                reached = None;
                gated = false;
                Ok(json!(true))
            }
            "storage-error" => {
                *service.publication_error.lock().unwrap() = Some(if v["kind"] == "full" {
                    std::io::ErrorKind::StorageFull
                } else {
                    std::io::ErrorKind::PermissionDenied
                });
                Ok(json!(true))
            }
            "snapshot" => {
                let snap = service.ui_snapshot().map_err(|e| e.to_string())?;
                let tasks=snap.tasks.iter().map(|t|json!({"id":t.id.as_str(),"name":t.name,"peer":t.peer.to_hex(),"state":format!("{:?}",t.state),"confirmed":t.confirmed,"total":t.total,"rate":t.rate,"diagnostic":t.diagnostic,"retryable":t.retryable})).collect::<Vec<_>>();
                Ok(
                    json!({"node":identity.node_id().to_hex(),"configured":network.is_some(),"signal_online":online,"receive_root":draft.receive_directory,"peers":peers.iter().map(|(p,(_,s))|(p.to_hex(),s.clone())).collect::<HashMap<_,_>>(),"tasks":tasks,"limit":snap.queue.limit,"pending":snap.queue.pending,"active":snap.queue.active_files,"gated":gated,"diagnostics":diagnostics}),
                )
            }
            "stop" => Ok(json!(true)),
            _ => Err("unknown test control".into()),
        })();
        println!(
            "{PREFIX}{}",
            json!({"seq":v["seq"],"result":result.as_ref().ok(),"error":result.err()})
        );
        std::io::stdout().flush().unwrap();
        if command == "stop" {
            break;
        }
    }
    if let Some((handle, _)) = network {
        handle.shutdown();
        drop(handle);
    }
}
struct Actor {
    child: Child,
    input: ChildStdin,
    output: mpsc::Receiver<Value>,
    reader: Option<std::thread::JoinHandle<()>>,
    seq: u64,
    root: PathBuf,
}
impl Actor {
    fn spawn(root: PathBuf) -> Self {
        fs::create_dir_all(&root).unwrap();
        let log = fs::File::create(root.join("actor.log")).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", ENTRY, "--nocapture"])
            .env("P2P_DESKTOP_E2E_ACTOR", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            let mut log = log;
            for line in BufReader::new(out).lines() {
                let line = line.unwrap();
                writeln!(log, "{line}").unwrap();
                if let Some(data) = line.strip_prefix(PREFIX) {
                    let value = serde_json::from_str(data).unwrap();
                    if tx.send(value).is_err() {
                        break;
                    }
                }
            }
        });
        Self {
            child,
            input,
            output: rx,
            reader: Some(reader),
            seq: 0,
            root,
        }
    }
    fn call(&mut self, mut request: Value) -> Value {
        self.seq += 1;
        request["seq"] = json!(self.seq);
        writeln!(self.input, "{request}").unwrap();
        self.input.flush().unwrap();
        let response = self.output.recv_timeout(DEADLINE).unwrap_or_else(|e| {
            panic!(
                "actor {} response: {e}; {}",
                self.root.display(),
                fs::read_to_string(self.root.join("actor.log")).unwrap()
            )
        });
        assert_eq!(response["seq"], self.seq);
        assert!(response["error"].is_null(), "{response}");
        response["result"].clone()
    }
    fn snapshot(&mut self) -> Value {
        self.call(json!({"op":"snapshot"}))
    }
    fn wait(&mut self, description: &str, mut check: impl FnMut(&Value) -> bool) -> Value {
        let begin = Instant::now();
        loop {
            let v = self.snapshot();
            if check(&v) {
                return v;
            }
            assert!(
                begin.elapsed() < DEADLINE,
                "{description}: {v}; fixture {}",
                self.root.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn node(&mut self) -> String {
        str_field(&self.snapshot(), "node").to_owned()
    }
    fn configure(&mut self, server: SocketAddr) {
        self.call(json!({"op":"configure","signal":server.to_string()}));
        self.wait("signal registration", |s| s["signal_online"] == true);
    }
    fn connect(&mut self, node: &str) {
        self.call(json!({"op":"connect","peer":node}));
        self.wait("authenticated peer", |s| s["peers"][node] == "Connected");
    }
    fn send(&mut self, node: &str, path: &Path, directory: bool) {
        self.call(json!({"op":if directory{"directory"}else{"file"},"peer":node,"path":path}));
    }
    fn task(&mut self, name: &str) -> Value {
        let s = self.wait("task appears", |s| {
            s["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["name"] == name)
        });
        s["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap()
            .clone()
    }
    fn state(&mut self, id: &str, state: &str) -> Value {
        self.wait(state, |s| {
            s["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == id && t["state"] == state)
        })
    }
    fn kill(&mut self) {
        self.child.kill().unwrap();
        let status = self.child.wait().unwrap();
        assert!(!status.success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
    fn stop(&mut self) {
        self.call(json!({"op":"stop"}));
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "{}",
                    fs::read_to_string(self.root.join("actor.log")).unwrap()
                );
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(10));
        }
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
struct Server {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn spawn(addr: SocketAddr) -> Self {
        let (tx, rx) = mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                    tx.send(listener.local_addr().unwrap()).unwrap();
                    let job = tokio::spawn(crate::discovery::signal::run_signal_server_on_with(
                        listener,
                        Default::default(),
                    ));
                    let _ = stopped.await;
                    job.abort();
                    let _ = job.await;
                });
        });
        Self {
            addr: rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    fn new() -> Self {
        Self::spawn("127.0.0.1:0".parse().unwrap())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("p2p-session-e2e-{}", rand::random::<u128>()));
        config::ensure_private_app_dir(&root).unwrap();
        Self(root)
    }
    fn actor(&self, role: &str) -> Actor {
        Actor::spawn(self.0.join(role))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("retained failing fixture {}", self.0.display());
        } else {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn rows(s: &Value) -> &[Value] {
    s["tasks"].as_array().unwrap()
}
fn proof(scenario: &str, detail: Value) {
    println!(
        "DESKTOP_E2E_PROOF {}",
        json!({"scenario":scenario,"platform":std::env::consts::OS,"detail":detail})
    );
}
fn complete(a: &mut Actor, b: &mut Actor, id: &str, path: &Path, expected: &[u8]) {
    for actor in [&mut *a, &mut *b] {
        let s = actor.state(id, "Completed");
        let row = rows(&s).iter().find(|t| t["id"] == id).unwrap();
        assert_eq!(row["rate"], 0.);
        assert_eq!(row["confirmed"], expected.len() as u64);
        let stored: Value =
            serde_json::from_slice(&fs::read(actor.root.join("state/tasks.json")).unwrap())
                .unwrap();
        let record = stored["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["task_id"] == id)
            .unwrap();
        assert_eq!(record["file_details"]["receipt_committed"], true);
    }
    let actual = fs::read(path).unwrap();
    assert_eq!(blake3::hash(&actual), blake3::hash(expected));
    assert_eq!(actual, expected);
}
fn large(root: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    let bytes = vec![73; 70 * 1024 * 1024];
    let source = root.join(name);
    fs::write(&source, &bytes).unwrap();
    (source, bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actor_process() {
        if let Some(root) = std::env::var_os("P2P_DESKTOP_E2E_ACTOR") {
            actor(root.into());
        }
    }
    #[test]
    fn three_process_passive_directory_collision_and_signal_restart() {
        let f = Fixture::new();
        let server = Server::new();
        let addr = server.addr;
        let mut a = f.actor("a");
        let mut b = f.actor("b");
        let mut c = f.actor("c");
        let aid = a.node();
        let bid = b.node();
        let cid = c.node();
        assert!(!a.snapshot()["configured"].as_bool().unwrap());
        assert!(rows(&a.snapshot()).is_empty());
        assert!(!a.root.join("state/config.json").exists());
        for actor in [&mut a, &mut b, &mut c] {
            actor.configure(addr);
        }
        b.connect(&aid);
        c.connect(&aid);
        a.wait("two passive peers", |s| {
            s["peers"][&bid] == "Connected" && s["peers"][&cid] == "Connected"
        });
        let bytes = vec![19; 2 * 1024 * 1024 + 7];
        let src = f.0.join("中文🙂.txt");
        fs::write(&src, &bytes).unwrap();
        b.send(&aid, &src, false);
        let task = b.task("中文🙂.txt");
        let tid = str_field(&task, "id");
        let output = a.root.join("receive/中文🙂.txt");
        complete(&mut b, &mut a, tid, &output, &bytes);
        let dir = f.0.join("中文目录");
        fs::create_dir_all(dir.join("子目录/空目录")).unwrap();
        fs::write(dir.join("子目录/空文件"), b"").unwrap();
        let content = vec![51; 50000];
        fs::write(dir.join("子目录/内容.txt"), &content).unwrap();
        fs::create_dir_all(a.root.join("receive/中文目录/子目录")).unwrap();
        fs::write(
            a.root.join("receive/中文目录/子目录/内容.txt"),
            b"old contents",
        )
        .unwrap();
        c.send(&aid, &dir, true);
        for actor in [&mut a, &mut c] {
            actor.wait("whole directory complete", |s| {
                rows(s)
                    .iter()
                    .filter(|t| str_field(t, "name").starts_with("中文目录"))
                    .count()
                    == 5
                    && rows(s)
                        .iter()
                        .filter(|t| str_field(t, "name").starts_with("中文目录"))
                        .all(|t| t["state"] == "Completed")
            });
        }
        assert!(a.root.join("receive/中文目录/子目录/空目录").is_dir());
        assert_eq!(
            fs::read(a.root.join("receive/中文目录/子目录/空文件")).unwrap(),
            b""
        );
        assert_eq!(
            fs::read(a.root.join("receive/中文目录/子目录/内容.txt")).unwrap(),
            content
        );
        let backups = fs::read_dir(a.root.join("receive/中文目录/子目录"))
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("内容+")
                    .then_some(p)
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(&backups[0]).unwrap(), b"old contents");
        for value in [2, 3, 1] {
            b.call(json!({"op":"limit","value":value}));
            assert_eq!(b.snapshot()["limit"], value);
        }
        let before = a.snapshot()["tasks"].clone();
        let root = a.root.clone();
        a.kill();
        a = Actor::spawn(root);
        assert_eq!(a.node(), aid);
        a.wait("restored config", |s| s["signal_online"] == true);
        assert_eq!(a.snapshot()["tasks"], before);
        assert_eq!(a.snapshot()["pending"], 0);
        b.connect(&aid);
        c.connect(&aid);
        a.wait("fresh passive connections after restart", |s| {
            s["peers"][&bid] == "Connected" && s["peers"][&cid] == "Connected"
        });
        drop(server);
        for actor in [&mut a, &mut b, &mut c] {
            actor.wait("signal really offline", |s| s["signal_online"] == false);
        }
        let server = Server::spawn(addr);
        for actor in [&mut a, &mut b, &mut c] {
            actor.wait("same identity re-register", |s| s["signal_online"] == true);
        }
        assert_eq!(a.node(), aid);
        assert_eq!(b.node(), bid);
        assert_eq!(c.node(), cid);
        let next = f.0.join("restart.txt");
        fs::write(&next, b"after signal restart").unwrap();
        c.send(&aid, &next, false);
        let task = c.task("restart.txt");
        let output = a.root.join("receive/restart.txt");
        complete(
            &mut c,
            &mut a,
            str_field(&task, "id"),
            &output,
            b"after signal restart",
        );
        proof(
            "three-process-passive-directory-collision-config-signal",
            json!({"nodes":[aid,bid,cid],"directory_entries":5,"file_hash":blake3::hash(&bytes).to_hex().to_string(),"backup_count":1,"identity_preserved":true}),
        );
        a.stop();
        b.stop();
        c.stop();
        drop(server);
    }
    #[test]
    fn two_process_pause_both_sides_and_storage_source_errors_reach_ui() {
        let f = Fixture::new();
        let server = Server::new();
        let mut a = f.actor("a");
        let mut b = f.actor("b");
        a.configure(server.addr);
        b.configure(server.addr);
        let aid = a.node();
        let bid = b.node();
        a.connect(&bid);
        for mode in ["sender", "receiver", "simultaneous"] {
            let (source, bytes) = large(&f.0, &format!("{mode}.bin"));
            b.call(json!({"op":"gate","kind":"chunk"}));
            a.send(&bid, &source, false);
            b.wait("first real chunk gate", |s| s["gated"] == true);
            let task = a.task(&format!("{mode}.bin"));
            let tid = str_field(&task, "id");
            if mode != "receiver" {
                a.call(json!({"op":"pause","id":tid}));
            }
            if mode != "sender" {
                b.call(json!({"op":"pause","id":tid}));
            }
            b.call(json!({"op":"release"}));
            for actor in [&mut a, &mut b] {
                let s = actor.state(tid, "Paused");
                assert_eq!(
                    rows(&s).iter().find(|t| t["id"] == tid).unwrap()["rate"],
                    0.
                );
            }
            if mode == "receiver" {
                b.call(json!({"op":"resume","peer":aid,"id":tid}));
            } else {
                a.call(json!({"op":"resume","peer":bid,"id":tid}));
            }
            let path = b.root.join(format!("receive/{mode}.bin"));
            complete(&mut a, &mut b, tid, &path, &bytes);
            assert_eq!(
                fs::read_dir(b.root.join("receive"))
                    .unwrap()
                    .filter(|e| e
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(mode))
                    .count(),
                1
            );
            proof(
                "process-pause-continue",
                json!({"initiator":mode,"task_id":tid,"bytes":bytes.len(),"hash":blake3::hash(&bytes).to_hex().to_string()}),
            );
        }
        for kind in ["full", "permission"] {
            let name = format!("{kind}.txt");
            let source = f.0.join(&name);
            fs::write(&source, b"new contents").unwrap();
            fs::write(b.root.join("receive").join(&name), b"old contents").unwrap();
            b.call(json!({"op":"storage-error","kind":kind}));
            a.send(&bid, &source, false);
            let task = a.task(&name);
            let tid = str_field(&task, "id");
            let failed = b.state(tid, "Failed");
            let row = rows(&failed).iter().find(|t| t["id"] == tid).unwrap();
            assert!(!row["diagnostic"].is_null());
            assert_eq!(row["rate"], 0.);
            assert_eq!(row["retryable"], true);
            assert_eq!(
                fs::read(b.root.join("receive").join(&name)).unwrap(),
                b"old contents"
            );
            let remote_failed = a.state(tid, "Failed");
            assert!(
                rows(&remote_failed)
                    .iter()
                    .find(|t| t["id"] == tid)
                    .unwrap()["diagnostic"]
                    .is_string()
            );
            b.call(json!({"op":"resume","peer":aid,"id":tid}));
            let path = b.root.join("receive").join(&name);
            complete(&mut a, &mut b, tid, &path, b"new contents");
            proof(
                "modeled-publication-io-error-ui-retry",
                json!({"kind":kind,"task_id":tid,"diagnostic":row["diagnostic"],"modeled":true}),
            );
        }
        for change in ["changed", "missing"] {
            let name = format!("source-{change}.bin");
            let (source, _) = large(&f.0, &name);
            b.call(json!({"op":"gate","kind":"chunk"}));
            a.send(&bid, &source, false);
            b.wait("source failure first chunk", |s| s["gated"] == true);
            let task = a.task(&name);
            let tid = str_field(&task, "id");
            a.call(json!({"op":"pause","id":tid}));
            b.call(json!({"op":"release"}));
            a.state(tid, "Paused");
            b.state(tid, "Paused");
            if change == "changed" {
                let mut file = fs::OpenOptions::new().write(true).open(&source).unwrap();
                file.write_all(b"different bytes").unwrap();
            } else {
                fs::remove_file(&source).unwrap();
            }
            a.call(json!({"op":"resume","peer":bid,"id":tid}));
            let failed = a.state(tid, "Failed");
            let row = rows(&failed).iter().find(|t| t["id"] == tid).unwrap();
            assert!(!row["diagnostic"].is_null());
            assert_eq!(row["rate"], 0.);
            assert!(!b.root.join("receive").join(&name).exists());
            proof(
                "process-source-failure-ui",
                json!({"kind":change,"task_id":tid,"diagnostic":row["diagnostic"]}),
            );
        }
        a.stop();
        b.stop();
        drop(server);
    }
    #[cfg(unix)]
    #[test]
    fn actual_unix_receive_permission_failure_reaches_ui_and_retry_preserves_old_file() {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(PathBuf, fs::Permissions);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, self.1.clone());
            }
        }
        let f = Fixture::new();
        let server = Server::new();
        let mut a = f.actor("a");
        let mut b = f.actor("b");
        a.configure(server.addr);
        b.configure(server.addr);
        let aid = a.node();
        let bid = b.node();
        a.connect(&bid);
        let source = f.0.join("permission-real.bin");
        let bytes = vec![84; 1024 * 1024];
        fs::write(&source, &bytes).unwrap();
        let receive = b.root.join("receive");
        let target = receive.join("permission-real.bin");
        fs::write(&target, b"old actual permission content").unwrap();
        b.call(json!({"op":"gate","kind":"chunk"}));
        a.send(&bid, &source, false);
        b.wait("real permission first chunk", |s| s["gated"] == true);
        let task = a.task("permission-real.bin");
        let tid = str_field(&task, "id");
        let restore = Restore(
            receive.clone(),
            fs::metadata(&receive).unwrap().permissions(),
        );
        fs::set_permissions(&receive, fs::Permissions::from_mode(0o500)).unwrap();
        b.call(json!({"op":"release"}));
        let failed = b.state(tid, "Failed");
        let row = rows(&failed).iter().find(|t| t["id"] == tid).unwrap();
        assert!(row["diagnostic"].is_string());
        assert_eq!(row["rate"], 0.);
        assert_eq!(row["retryable"], true);
        assert_eq!(fs::read(&target).unwrap(), b"old actual permission content");
        a.state(tid, "Failed");
        drop(restore);
        b.call(json!({"op":"resume","peer":aid,"id":tid}));
        complete(&mut a, &mut b, tid, &target, &bytes);
        proof(
            "actual-unix-permission-ui-retry",
            json!({"task_id":tid,"modeled":false,"operation":"chmod receive directory 0500","hash":blake3::hash(&bytes).to_hex().to_string()}),
        );
        a.stop();
        b.stop();
        drop(server);
    }

    #[test]
    fn session_process_kill_either_endpoint_restart_requires_manual_continue() {
        for killed in ["a", "b"] {
            let f = Fixture::new();
            let server = Server::new();
            let mut a = f.actor("a");
            let mut b = f.actor("b");
            a.configure(server.addr);
            b.configure(server.addr);
            let aid = a.node();
            let bid = b.node();
            a.connect(&bid);
            let (source, bytes) = large(&f.0, "kill.bin");
            b.call(json!({"op":"gate","kind":"checkpoint"}));
            a.send(&bid, &source, false);
            b.wait("actual durable checkpoint", |s| s["gated"] == true);
            let task = a.task("kill.bin");
            let tid = str_field(&task, "id");
            if killed == "a" {
                a.kill();
                b.call(json!({"op":"release"}));
                b.state(tid, "Interrupted");
                a = Actor::spawn(f.0.join("a"));
            } else {
                b.kill();
                a.state(tid, "Interrupted");
                b = Actor::spawn(f.0.join("b"));
            }
            assert_eq!(a.node(), aid);
            assert_eq!(b.node(), bid);
            for actor in [&mut a, &mut b] {
                let s = actor.state(tid, "Interrupted");
                assert_eq!(s["pending"], 0);
                assert_eq!(
                    rows(&s).iter().find(|t| t["id"] == tid).unwrap()["rate"],
                    0.
                );
                actor.wait("restored signal", |s| s["signal_online"] == true);
            }
            std::thread::sleep(Duration::from_millis(150));
            assert!(!b.root.join("receive/kill.bin").exists());
            a.connect(&bid);
            b.wait("fresh authenticated survivor connection", |s| {
                s["peers"][&aid] == "Connected"
            });
            a.call(json!({"op":"resume","peer":bid,"id":tid}));
            let path = b.root.join("receive/kill.bin");
            complete(&mut a, &mut b, tid, &path, &bytes);
            assert_eq!(
                fs::read_dir(b.root.join("receive"))
                    .unwrap()
                    .filter(|e| !e
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with('.'))
                    .count(),
                1
            );
            proof(
                "session-os-kill-manual-continue",
                json!({"killed":killed,"task_id":tid,"bytes":bytes.len(),"hash":blake3::hash(&bytes).to_hex().to_string(),"os_kill":if cfg!(unix){"SIGKILL"}else{"TerminateProcess"}}),
            );
            a.stop();
            b.stop();
            drop(server);
        }
    }
}
