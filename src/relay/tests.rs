use super::{client, server, wire};
use crate::identity::{Identity, NodeId};
use crate::nat::punch::PunchToken;
use crate::net::{AddressFamily, NetworkFamilies, family::bind_udp};
use crate::transport::quic::ChannelBinding;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

async fn socket(family: AddressFamily) -> UdpSocket {
    UdpSocket::from_std(bind_udp(family.loopback(0)).unwrap()).unwrap()
}
async fn raw_register(
    socket: &UdpSocket,
    identity: &Identity,
    peer: NodeId,
    token: PunchToken,
    server: SocketAddr,
) {
    let hello = wire::Hello::new(identity, peer, token);
    socket
        .send_to(&wire::encode(wire::Packet::Hello(hello)).unwrap(), server)
        .await
        .unwrap();
    let mut bytes = [0; 512];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, server);
    let wire::Packet::Challenge {
        client_nonce,
        nonce,
        source,
    } = wire::decode(&bytes[..n]).unwrap()
    else {
        panic!("challenge expected")
    };
    assert_eq!(client_nonce, hello.client_nonce);
    assert_eq!(source, socket.local_addr().unwrap());
    let challenge = wire::Challenge {
        hello,
        nonce,
        source,
    };
    socket
        .send_to(
            &wire::encode(wire::register(identity, challenge).unwrap()).unwrap(),
            server,
        )
        .await
        .unwrap();
}
async fn ready(socket: &UdpSocket) {
    let mut bytes = [0; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        wire::decode(&bytes[..n]).unwrap(),
        wire::Packet::Ready { .. }
    ));
}
#[tokio::test]
async fn relay_raw_udp_is_opaque_bounded_isolated_and_never_forwards_before_ready() {
    let listener = socket(AddressFamily::Ipv4).await;
    let addr = listener.local_addr().unwrap();
    let admission = server::Admission::new(server::RelayServerConfig::default()).unwrap();
    let task = tokio::spawn(server::run(listener, admission.clone()));
    let a = Identity::generate();
    let b = Identity::generate();
    let c = Identity::generate();
    let token = PunchToken::random();
    let token2 = PunchToken::random();
    assert!(admission.issue(token, a.node_id(), b.node_id()));
    assert!(admission.issue(token2, a.node_id(), c.node_id()));
    let sa = socket(AddressFamily::Ipv4).await;
    let sb = socket(AddressFamily::Ipv4).await;
    let sa2 = socket(AddressFamily::Ipv4).await;
    let sc = socket(AddressFamily::Ipv4).await;
    raw_register(&sa, &a, b.node_id(), token, addr).await;
    sa.send_to(b"before-ready", addr).await.unwrap();
    raw_register(&sb, &b, a.node_id(), token, addr).await;
    ready(&sa).await;
    ready(&sb).await;
    raw_register(&sa2, &a, c.node_id(), token2, addr).await;
    raw_register(&sc, &c, a.node_id(), token2, addr).await;
    ready(&sa2).await;
    ready(&sc).await;
    let third = socket(AddressFamily::Ipv4).await;
    third.send_to(b"injection", addr).await.unwrap();
    sa.send_to(&[7; server::MAX_DATAGRAM + 1], addr)
        .await
        .unwrap();
    let payload = [0x80; 1200]; // Server does not need to recognize QUIC to copy it.
    sa.send_to(&payload, addr).await.unwrap();
    sa2.send_to(b"other-peer", addr).await.unwrap();
    let mut buffer = [0; 4096];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), sb.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], payload);
    assert_eq!(from, addr);
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sc.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], b"other-peer");
    assert!(
        tokio::time::timeout(Duration::from_millis(80), sb.recv_from(&mut buffer))
            .await
            .is_err()
    );
    sb.send_to(b"return", addr).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sa.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], b"return");
    task.abort();
    task.await.unwrap_err();
}

async fn quic_pair(family_a: AddressFamily, family_b: AddressFamily, selector_initiates: bool) {
    let s1 = socket(family_a).await;
    let addr1 = s1.local_addr().unwrap();
    let mut listeners = vec![s1];
    let addr2 = if family_a == family_b {
        addr1
    } else {
        let s2 = socket(family_b).await;
        let addr = s2.local_addr().unwrap();
        listeners.push(s2);
        addr
    };
    let admission = server::Admission::new(server::RelayServerConfig::default()).unwrap();
    let task = tokio::spawn(server::run_listeners(listeners, admission.clone()));
    let mut a = Identity::generate();
    let mut b = Identity::generate();
    if (a.node_id() < b.node_id()) != selector_initiates {
        std::mem::swap(&mut a, &mut b);
    }
    let token = PunchToken::random();
    assert!(admission.issue(token, a.node_id(), b.node_id()));
    let b2 = b.clone();
    let a_id = a.node_id();
    let waiter = tokio::spawn(async move {
        client::prepare(&b2, a_id, token, addr2)
            .await
            .unwrap()
            .wait_for_selection()
            .await
            .unwrap()
    });
    let prepared = client::prepare(&a, b.node_id(), token, addr1)
        .await
        .unwrap();
    let mut ga = prepared.finish().await.unwrap();
    let mut gb = waiter.await.unwrap();
    let pool_a = client::EndpointPool::default();
    let pool_b = client::EndpointPool::default();
    ga.retain_relay_endpoint(&pool_a).unwrap();
    gb.retain_relay_endpoint(&pool_b).unwrap();
    assert!(pool_a.is_relay(ga.connection()));
    assert!(pool_b.is_relay(gb.connection()));
    assert_eq!(ga.connection().remote_address(), addr1);
    assert_eq!(gb.connection().remote_address(), addr2);
    assert_eq!(
        ChannelBinding::from_connection(ga.connection()).unwrap(),
        ChannelBinding::from_connection(gb.connection()).unwrap()
    );
    // A normal encrypted application stream, independent of deterministic QUIC role.
    let (mut tx, _rx) = ga.connection().open_bi().await.unwrap();
    tx.write_all(b"end-to-end-only").await.unwrap();
    tx.finish().unwrap();
    let (_tx, mut rx) = gb.connection().accept_bi().await.unwrap();
    assert_eq!(rx.read_to_end(64).await.unwrap(), b"end-to-end-only");
    pool_a.close();
    pool_b.close();
    drop((ga, gb));
    for endpoint in pool_a.endpoints().into_iter().chain(pool_b.endpoints()) {
        endpoint.wait_idle().await;
    }
    task.abort();
    task.await.unwrap_err();
}
#[tokio::test]
async fn relay_real_quic_ed25519_tls_ipv4_loopback() {
    quic_pair(AddressFamily::Ipv4, AddressFamily::Ipv4, true).await;
    quic_pair(AddressFamily::Ipv4, AddressFamily::Ipv4, false).await;
}
#[tokio::test]
async fn relay_real_quic_ed25519_tls_ipv6_loopback() {
    if crate::net::family::ipv6_test_available() {
        quic_pair(AddressFamily::Ipv6, AddressFamily::Ipv6, false).await;
    }
}
#[tokio::test]
async fn relay_real_quic_native_cross_family_loopback() {
    if crate::net::family::ipv6_test_available() {
        quic_pair(AddressFamily::Ipv4, AddressFamily::Ipv6, true).await;
    }
}
#[tokio::test]
async fn relay_wrong_expected_quic_identity_fails_after_valid_udp_admission() {
    let listener = socket(AddressFamily::Ipv4).await;
    let addr = listener.local_addr().unwrap();
    let admission = server::Admission::new(server::RelayServerConfig::default()).unwrap();
    let task = tokio::spawn(server::run(listener, admission.clone()));
    let (mut a, mut b) = (Identity::generate(), Identity::generate());
    if a.node_id() > b.node_id() {
        std::mem::swap(&mut a, &mut b);
    }
    let token = PunchToken::random();
    assert!(admission.issue(token, a.node_id(), b.node_id()));
    let a_id = a.node_id();
    let b_id = b.node_id();
    let malicious = tokio::spawn(async move {
        let endpoint = client::bind(&b, a_id, token, addr).await.unwrap();
        let incoming = endpoint.accept().await.unwrap();
        let _ = crate::net::race::PreparedTransport::accept(incoming, &Identity::generate(), a_id)
            .await;
    });
    assert!(client::prepare(&a, b_id, token, addr).await.is_err());
    malicious.abort();
    let _ = malicious.await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn relay_blackhole_admission_has_bounded_failure() {
    let blackhole = socket(AddressFamily::Ipv4).await;
    let a = Identity::generate();
    let started = tokio::time::Instant::now();
    assert!(
        client::prepare_any(
            a,
            Identity::generate().node_id(),
            PunchToken::random(),
            blackhole.local_addr().unwrap().to_string(),
            NetworkFamilies::Ipv4Only
        )
        .await
        .is_err()
    );
    assert!(started.elapsed() < super::RELAY_BIND_TIMEOUT + Duration::from_secs(2));
}
#[test]
fn relay_optional_server_validation_does_not_resolve_dns() {
    for spec in ["127.0.0.1:7001", "[::1]:7001", "relay.example.invalid:7001"] {
        client::validate_server_spec(spec).unwrap();
    }
    for spec in [
        "",
        "http://relay:7001",
        "[::ffff:127.0.0.1]:7001",
        "[fe80::1]:7001",
        "relay:0",
        "relay:7001 ",
        "0.0.0.0:7001",
    ] {
        assert!(client::validate_server_spec(spec).is_err(), "{spec}");
    }
}

pub(crate) async fn signaling_fixture() -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<crate::Result<()>>,
) {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let reserve = socket(AddressFamily::Ipv4).await;
    let relay = reserve.local_addr().unwrap();
    drop(reserve);
    let config = crate::discovery::signal::SignalServerConfig {
        relay: Some(server::RelayServerConfig {
            listen: vec![relay],
            ..Default::default()
        }),
        ..crate::discovery::signal::SignalServerConfig::for_tests()
    };
    let task = tokio::spawn(crate::discovery::signal::run_signal_server_on_with(
        tcp, config,
    ));
    (addr, relay, task)
}

#[tokio::test]
async fn relay_and_direct_simultaneous_ready_commit_only_one_authenticated_handler() {
    use crate::net::race::{ConnectionGuard, PreparedTransport};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let listener = socket(AddressFamily::Ipv4).await;
    let addr = listener.local_addr().unwrap();
    let admission = server::Admission::new(server::RelayServerConfig::default()).unwrap();
    let relay_task = tokio::spawn(server::run(listener, admission.clone()));
    let mut a = Identity::generate();
    let mut b = Identity::generate();
    if a.node_id() > b.node_id() {
        std::mem::swap(&mut a, &mut b);
    }
    let token = PunchToken::random();
    assert!(admission.issue(token, a.node_id(), b.node_id()));
    let ea = crate::transport::quic::endpoint_from_socket(
        bind_udp(AddressFamily::Ipv4.loopback(0)).unwrap(),
    )
    .unwrap();
    let eb = crate::transport::quic::endpoint_from_socket(
        bind_udp(AddressFamily::Ipv4.loopback(0)).unwrap(),
    )
    .unwrap();
    let direct = eb.local_addr().unwrap();
    let mut waiters = tokio::task::JoinSet::<crate::Result<ConnectionGuard>>::new();
    let a_id = a.node_id();
    let b_direct = b.clone();
    let accept = eb.clone();
    waiters.spawn(async move {
        PreparedTransport::accept(accept.accept().await.unwrap(), &b_direct, a_id)
            .await?
            .wait_for_selection()
            .await
    });
    let b_relay = b.clone();
    waiters.spawn(async move {
        client::prepare(&b_relay, a_id, token, addr)
            .await?
            .wait_for_selection()
            .await
    });
    let count = Arc::new(AtomicUsize::new(0));
    let commits = count.clone();
    let handlers = tokio::spawn(async move {
        let mut winners = Vec::new();
        while let Some(result) = waiters.join_next().await {
            if let Ok(Ok(guard)) = result {
                commits.fetch_add(1, Ordering::SeqCst);
                winners.push(guard);
            }
        }
        // Retain the winning connection until client cleanup closes it.
        for guard in &winners {
            let _ = guard.connection().closed().await;
        }
    });
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut candidates = tokio::task::JoinSet::new();
    let a_direct = a.clone();
    let endpoint = ea.clone();
    let peer = b.node_id();
    let gate = barrier.clone();
    candidates.spawn(async move {
        let prepared = PreparedTransport::dial(&endpoint, direct, &a_direct, peer).await?;
        gate.wait().await;
        Ok(prepared)
    });
    candidates.spawn(async move {
        let prepared = client::prepare(&a, peer, token, addr).await?;
        barrier.wait().await;
        Ok(prepared)
    });
    let mut winner = tokio::time::timeout(
        Duration::from_secs(5),
        crate::net::race::finish_prepared_guard(candidates),
    )
    .await
    .unwrap()
    .unwrap();
    let pool = client::EndpointPool::default();
    winner.retain_relay_endpoint(&pool).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while count.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(winner);
    pool.close();
    ea.close(0u32.into(), b"done");
    eb.close(0u32.into(), b"done");
    handlers.await.unwrap();
    ea.wait_idle().await;
    eb.wait_idle().await;
    relay_task.abort();
    let _ = relay_task.await;
}
