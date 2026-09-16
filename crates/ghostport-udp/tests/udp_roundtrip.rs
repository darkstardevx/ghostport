//! End-to-end tests against real running UDP server+client role tasks
//! (`ghostport_udp::server::run`/`client::run`), talking over real
//! loopback UDP sockets with real `Noise_KK` handshakes — not mocked
//! at any layer, same "nothing mocked" philosophy as
//! `ghostport-core`'s own `daemon_roundtrip.rs`.

use ghostport_core::config::{Config, LinkConfig, LinkMode, PeerConfig, Role, Transport};
use ghostport_core::{keys, peermatch};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Bounces back every datagram it receives — stands in for "the real
/// UDP destination" the server's forward link relays to.
async fn spawn_udp_echo(addr: String) {
    let socket = UdpSocket::bind(&addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let _ = socket.send_to(&buf[..n], src).await;
        }
    });
}

struct Ports {
    control: u16,
    data: u16,
    udp_channel: u16,
    local_listen: u16,
    target: u16,
}

fn alloc_ports() -> Ports {
    Ports {
        control: free_port(),
        data: free_port(),
        udp_channel: free_port(),
        local_listen: free_port(),
        target: free_port(),
    }
}

/// Only `allowed_client_pub` is put in the server's `peers` list — the
/// caller decides whether that matches the keypair that actually
/// dials in, so this same builder covers both the happy path and the
/// wrong-key rejection test.
fn server_config(ports: &Ports, allowed_client_pub_b64: String) -> Config {
    Config {
        role: Role::Server,
        private_key_path: PathBuf::new(),
        peer_public_key: None,
        peers: vec![PeerConfig {
            name: "client".to_string(),
            public_key: allowed_client_pub_b64,
            links: vec!["dns".to_string()],
        }],
        listen_control: Some(format!("127.0.0.1:{}", ports.control)),
        listen_data: Some(format!("127.0.0.1:{}", ports.data)),
        listen_udp: Some(format!("127.0.0.1:{}", ports.udp_channel)),
        server_control_addr: None,
        server_data_addr: None,
        server_udp_addr: None,
        links: vec![LinkConfig {
            id: "dns".to_string(),
            mode: LinkMode::Forward,
            transport: Transport::Udp,
            listen: None,
            target: Some(format!("127.0.0.1:{}", ports.target)),
        }],
    }
}

fn client_config(ports: &Ports, server_pub_b64: String) -> Config {
    Config {
        role: Role::Client,
        private_key_path: PathBuf::new(),
        peer_public_key: Some(server_pub_b64),
        peers: vec![],
        listen_control: None,
        listen_data: None,
        listen_udp: None,
        server_control_addr: Some(format!("127.0.0.1:{}", ports.control)),
        server_data_addr: Some(format!("127.0.0.1:{}", ports.data)),
        server_udp_addr: Some(format!("127.0.0.1:{}", ports.udp_channel)),
        links: vec![LinkConfig {
            id: "dns".to_string(),
            mode: LinkMode::Forward,
            transport: Transport::Udp,
            listen: Some(format!("127.0.0.1:{}", ports.local_listen)),
            target: None,
        }],
    }
}

#[tokio::test]
async fn forward_udp_link_round_trips_end_to_end() {
    let server_kp = keys::generate();
    let client_kp = keys::generate();
    let ports = alloc_ports();

    spawn_udp_echo(format!("127.0.0.1:{}", ports.target)).await;

    let server_cfg = server_config(&ports, keys::encode_public_key(&client_kp.public));
    assert!(
        server_cfg.validate().is_empty(),
        "{:?}",
        server_cfg.validate()
    );
    let client_cfg = client_config(&ports, keys::encode_public_key(&server_kp.public));
    assert!(
        client_cfg.validate().is_empty(),
        "{:?}",
        client_cfg.validate()
    );

    tokio::spawn(ghostport_udp::server::run(ghostport_udp::server::Context {
        config: Arc::new(server_cfg),
        private_key: Arc::new(server_kp.private),
        peers: Arc::new(vec![peermatch::ResolvedPeer {
            name: "client".to_string(),
            public_key: client_kp.public.clone(),
            links: ["dns"].map(String::from).into(),
        }]),
    }));
    tokio::spawn(ghostport_udp::client::run(ghostport_udp::client::Context {
        config: Arc::new(client_cfg),
        private_key: Arc::new(client_kp.private),
        peer_public_key: Arc::new(server_kp.public.clone()),
    }));

    // Real UDP has no connect()-style backpressure to poll/retry
    // against the way TCP's connect_with_retry pattern can — a short
    // settle delay before the first send is the simplest real wait.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let local_app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    local_app
        .connect(format!("127.0.0.1:{}", ports.local_listen))
        .await
        .unwrap();
    local_app.send(b"hello over udp").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), local_app.recv(&mut buf))
        .await
        .expect("timed out waiting for the round-tripped reply")
        .unwrap();
    assert_eq!(&buf[..n], b"hello over udp");
}

#[tokio::test]
async fn wrong_peer_key_never_completes_the_handshake() {
    let server_kp = keys::generate();
    let real_client_kp = keys::generate();
    let impostor_kp = keys::generate(); // never added to the server's peers
    let ports = alloc_ports();

    spawn_udp_echo(format!("127.0.0.1:{}", ports.target)).await;

    // Server only allow-lists the real client's key.
    let server_cfg = server_config(&ports, keys::encode_public_key(&real_client_kp.public));
    assert!(
        server_cfg.validate().is_empty(),
        "{:?}",
        server_cfg.validate()
    );
    // The impostor's own client config claims to trust the real server,
    // but dials in with its own (unlisted) keypair.
    let client_cfg = client_config(&ports, keys::encode_public_key(&server_kp.public));
    assert!(
        client_cfg.validate().is_empty(),
        "{:?}",
        client_cfg.validate()
    );

    tokio::spawn(ghostport_udp::server::run(ghostport_udp::server::Context {
        config: Arc::new(server_cfg),
        private_key: Arc::new(server_kp.private),
        peers: Arc::new(vec![peermatch::ResolvedPeer {
            name: "client".to_string(),
            public_key: real_client_kp.public.clone(),
            links: ["dns"].map(String::from).into(),
        }]),
    }));
    tokio::spawn(ghostport_udp::client::run(ghostport_udp::client::Context {
        config: Arc::new(client_cfg),
        private_key: Arc::new(impostor_kp.private),
        peer_public_key: Arc::new(server_kp.public.clone()),
    }));

    tokio::time::sleep(Duration::from_millis(200)).await;

    let local_app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    local_app
        .connect(format!("127.0.0.1:{}", ports.local_listen))
        .await
        .unwrap();
    local_app.send(b"should never arrive").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(Duration::from_millis(800), local_app.recv(&mut buf)).await;
    assert!(
        result.is_err(),
        "an unrecognized key must never get a round-tripped reply"
    );
}
