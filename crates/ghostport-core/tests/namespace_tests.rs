//! Forward-link round trip across two *real* Linux network namespaces,
//! connected by a real veth pair (via `gateflow`), instead of one
//! process talking to itself over loopback like `daemon_roundtrip.rs`
//! does.
//!
//! Same "nothing mocked" philosophy that file is already built on —
//! this just closes the one thing it can't reach: the control/data
//! channels crossing a real network boundary, not two tasks in the same
//! process sharing one loopback. `server::run`/`client::run` themselves
//! are completely unmodified; only which addresses they're told to bind/
//! dial changes.
//!
//! Reverse mode is covered too, in a separate test below — the mirror
//! of the forward one, since reverse mode inverts who dials whom.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateflow::veth::VethEnd;
use gateflow::Sandbox;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ghostport_core::config::{Config, LinkConfig, LinkMode, Role};
use ghostport_core::stats::SharedState;
use ghostport_core::{client, keys, server};

const CONTROL_PORT: u16 = 17800;
const DATA_PORT: u16 = 17801;
const FORWARD_TARGET_PORT: u16 = 17802;
const FORWARD_LOCAL_PORT: u16 = 17803;
const REVERSE_EXTERNAL_PORT: u16 = 17804;
const REVERSE_TARGET_PORT: u16 = 17805;

async fn connect_with_retry(addr: &str, timeout: Duration) -> Option<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(s) = TcpStream::connect(addr).await {
            return Some(s);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn scratch_socket_path(role: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ghostport-netns-test-{role}-{}.sock",
        std::process::id()
    ))
}

fn gateflow_peer(public_key: Vec<u8>) -> ghostport_core::peermatch::ResolvedPeer {
    ghostport_core::peermatch::ResolvedPeer {
        name: "client".to_string(),
        public_key,
        links: ["fwd", "rev"].map(String::from).into(),
    }
}

#[test]
fn forward_link_round_trips_across_real_network_namespaces() {
    let server_kp = keys::generate();
    let client_kp = keys::generate();
    let server_pub = server_kp.public.clone();
    let client_pub = client_kp.public.clone();

    let (a_code, b_code) = Sandbox::paired()
        .enter(
            // Side A: the server, plus the "real destination" its forward
            // link relays to — both live in this namespace, on its own
            // loopback, same as a real deployment would have them.
            move |end: VethEnd| {
                let runtime = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return 90,
                };
                runtime.block_on(async move {
                    let listener =
                        match TcpListener::bind(format!("127.0.0.1:{FORWARD_TARGET_PORT}")).await {
                            Ok(l) => l,
                            Err(_) => return 91,
                        };
                    tokio::spawn(async move {
                        loop {
                            let Ok((mut sock, _)) = listener.accept().await else {
                                return;
                            };
                            tokio::spawn(async move {
                                let (mut r, mut w) = sock.split();
                                let _ = tokio::io::copy(&mut r, &mut w).await;
                            });
                        }
                    });

                    let server_config = Config {
                        role: Role::Server,
                        private_key_path: PathBuf::new(),
                        peer_public_key: None,
                        peers: vec![ghostport_core::config::PeerConfig {
                            name: "client".to_string(),
                            public_key: keys::encode_public_key(&client_pub),
                            links: vec!["fwd".to_string()],
                        }],
                        listen_control: Some(format!("{}:{CONTROL_PORT}", end.address)),
                        listen_data: Some(format!("{}:{DATA_PORT}", end.address)),
                        server_control_addr: None,
                        server_data_addr: None,
                        links: vec![LinkConfig {
                            id: "fwd".to_string(),
                            mode: LinkMode::Forward,
                            listen: None,
                            target: Some(format!("127.0.0.1:{FORWARD_TARGET_PORT}")),
                        }],
                    };
                    if !server_config.validate().is_empty() {
                        return 92;
                    }

                    let state = Arc::new(SharedState::new(&server_config));
                    tokio::spawn(server::run(server::Context {
                        config: Arc::new(server_config),
                        private_key: Arc::new(server_kp.private),
                        peers: Arc::new(vec![gateflow_peer(client_pub)]),
                        state: state.clone(),
                        socket_path: scratch_socket_path("server"),
                    }));

                    // Block on the client's real completion signal instead
                    // of guessing how long its round trip takes with a
                    // fixed sleep. wait_for_peer does a blocking sleep-poll
                    // loop internally, so it runs on a blocking thread
                    // rather than tying up the async runtime.
                    let signaled = match tokio::task::spawn_blocking(move || {
                        end.wait_for_peer(Duration::from_secs(5))
                    })
                    .await
                    {
                        Ok(Ok(signaled)) => signaled,
                        _ => return 102,
                    };
                    if !signaled {
                        return 103;
                    }

                    if state.links["fwd"].total_streams.load(Ordering::Relaxed) != 1 {
                        return 93;
                    }
                    if state.links["fwd"].bytes_forward.load(Ordering::Relaxed) == 0 {
                        return 94;
                    }

                    0
                })
            },
            // Side B: the client, plus the local app-facing port a real
            // user would connect to.
            move |end: VethEnd| {
                let runtime = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return 90,
                };
                runtime.block_on(async move {
                    let client_config = Config {
                        role: Role::Client,
                        private_key_path: PathBuf::new(),
                        peer_public_key: Some(keys::encode_public_key(&server_pub)),
                        peers: vec![],
                        listen_control: None,
                        listen_data: None,
                        server_control_addr: Some(format!("{}:{CONTROL_PORT}", end.peer_address)),
                        server_data_addr: Some(format!("{}:{DATA_PORT}", end.peer_address)),
                        links: vec![LinkConfig {
                            id: "fwd".to_string(),
                            mode: LinkMode::Forward,
                            listen: Some(format!("127.0.0.1:{FORWARD_LOCAL_PORT}")),
                            target: None,
                        }],
                    };
                    if !client_config.validate().is_empty() {
                        return 95;
                    }

                    let state = Arc::new(SharedState::new(&client_config));
                    tokio::spawn(client::run(client::Context {
                        config: Arc::new(client_config),
                        private_key: Arc::new(client_kp.private),
                        peer_public_key: Arc::new(server_pub),
                        state: state.clone(),
                        socket_path: scratch_socket_path("client"),
                    }));

                    let Some(mut sock) = connect_with_retry(
                        &format!("127.0.0.1:{FORWARD_LOCAL_PORT}"),
                        Duration::from_secs(5),
                    )
                    .await
                    else {
                        return 96;
                    };

                    let payload = b"hello-across-real-network-namespaces";
                    if sock.write_all(payload).await.is_err() {
                        return 97;
                    }
                    if sock.shutdown().await.is_err() {
                        return 98;
                    }
                    let mut received = Vec::new();
                    if sock.read_to_end(&mut received).await.is_err() {
                        return 99;
                    }
                    if received != payload {
                        return 100;
                    }

                    if state.links["fwd"].total_streams.load(Ordering::Relaxed) != 1 {
                        return 101;
                    }

                    // Tell the server side we're done so it can check its
                    // own stats immediately instead of guessing with a
                    // fixed sleep.
                    if end.signal_done().is_err() {
                        return 104;
                    }

                    0
                })
            },
        )
        .expect("Sandbox::paired().enter should run to completion");

    assert_eq!(a_code, 0, "server side failed (code {a_code})");
    assert_eq!(b_code, 0, "client side failed (code {b_code})");
}

/// The mirror of the forward-mode test above — reverse mode inverts
/// who dials whom, so the roles swap too. Side A (the server) does the
/// *active* work this time: it dials its own external-facing reverse
/// listener directly (standing in for "an external user connecting
/// in"), which the server relays to the client via the control
/// channel's `OpenStream` signal — the one real-namespace path the
/// forward test never touches.
#[test]
fn reverse_link_round_trips_across_real_network_namespaces() {
    let server_kp = keys::generate();
    let client_kp = keys::generate();
    let server_pub = server_kp.public.clone();
    let client_pub = client_kp.public.clone();

    let (a_code, b_code) = Sandbox::paired()
        .enter(
            // Side A: the server, plus the "external user" that dials
            // its own reverse-link listen port once the client side is
            // ready to fulfill it.
            move |end: VethEnd| {
                let end = Arc::new(end);
                let runtime = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return 60,
                };
                runtime.block_on(async move {
                    let server_config = Config {
                        role: Role::Server,
                        private_key_path: PathBuf::new(),
                        peer_public_key: None,
                        peers: vec![ghostport_core::config::PeerConfig {
                            name: "client".to_string(),
                            public_key: keys::encode_public_key(&client_pub),
                            links: vec!["rev".to_string()],
                        }],
                        listen_control: Some(format!("{}:{CONTROL_PORT}", end.address)),
                        listen_data: Some(format!("{}:{DATA_PORT}", end.address)),
                        server_control_addr: None,
                        server_data_addr: None,
                        links: vec![LinkConfig {
                            id: "rev".to_string(),
                            mode: LinkMode::Reverse,
                            listen: Some(format!("{}:{REVERSE_EXTERNAL_PORT}", end.address)),
                            target: None,
                        }],
                    };
                    if !server_config.validate().is_empty() {
                        return 61;
                    }

                    let state = Arc::new(SharedState::new(&server_config));
                    tokio::spawn(server::run(server::Context {
                        config: Arc::new(server_config),
                        private_key: Arc::new(server_kp.private),
                        peers: Arc::new(vec![gateflow_peer(client_pub)]),
                        state: state.clone(),
                        socket_path: scratch_socket_path("rev-server"),
                    }));

                    // Wait for the client side to confirm its own echo
                    // target is bound and client::run is spawned before
                    // dialing in -- handle_open_stream on the client
                    // side has no retry if its target isn't listening
                    // yet, so this ordering is load-bearing, not just
                    // a nicety.
                    let wait_end = end.clone();
                    let signaled = match tokio::task::spawn_blocking(move || {
                        wait_end.wait_for_peer(Duration::from_secs(5))
                    })
                    .await
                    {
                        Ok(Ok(signaled)) => signaled,
                        _ => return 62,
                    };
                    if !signaled {
                        return 63;
                    }

                    let Some(mut sock) = connect_with_retry(
                        &format!("{}:{REVERSE_EXTERNAL_PORT}", end.address),
                        Duration::from_secs(5),
                    )
                    .await
                    else {
                        return 64;
                    };

                    let payload = b"hello-reverse-across-real-network-namespaces";
                    if sock.write_all(payload).await.is_err() {
                        return 65;
                    }
                    if sock.shutdown().await.is_err() {
                        return 66;
                    }
                    let mut received = Vec::new();
                    if sock.read_to_end(&mut received).await.is_err() {
                        return 67;
                    }
                    if received != payload {
                        return 68;
                    }

                    if state.links["rev"].total_streams.load(Ordering::Relaxed) != 1 {
                        return 69;
                    }
                    if state.links["rev"].bytes_forward.load(Ordering::Relaxed) == 0 {
                        return 70;
                    }

                    // Let the client know it's safe to return -- its
                    // control connection needs to stay alive until this
                    // whole round trip is done.
                    if end.signal_done().is_err() {
                        return 71;
                    }

                    0
                })
            },
            // Side B: the client, plus the "local" echo service the
            // reverse link exposes -- this is what moves for reverse
            // mode, the mirror of where the target lived for forward.
            move |end: VethEnd| {
                let runtime = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return 80,
                };
                runtime.block_on(async move {
                    let listener =
                        match TcpListener::bind(format!("127.0.0.1:{REVERSE_TARGET_PORT}")).await {
                            Ok(l) => l,
                            Err(_) => return 81,
                        };
                    tokio::spawn(async move {
                        loop {
                            let Ok((mut sock, _)) = listener.accept().await else {
                                return;
                            };
                            tokio::spawn(async move {
                                let (mut r, mut w) = sock.split();
                                let _ = tokio::io::copy(&mut r, &mut w).await;
                            });
                        }
                    });

                    let client_config = Config {
                        role: Role::Client,
                        private_key_path: PathBuf::new(),
                        peer_public_key: Some(keys::encode_public_key(&server_pub)),
                        peers: vec![],
                        listen_control: None,
                        listen_data: None,
                        server_control_addr: Some(format!("{}:{CONTROL_PORT}", end.peer_address)),
                        server_data_addr: Some(format!("{}:{DATA_PORT}", end.peer_address)),
                        links: vec![LinkConfig {
                            id: "rev".to_string(),
                            mode: LinkMode::Reverse,
                            listen: None,
                            target: Some(format!("127.0.0.1:{REVERSE_TARGET_PORT}")),
                        }],
                    };
                    if !client_config.validate().is_empty() {
                        return 82;
                    }

                    let state = Arc::new(SharedState::new(&client_config));
                    tokio::spawn(client::run(client::Context {
                        config: Arc::new(client_config),
                        private_key: Arc::new(client_kp.private),
                        peer_public_key: Arc::new(server_pub),
                        state,
                        socket_path: scratch_socket_path("rev-client"),
                    }));

                    // Echo target bound, client::run spawned -- safe for
                    // the server side to dial in now.
                    if end.signal_done().is_err() {
                        return 83;
                    }

                    // Block until the server side confirms its whole
                    // round trip (including its own stats check) is
                    // done, rather than tearing down (and taking the
                    // control connection with it) while that's still
                    // in flight.
                    let signaled = match tokio::task::spawn_blocking(move || {
                        end.wait_for_peer(Duration::from_secs(5))
                    })
                    .await
                    {
                        Ok(Ok(signaled)) => signaled,
                        _ => return 84,
                    };
                    if !signaled {
                        return 85;
                    }

                    0
                })
            },
        )
        .expect("Sandbox::paired().enter should run to completion");

    assert_eq!(a_code, 0, "server side failed (code {a_code})");
    assert_eq!(b_code, 0, "client side failed (code {b_code})");
}
