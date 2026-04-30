#![cfg(feature = "iroh")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use enlace::{
    Config, IrohConfig, IrohEndpointAddr, IrohRelayMode, Namespace, PeerCard, PeerConfig,
    PeerIdentity, PeerNamespace, TransportKind, TrustedPeer,
};

fn iroh_config(peers: Vec<IrohEndpointAddr>) -> IrohConfig {
    IrohConfig {
        relay_mode: IrohRelayMode::Disabled,
        bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
        peers,
        ..IrohConfig::default()
    }
}

fn config(peers: Vec<IrohEndpointAddr>) -> Config {
    Config {
        iroh: Some(iroh_config(peers)),
        ..Config::default()
    }
}

fn peer_config(peers: Vec<IrohEndpointAddr>) -> PeerConfig {
    PeerConfig {
        iroh: Some(iroh_config(peers)),
        ..PeerConfig::default()
    }
}

#[tokio::test]
async fn iroh_mailbox_delivers_between_loopback_namespaces() {
    let left = Namespace::open(&[3; 32], config(Vec::new())).await.unwrap();
    let peer = left.iroh().unwrap().endpoint_addr();
    assert!(!peer.direct_addrs.is_empty());
    let right = Namespace::open(&[3; 32], config(vec![peer])).await.unwrap();

    let inbox = left.mailbox("cmd").unwrap();
    let recv = tokio::spawn(async move { inbox.recv().await.unwrap() });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let report = right.mailbox("cmd").unwrap().send(b"ping").await.unwrap();
    assert_eq!(report.delivered, vec![TransportKind::Iroh]);

    let message = tokio::time::timeout(Duration::from_secs(5), recv)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message.payload, b"ping");
    assert_eq!(message.via, TransportKind::Iroh);
}

#[tokio::test]
async fn peer_iroh_mailbox_delivers_between_loopback_namespaces() {
    let left_identity = PeerIdentity::generate();
    let right_identity = PeerIdentity::generate();
    let left_card = left_identity.card();
    let right_card = right_identity.card();
    let left = PeerNamespace::open(
        left_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(right_card.clone()).unwrap()],
            ..peer_config(Vec::new())
        },
    )
    .await
    .unwrap();
    let peer = left.iroh_endpoint_addr().unwrap();
    assert!(!peer.direct_addrs.is_empty());
    let right = PeerNamespace::open(right_identity, peer_config(vec![peer]))
        .await
        .unwrap();

    let inbox = left.mailbox("cmd").unwrap();
    let recv = inbox.recv();
    tokio::pin!(recv);

    tokio::select! {
        result = &mut recv => panic!("recv completed before send: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
    let report = right
        .mailbox("cmd")
        .unwrap()
        .send_to_peers(&[left_card], b"ping")
        .await
        .unwrap();
    assert_eq!(report.delivered, vec![TransportKind::Iroh]);

    let message = tokio::time::timeout(Duration::from_secs(5), recv)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message.sender, right.peer_id());
    assert_eq!(message.signed_by, right_card.signing_key);
    assert_eq!(message.payload, b"ping");
    assert_eq!(message.via, TransportKind::Iroh);
}

#[tokio::test]
async fn peer_iroh_runtime_trust_adds_endpoint_hint() {
    let left_identity = PeerIdentity::generate();
    let right_identity = PeerIdentity::generate();
    let left_card = left_identity.card();
    let right_card = right_identity.card();
    let left = PeerNamespace::open(left_identity, peer_config(Vec::new()))
        .await
        .unwrap();
    let left_endpoint = left.iroh_endpoint_addr().unwrap();
    let right = PeerNamespace::open(right_identity, peer_config(vec![left_endpoint]))
        .await
        .unwrap();
    let right_endpoint = right.iroh_endpoint_addr().unwrap();
    let right_peer_id = right.peer_id();
    let right_card = PeerCard {
        iroh_endpoint: Some(right_endpoint),
        ..right_card
    };

    left.trust_peer(TrustedPeer::try_from_card(right_card.clone()).unwrap())
        .unwrap();

    let inbox = left.mailbox("runtime").unwrap();
    let recv = inbox.recv();
    tokio::pin!(recv);

    tokio::select! {
        result = &mut recv => panic!("recv completed before send: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
    let report = right
        .mailbox("runtime")
        .unwrap()
        .send_to_peers(&[left_card], b"runtime")
        .await
        .unwrap();
    assert_eq!(report.delivered, vec![TransportKind::Iroh]);

    let message = tokio::time::timeout(Duration::from_secs(5), recv)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message.sender, right_peer_id);
    assert_eq!(message.payload, b"runtime");
    assert_eq!(message.via, TransportKind::Iroh);
}

#[tokio::test]
async fn iroh_slot_watch_delivers_latest_loopback_value() {
    let left = Namespace::open(&[4; 32], config(Vec::new())).await.unwrap();
    let peer = left.iroh().unwrap().endpoint_addr();
    assert!(!peer.direct_addrs.is_empty());
    let right = Namespace::open(&[4; 32], config(vec![peer])).await.unwrap();

    let mut watch = left.slot("relay").unwrap().watch();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let report = right.slot("relay").unwrap().put(b"cfg-v1").await.unwrap();
    assert_eq!(report.stored, vec![TransportKind::Iroh]);

    let value = tokio::time::timeout(Duration::from_secs(5), watch.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value.version, 1);
    assert_eq!(value.payload, b"cfg-v1");
    assert_eq!(value.via, TransportKind::Iroh);
}
