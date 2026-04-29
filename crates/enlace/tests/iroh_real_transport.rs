#![cfg(feature = "iroh")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use enlace::{
    Config, InMemoryStateStore, IrohConfig, IrohEndpointAddr, IrohRelayMode, Namespace,
    TransportKind,
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
        state: Some(Arc::new(InMemoryStateStore::new())),
        ..Config::default()
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
