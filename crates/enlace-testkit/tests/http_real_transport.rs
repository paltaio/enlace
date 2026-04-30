use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use enlace::{
    Config, HttpConfig, IrohConfig, IrohEndpointAddr, IrohRelayMode, Namespace, TransportKind,
};
use enlace_relay::{RelayConfig, build_router};
use tokio::task::JoinHandle;

struct RelayProcess {
    base_url: String,
    task: JoinHandle<()>,
}

impl RelayProcess {
    async fn spawn() -> Self {
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("ephemeral listener binds");
        listener
            .set_nonblocking(true)
            .expect("listener switches to nonblocking");
        let addr = listener.local_addr().expect("listener has local addr");
        let app = build_router(RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .await
            .expect("relay router builds");
        let server = axum_server::from_tcp(listener)
            .expect("server accepts listener")
            .serve(app.into_make_service());
        let task = tokio::spawn(async move {
            let _ = server.await;
        });
        let relay = Self {
            base_url: format!("http://{addr}"),
            task,
        };
        relay.wait_ready().await;
        relay
    }

    async fn wait_ready(&self) {
        let client = reqwest::Client::new();
        for _ in 0..20 {
            if client
                .get(format!(
                    "{}/m/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    self.base_url
                ))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("relay did not become ready");
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn http_config(base_url: &str) -> Config {
    Config {
        http: Some(HttpConfig::new(base_url.parse().expect("relay URL parses"))),
        ..Config::default()
    }
}

fn iroh_config(peers: Vec<IrohEndpointAddr>) -> IrohConfig {
    IrohConfig {
        relay_mode: IrohRelayMode::Disabled,
        bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
        peers,
        ..IrohConfig::default()
    }
}

fn http_iroh_config(base_url: &str, peers: Vec<IrohEndpointAddr>) -> Config {
    Config {
        http: Some(HttpConfig::new(base_url.parse().expect("relay URL parses"))),
        iroh: Some(iroh_config(peers)),
        ..Config::default()
    }
}

#[tokio::test]
async fn namespaces_exchange_mailbox_and_slot_over_http() {
    let relay = RelayProcess::spawn().await;
    let seed = [0x55; 32];
    let sender = Namespace::open(&seed, http_config(&relay.base_url))
        .await
        .expect("sender opens");
    let receiver = Namespace::open(&seed, http_config(&relay.base_url))
        .await
        .expect("receiver opens");

    let sender_mailbox = sender.mailbox("ops/events").expect("mailbox opens");
    let receiver_mailbox = receiver.mailbox("ops/events").expect("mailbox opens");
    sender_mailbox
        .send(b"hello-http")
        .await
        .expect("mailbox send succeeds");
    let message = receiver_mailbox
        .recv()
        .await
        .expect("mailbox recv succeeds");
    assert_eq!(message.payload, b"hello-http");
    assert_eq!(message.via, TransportKind::Http);

    let sender_slot = sender.slot("state/current").expect("slot opens");
    let receiver_slot = receiver.slot("state/current").expect("slot opens");
    let put = sender_slot
        .put(b"slot-http")
        .await
        .expect("slot put succeeds");
    assert_eq!(put.stored, vec![TransportKind::Http]);

    let value = receiver_slot
        .get()
        .await
        .expect("slot get succeeds")
        .expect("slot value exists");
    assert_eq!(value.payload, b"slot-http");
    assert_eq!(value.version, put.version);
    assert_eq!(value.via, TransportKind::Http);
}

#[tokio::test]
async fn namespaces_exchange_mailbox_and_slot_over_http_and_iroh() {
    let relay = RelayProcess::spawn().await;
    let seed = [0x66; 32];
    let receiver = Namespace::open(&seed, http_iroh_config(&relay.base_url, Vec::new()))
        .await
        .expect("receiver opens");
    let peer = receiver.iroh().expect("receiver has iroh").endpoint_addr();
    assert!(!peer.direct_addrs.is_empty());
    let sender = Namespace::open(&seed, http_iroh_config(&relay.base_url, vec![peer]))
        .await
        .expect("sender opens");

    let receiver_mailbox = receiver.mailbox("ops/combo").expect("mailbox opens");
    let recv = tokio::spawn(async move { receiver_mailbox.recv().await });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let send = tokio::time::timeout(
        Duration::from_secs(5),
        sender
            .mailbox("ops/combo")
            .expect("mailbox opens")
            .send(b"hello-combo"),
    )
    .await
    .expect("mailbox send completes")
    .expect("mailbox send succeeds");
    assert_eq!(send.delivered.len(), 2);
    assert!(send.delivered.contains(&TransportKind::Http));
    assert!(send.delivered.contains(&TransportKind::Iroh));

    let message = tokio::time::timeout(Duration::from_secs(5), recv)
        .await
        .expect("mailbox recv completes")
        .expect("mailbox task joins")
        .expect("mailbox recv succeeds");
    assert_eq!(message.payload, b"hello-combo");
    assert!(matches!(
        message.via,
        TransportKind::Http | TransportKind::Iroh
    ));

    let receiver_slot = receiver.slot("state/combo").expect("slot opens");
    let mut watch = receiver_slot.watch();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let put = tokio::time::timeout(
        Duration::from_secs(5),
        sender
            .slot("state/combo")
            .expect("slot opens")
            .put(b"slot-combo"),
    )
    .await
    .expect("slot put completes")
    .expect("slot put succeeds");
    assert_eq!(put.stored.len(), 2);
    assert!(put.stored.contains(&TransportKind::Http));
    assert!(put.stored.contains(&TransportKind::Iroh));

    let watched = tokio::time::timeout(Duration::from_secs(5), watch.recv())
        .await
        .expect("slot watch completes")
        .expect("slot watch succeeds");
    assert_eq!(watched.payload, b"slot-combo");
    assert_eq!(watched.version, put.version);
    assert!(matches!(
        watched.via,
        TransportKind::Http | TransportKind::Iroh
    ));

    let value = tokio::time::timeout(Duration::from_secs(5), receiver_slot.get())
        .await
        .expect("slot get completes")
        .expect("slot get succeeds")
        .expect("slot value exists");
    assert_eq!(value.payload, b"slot-combo");
    assert_eq!(value.version, put.version);
    assert!(matches!(
        value.via,
        TransportKind::Http | TransportKind::Iroh
    ));
}
