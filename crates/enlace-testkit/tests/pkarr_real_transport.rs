#![cfg(all(feature = "http", feature = "pkarr"))]

mod support;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::put;
use enlace::{
    Config, HttpConfig, Namespace, PeerConfig, PeerIdentity, PeerSlot, PeerSlotScope,
    PeerSlotValue, PkarrConfig, TransportError, TransportKind, TrustedPeer,
};
use enlace_relay::{RelayConfig, build_router};
use tokio::task::JoinHandle;

#[derive(Clone, Default)]
struct PkarrRelayState {
    packets: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

struct PkarrRelayProcess {
    base_url: String,
    task: JoinHandle<()>,
}

impl PkarrRelayProcess {
    async fn spawn() -> Self {
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("ephemeral listener binds");
        listener
            .set_nonblocking(true)
            .expect("listener switches to nonblocking");
        let addr = listener.local_addr().expect("listener has local addr");
        let app = Router::new()
            .route("/{public_key}", put(pkarr_put).get(pkarr_get))
            .with_state(PkarrRelayState::default());
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
        let client = support::reqwest_client();
        for _ in 0..20 {
            if client
                .get(format!("{}/ready", self.base_url))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("pkarr relay did not become ready");
    }
}

impl Drop for PkarrRelayProcess {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct HttpRelayProcess {
    base_url: String,
    task: JoinHandle<()>,
}

impl HttpRelayProcess {
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
        let client = support::reqwest_client();
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
        panic!("HTTP relay did not become ready");
    }
}

impl Drop for HttpRelayProcess {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn pkarr_put(
    State(state): State<PkarrRelayState>,
    Path(public_key): Path<String>,
    body: Bytes,
) -> StatusCode {
    let mut packets = state.packets.lock().expect("mock pkarr state lock");
    packets.insert(public_key, body.to_vec());
    StatusCode::NO_CONTENT
}

async fn pkarr_get(
    State(state): State<PkarrRelayState>,
    Path(public_key): Path<String>,
) -> impl IntoResponse {
    let packets = state.packets.lock().expect("mock pkarr state lock");
    if let Some(packet) = packets.get(&public_key) {
        (StatusCode::OK, packet.clone()).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn relay_pkarr_config(base_url: &str) -> PkarrConfig {
    PkarrConfig {
        resolvers: vec![base_url.to_owned()],
        republish_interval: Duration::from_millis(50),
        ..PkarrConfig::default()
    }
}

fn relay_namespace_config(base_url: &str) -> Config {
    Config {
        pkarr: Some(relay_pkarr_config(base_url)),
        ..Config::default()
    }
}

fn relay_peer_config(base_url: &str) -> PeerConfig {
    PeerConfig {
        pkarr: Some(relay_pkarr_config(base_url)),
        ..PeerConfig::default()
    }
}

fn http_config(base_url: &str) -> Config {
    Config {
        http: Some(HttpConfig::new(base_url.parse().expect("relay URL parses"))),
        ..Config::default()
    }
}

async fn wait_for_slot(slot: &enlace::Slot) -> enlace::SlotValue {
    for _ in 0..30 {
        if let Some(value) = slot.get().await.expect("slot get succeeds") {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("slot value did not arrive");
}

async fn wait_for_peer_pairwise_slot(slot: &PeerSlot<'_>) -> PeerSlotValue {
    for _ in 0..30 {
        if let Some(value) = slot.get_pairwise().await.expect("peer slot get succeeds") {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("peer slot value did not arrive");
}

#[tokio::test]
async fn namespaces_exchange_slot_over_pkarr_relay_mock() {
    let relay = PkarrRelayProcess::spawn().await;
    let seed = [0x77; 32];
    let sender = Namespace::open(&seed, relay_namespace_config(&relay.base_url))
        .await
        .expect("sender opens");
    let receiver = Namespace::open(&seed, relay_namespace_config(&relay.base_url))
        .await
        .expect("receiver opens");

    let sender_slot = sender.slot("state/current").expect("slot opens");
    let receiver_slot = receiver.slot("state/current").expect("slot opens");
    let put = sender_slot
        .put(b"slot-pkarr")
        .await
        .expect("slot put succeeds");
    assert_eq!(put.stored, vec![TransportKind::Pkarr]);

    let value = receiver_slot
        .get()
        .await
        .expect("slot get succeeds")
        .expect("slot value exists");
    assert_eq!(value.payload, b"slot-pkarr");
    assert_eq!(value.version, put.version);
    assert_eq!(value.via, TransportKind::Pkarr);
}

#[tokio::test]
async fn peer_namespaces_exchange_pairwise_slot_over_pkarr_relay_mock() {
    let relay = PkarrRelayProcess::spawn().await;
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let bob_card = bob_identity.card();
    let alice = enlace::PeerNamespace::open(
        alice_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(bob_card.clone()).unwrap()],
            ..relay_peer_config(&relay.base_url)
        },
    )
    .await
    .expect("alice opens");
    let bob = enlace::PeerNamespace::open(
        bob_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(alice_card.clone()).unwrap()],
            ..relay_peer_config(&relay.base_url)
        },
    )
    .await
    .expect("bob opens");

    let put = alice
        .slot("state/current")
        .expect("peer slot opens")
        .put_for_peers(std::slice::from_ref(&bob_card), b"peer-slot-pkarr")
        .await
        .expect("peer slot put succeeds");
    assert_eq!(put.stored, vec![TransportKind::Pkarr]);

    let value = bob
        .slot("state/current")
        .expect("peer slot opens")
        .get_pairwise()
        .await
        .expect("peer slot get succeeds")
        .expect("peer slot value exists");
    assert_eq!(value.payload, b"peer-slot-pkarr");
    assert_eq!(value.version, put.version);
    assert_eq!(value.sender, alice.peer_id());
    assert_eq!(value.signed_by, alice_card.signing_key);
    assert_eq!(value.via, TransportKind::Pkarr);
    assert_eq!(value.scope, PeerSlotScope::Pairwise);
}

#[tokio::test]
async fn http_mailbox_and_pkarr_slot_fanout() {
    let http_relay = HttpRelayProcess::spawn().await;
    let pkarr_relay = PkarrRelayProcess::spawn().await;
    let seed = [0x88; 32];

    let combined = |base_url: &str, http_url: &str| -> Config {
        Config {
            http: Some(HttpConfig::new(http_url.parse().expect("relay URL parses"))),
            pkarr: Some(relay_pkarr_config(base_url)),
            ..Config::default()
        }
    };

    let sender = Namespace::open(&seed, combined(&pkarr_relay.base_url, &http_relay.base_url))
        .await
        .expect("sender opens");
    let receiver = Namespace::open(&seed, combined(&pkarr_relay.base_url, &http_relay.base_url))
        .await
        .expect("receiver opens");

    let sender_mailbox = sender.mailbox("ops/events").expect("mailbox opens");
    let send = sender_mailbox
        .send(b"hello-fanout")
        .await
        .expect("mailbox send succeeds through HTTP");
    assert_eq!(send.delivered, vec![TransportKind::Http]);
    assert_eq!(send.failed.len(), 1);
    assert_eq!(send.failed[0].0, TransportKind::Pkarr);
    assert!(matches!(send.failed[0].1, TransportError::Unsupported));

    let receiver_mailbox = receiver.mailbox("ops/events").expect("mailbox opens");
    let message = receiver_mailbox
        .recv()
        .await
        .expect("mailbox recv succeeds");
    assert_eq!(message.payload, b"hello-fanout");
    assert_eq!(message.via, TransportKind::Http);

    let sender_slot = sender.slot("state/current").expect("slot opens");
    let put = sender_slot
        .put(b"slot-fanout")
        .await
        .expect("slot put succeeds");
    assert!(put.stored.contains(&TransportKind::Http));
    assert!(put.stored.contains(&TransportKind::Pkarr));
    assert!(put.failed.is_empty());

    let http_reader = Namespace::open(&seed, http_config(&http_relay.base_url))
        .await
        .expect("HTTP reader opens");
    let http_value = http_reader
        .slot("state/current")
        .expect("slot opens")
        .get()
        .await
        .expect("HTTP slot get succeeds")
        .expect("HTTP slot value exists");
    assert_eq!(http_value.payload, b"slot-fanout");
    assert_eq!(http_value.version, put.version);
    assert_eq!(http_value.via, TransportKind::Http);

    let pkarr_reader = Namespace::open(&seed, relay_namespace_config(&pkarr_relay.base_url))
        .await
        .expect("pkarr reader opens");
    let pkarr_value = pkarr_reader
        .slot("state/current")
        .expect("slot opens")
        .get()
        .await
        .expect("pkarr slot get succeeds")
        .expect("pkarr slot value exists");
    assert_eq!(pkarr_value.payload, b"slot-fanout");
    assert_eq!(pkarr_value.version, put.version);
    assert_eq!(pkarr_value.via, TransportKind::Pkarr);
}

#[cfg(feature = "pkarr-dht")]
mod dht_mode {
    use super::*;
    use enlace::PkarrNetworkMode;
    use pkarr::mainline::Testnet;

    async fn build_testnet(size: usize) -> Testnet {
        tokio::task::spawn_blocking(move || Testnet::builder(size).build())
            .await
            .expect("testnet build task joins")
            .expect("testnet builds")
    }

    fn testnet_pkarr_config(bootstrap: &[String]) -> PkarrConfig {
        PkarrConfig {
            network: PkarrNetworkMode::Dht,
            bootstrap: bootstrap
                .iter()
                .map(|addr| addr.parse().expect("testnet bootstrap addr parses"))
                .collect(),
            request_timeout: Duration::from_secs(15),
            republish_interval: Duration::from_millis(100),
            ..PkarrConfig::default()
        }
    }

    fn testnet_namespace_config(bootstrap: &[String]) -> Config {
        Config {
            pkarr: Some(testnet_pkarr_config(bootstrap)),
            ..Config::default()
        }
    }

    fn testnet_peer_config(bootstrap: &[String]) -> PeerConfig {
        PeerConfig {
            pkarr: Some(testnet_pkarr_config(bootstrap)),
            ..PeerConfig::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn namespaces_exchange_slot_over_isolated_pkarr_dht() {
        let testnet = build_testnet(10).await;
        let seed = [0x66; 32];
        let sender = Namespace::open(&seed, testnet_namespace_config(&testnet.bootstrap))
            .await
            .expect("sender opens");
        let receiver = Namespace::open(&seed, testnet_namespace_config(&testnet.bootstrap))
            .await
            .expect("receiver opens");

        let sender_slot = sender.slot("state/current").expect("slot opens");
        let receiver_slot = receiver.slot("state/current").expect("slot opens");
        let put = sender_slot
            .put(b"slot-pkarr-dht")
            .await
            .expect("slot put succeeds");
        assert_eq!(put.stored, vec![TransportKind::Pkarr]);

        let value = wait_for_slot(&receiver_slot).await;
        assert_eq!(value.payload, b"slot-pkarr-dht");
        assert_eq!(value.version, put.version);
        assert_eq!(value.via, TransportKind::Pkarr);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_namespaces_exchange_pairwise_slot_over_isolated_pkarr_dht() {
        let testnet = build_testnet(10).await;
        let alice_identity = PeerIdentity::generate();
        let bob_identity = PeerIdentity::generate();
        let alice_card = alice_identity.card();
        let bob_card = bob_identity.card();
        let alice = enlace::PeerNamespace::open(
            alice_identity,
            PeerConfig {
                trusted_peers: vec![TrustedPeer::try_from_card(bob_card.clone()).unwrap()],
                ..testnet_peer_config(&testnet.bootstrap)
            },
        )
        .await
        .expect("alice opens");
        let bob = enlace::PeerNamespace::open(
            bob_identity,
            PeerConfig {
                trusted_peers: vec![TrustedPeer::try_from_card(alice_card.clone()).unwrap()],
                ..testnet_peer_config(&testnet.bootstrap)
            },
        )
        .await
        .expect("bob opens");

        let put = alice
            .slot("state/current")
            .expect("peer slot opens")
            .put_for_peers(std::slice::from_ref(&bob_card), b"peer-slot-pkarr-dht")
            .await
            .expect("peer slot put succeeds");
        assert_eq!(put.stored, vec![TransportKind::Pkarr]);

        let bob_slot = bob.slot("state/current").expect("peer slot opens");
        let value = wait_for_peer_pairwise_slot(&bob_slot).await;
        assert_eq!(value.payload, b"peer-slot-pkarr-dht");
        assert_eq!(value.version, put.version);
        assert_eq!(value.sender, alice.peer_id());
        assert_eq!(value.signed_by, alice_card.signing_key);
        assert_eq!(value.via, TransportKind::Pkarr);
        assert_eq!(value.scope, PeerSlotScope::Pairwise);
    }
}
