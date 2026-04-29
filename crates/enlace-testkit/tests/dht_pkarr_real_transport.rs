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
use enlace::{Config, DhtConfig, Namespace, PkarrConfig, TransportKind};
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
        let client = reqwest::Client::new();
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

fn dht_config(bootstrap: &[String]) -> Config {
    Config {
        dht: Some(DhtConfig {
            bootstrap: bootstrap
                .iter()
                .map(|addr| addr.parse().expect("testnet bootstrap addr parses"))
                .collect(),
            watch_poll_interval: Duration::from_millis(50),
        }),
        ..Config::default()
    }
}

fn pkarr_config(base_url: &str) -> Config {
    Config {
        pkarr: Some(PkarrConfig {
            resolvers: vec![base_url.to_owned()],
            republish_interval: Duration::from_millis(50),
        }),
        ..Config::default()
    }
}

async fn build_dht_testnet(size: usize) -> mainline::Testnet {
    tokio::task::spawn_blocking(move || mainline::Testnet::builder(size).build())
        .await
        .expect("testnet build task joins")
        .expect("testnet builds")
}

async fn wait_for_slot(slot: &enlace::Slot) -> enlace::SlotValue {
    for _ in 0..10 {
        if let Some(value) = slot.get().await.expect("slot get succeeds") {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("slot value did not arrive");
}

#[tokio::test]
async fn namespaces_exchange_slot_over_isolated_dht_bootstrap() {
    let testnet = build_dht_testnet(5).await;
    let seed = [0x66; 32];
    let sender = Namespace::open(&seed, dht_config(&testnet.bootstrap))
        .await
        .expect("sender opens");
    let receiver = Namespace::open(&seed, dht_config(&testnet.bootstrap))
        .await
        .expect("receiver opens");

    let sender_slot = sender.slot("state/current").expect("slot opens");
    let receiver_slot = receiver.slot("state/current").expect("slot opens");
    let put = sender_slot
        .put(b"slot-dht")
        .await
        .expect("slot put succeeds");
    assert_eq!(put.stored, vec![TransportKind::Dht]);

    let value = wait_for_slot(&receiver_slot).await;
    assert_eq!(value.payload, b"slot-dht");
    assert_eq!(value.version, put.version);
    assert_eq!(value.via, TransportKind::Dht);
}

#[tokio::test]
async fn namespaces_exchange_slot_over_pkarr_relay_mock() {
    let relay = PkarrRelayProcess::spawn().await;
    let seed = [0x77; 32];
    let sender = Namespace::open(&seed, pkarr_config(&relay.base_url))
        .await
        .expect("sender opens");
    let receiver = Namespace::open(&seed, pkarr_config(&relay.base_url))
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
