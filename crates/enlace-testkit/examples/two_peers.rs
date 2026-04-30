use std::sync::Arc;

use enlace::{Config, ConfiguredTransport, Namespace, TransportKind};
use enlace_testkit::InMemoryTransport;

const SEED: [u8; 32] = [7; 32];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = InMemoryTransport::new();

    let alice = Namespace::open(&SEED, config(transport.clone())).await?;
    let bob = Namespace::open(&SEED, config(transport)).await?;

    let sent = alice.mailbox("chat")?.send(b"hello from alice").await?;
    assert_eq!(sent.delivered, vec![TransportKind::Http]);

    let received = bob.mailbox("chat")?.recv().await?;
    assert_eq!(received.payload, b"hello from alice");
    assert_eq!(received.via, TransportKind::Http);

    let stored = bob.slot("status")?.put(b"bob is online").await?;
    assert_eq!(stored.version, 1);
    assert_eq!(stored.stored, vec![TransportKind::Http]);

    let status = alice
        .slot("status")?
        .get()
        .await?
        .ok_or_else(|| std::io::Error::other("status slot should be present"))?;
    assert_eq!(status.version, 1);
    assert_eq!(status.payload, b"bob is online");
    assert_eq!(status.via, TransportKind::Http);

    println!("mailbox and slot round trips completed");
    Ok(())
}

fn config(transport: InMemoryTransport) -> Config {
    Config {
        transports: vec![ConfiguredTransport::new(
            TransportKind::Http,
            Arc::new(transport),
        )],
        ..Config::default()
    }
}
