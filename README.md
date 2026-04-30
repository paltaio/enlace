# enlace

Encrypted mailbox and latest-value slot fan-out for Rust applications.

`enlace` can send the same encrypted payload over multiple transports and accept
the first valid delivery. It currently includes HTTP relay, DHT, pkarr, and iroh
transports.

## Crates

- `enlace`: library API
- `enlace-relay`: HTTP relay server
- `enlace-testkit`: in-memory, lossy, and delayed test transports

## Modes

- Shared-seed mode uses `Namespace::open(&seed, config)`. Use it when every peer
  can share one 32-byte secret and should have equal access to the same mailbox
  and slot names.
- Public-key mode uses `PeerNamespace::open(identity, config)`. Use it when peers
  pair by exchanging public `PeerCard` values and need per-peer trust, revocation,
  pairwise messages, or caller-managed group keys.

HTTP and iroh support mailboxes. HTTP, DHT, pkarr, and iroh support slots. DHT and
pkarr are latest-record slot transports; they do not support mailbox delivery.

## Shared-Seed Example

```rust
use std::sync::Arc;

use enlace::{Config, ConfiguredTransport, Namespace, TransportKind};
use enlace_testkit::InMemoryTransport;

const SEED: [u8; 32] = [7; 32];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = InMemoryTransport::new();
    let config = |transport: InMemoryTransport| Config {
        transports: vec![ConfiguredTransport::new(
            TransportKind::Http,
            Arc::new(transport),
        )],
        ..Config::default()
    };

    let sender = Namespace::open(&SEED, config(transport.clone())).await?;
    let receiver = Namespace::open(&SEED, config(transport)).await?;

    sender.mailbox("chat")?.send(b"hello").await?;
    let message = receiver.mailbox("chat")?.recv().await?;
    assert_eq!(message.payload, b"hello");

    receiver.slot("status")?.put(b"online").await?;
    let status = sender.slot("status")?.get().await?.expect("slot value");
    assert_eq!(status.payload, b"online");

    Ok(())
}
```

## Public-Key Example

```rust
use std::sync::Arc;

use enlace::{
    ConfiguredTransport, PeerConfig, PeerIdentity, PeerNamespace, TransportKind, TrustedPeer,
};
use enlace_testkit::InMemoryTransport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = InMemoryTransport::new();

    let sender_identity = PeerIdentity::generate();
    let receiver_identity = PeerIdentity::generate();
    let sender_card = sender_identity.card();
    let receiver_card = receiver_identity.card();

    let sender = PeerNamespace::open(
        sender_identity,
        peer_config(
            transport.clone(),
            vec![TrustedPeer::try_from_card(receiver_card.clone())?],
        ),
    )
    .await?;
    let receiver = PeerNamespace::open(
        receiver_identity,
        peer_config(transport, vec![TrustedPeer::try_from_card(sender_card)?]),
    )
    .await?;

    sender
        .mailbox("chat")?
        .send_to_peers(std::slice::from_ref(&receiver_card), b"hello")
        .await?;

    let message = receiver.mailbox("chat")?.recv().await?;
    assert_eq!(message.sender, sender.peer_id());
    assert_eq!(message.payload, b"hello");

    Ok(())
}

fn peer_config(transport: InMemoryTransport, trusted_peers: Vec<TrustedPeer>) -> PeerConfig {
    PeerConfig {
        trusted_peers,
        transports: vec![ConfiguredTransport::new(
            TransportKind::Http,
            Arc::new(transport),
        )],
        ..PeerConfig::default()
    }
}
```

## Relay

Run the HTTP relay locally:

```sh
cargo run -p enlace-relay -- --listen 127.0.0.1:7777
```

With basic auth:

```sh
ENLACE_RELAY_AUTH=user:pass cargo run -p enlace-relay -- --listen 127.0.0.1:7777
```

## Verification

```sh
cargo test --workspace --locked
cargo run -p enlace-testkit --example two_peers --locked
```
