# enlace

Encrypted mailbox and latest-value slot fan-out for Rust applications.

`enlace` can send the same encrypted payload over multiple transports and accept
the first valid delivery. It currently includes HTTP relay, pkarr, and iroh
transports. pkarr publishes signed DNS records over public HTTP relays and,
optionally on native targets, the Mainline DHT.

## Crates

- `enlace`: library API
- `enlace-agent`: local daemon for non-Rust clients
- `enlace-relay`: HTTP relay server
- `enlace-testkit`: in-memory, lossy, and delayed test transports

## Features

Default features enable `http`, `pkarr`, `iroh`, and `sled` (file-backed state).
pkarr ships with HTTP relay support; native Mainline DHT support is gated behind
the `pkarr-dht` feature. Each transport is independent; pick any subset:

```toml
enlace = { version = "0.1", default-features = false, features = ["http"] }
enlace = { version = "0.1", default-features = false, features = ["pkarr"] }
enlace = { version = "0.1", default-features = false, features = ["pkarr", "pkarr-dht"] }
enlace = { version = "0.1", default-features = false, features = ["iroh"] }
enlace = { version = "0.1", default-features = false, features = ["http", "iroh"] }
enlace = { version = "0.1", default-features = false, features = ["all-transports"] }
```

Browser/wasm builds keep pkarr relay-only; DHT mode is unavailable on wasm.

`sled` is a separate feature for file-backed `State::file(path)`. Builds without
`sled` keep `State::memory()` and any custom `StateStore` implementation.

## Modes

- Shared-seed mode uses `Namespace::open(&seed, config)`. Use it when every peer
  can share one 32-byte secret and should have equal access to the same mailbox
  and slot names.
- Public-key mode uses `PeerNamespace::open(identity, config)`. Use it when peers
  pair by exchanging public `PeerCard` values and need per-peer trust, revocation,
  pairwise messages, or caller-managed group keys.

HTTP and iroh support mailboxes. HTTP, pkarr, and iroh support slots. pkarr is
the latest-record slot transport and does not support mailbox delivery; on
native targets it can be configured for HTTP relays only, the Mainline DHT
only, or both networks together.

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

## Agent Daemon

`enlace-agent` exposes the public-key peer API to local clients over WebSocket
and Unix socket JSON.

Build a release binary:

```sh
cargo build -p enlace-agent --release --all-features --locked
```

Example host A config at `/etc/enlace/agent.toml`:

```toml
seed_file = "/etc/enlace/seed"
token_file = "/etc/enlace/token"
listen_ws = "127.0.0.1:3000"
listen_unix = "/run/enlace/agent.sock"
data_dir = "/var/lib/enlace-agent"
transports = ["http"]
relay = "https://relay.example.com"
```

Host B uses its own seed and a different local port:

```toml
seed_file = "/etc/enlace/seed"
token_file = "/etc/enlace/token"
listen_ws = "127.0.0.1:3001"
data_dir = "/var/lib/enlace-agent"
transports = ["http"]
relay = "https://relay.example.com"
```

Start each host:

```sh
enlace-agent --config /etc/enlace/agent.toml
```

For pkarr slots, select the pkarr transport and choose its network mode:

```toml
seed_file = "/etc/enlace/seed"
token_file = "/etc/enlace/token"
listen_ws = "127.0.0.1:3000"
data_dir = "/var/lib/enlace-agent"
transports = ["pkarr"]
pkarr_network = "relays"
pkarr_relays = ["https://pkarr.pubky.org", "https://pkarr.pubky.app"]
```

Native builds compiled with `pkarr-dht` can set `pkarr_network = "dht"` or
`pkarr_network = "both"`. `pkarr_bootstrap` is optional; when omitted, pkarr
uses its upstream Mainline DHT defaults.

Pair hosts by exporting each local card and adding it on the other host:

```json
{"id":"card","type":"export_card"}
{"id":"add","type":"add_peer","card":"<peer-card-from-other-host>"}
```

Client messages stay opaque base64 payloads:

```json
{"id":"sub","type":"subscribe","channel":"default"}
{"id":"send","type":"send","to":"<peer-id>","channel":"default","payload":"aGVsbG8="}
```

The systemd unit template is in `packaging/systemd/enlace-agent.service`.

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
cargo check -p enlace --no-default-features --locked
cargo check -p enlace --no-default-features --features http --locked
cargo run -p enlace-testkit --example two_peers --locked
```

## License

MIT
