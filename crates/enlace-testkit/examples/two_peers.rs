use std::sync::Arc;

use enlace::{
    Config, ConfiguredTransport, GroupId, GroupKey, GroupKeyId, Namespace, PeerConfig,
    PeerIdentity, PeerNamespace, Transport, TransportKind, TrustedPeer,
};
use enlace_testkit::InMemoryTransport;

const SEED: [u8; 32] = [7; 32];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    shared_seed_round_trip().await?;
    public_key_pairwise_round_trip().await?;
    public_key_group_round_trip().await?;

    println!("shared-seed and public-key round trips completed");
    Ok(())
}

async fn shared_seed_round_trip() -> Result<(), Box<dyn std::error::Error>> {
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

    Ok(())
}

async fn public_key_pairwise_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let transport = InMemoryTransport::new();
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let bob_card = bob_identity.card();

    let alice = PeerNamespace::open(
        alice_identity,
        peer_config(
            transport.clone(),
            vec![TrustedPeer::try_from_card(bob_card.clone())?],
            Vec::new(),
        ),
    )
    .await?;
    let bob = PeerNamespace::open(
        bob_identity,
        peer_config(
            transport,
            vec![TrustedPeer::try_from_card(alice_card.clone())?],
            Vec::new(),
        ),
    )
    .await?;

    let sent = alice
        .mailbox("chat")?
        .send_to_peers(
            std::slice::from_ref(&bob_card),
            b"hello without shared seed",
        )
        .await?;
    assert_eq!(sent.delivered, vec![TransportKind::Http]);

    let received = bob.mailbox("chat")?.recv().await?;
    assert_eq!(received.sender, alice.peer_id());
    assert_eq!(received.signed_by, alice_card.signing_key);
    assert_eq!(received.payload, b"hello without shared seed");
    assert_eq!(received.via, TransportKind::Http);
    assert_eq!(received.group, None);
    assert_eq!(received.key_id, None);

    Ok(())
}

async fn public_key_group_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let transport = InMemoryTransport::new();
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let bob_card = bob_identity.card();
    let group = GroupId::from_bytes([17; enlace::GROUP_ID_LEN]);
    let key = GroupKey::new(
        GroupKeyId::from_bytes([18; enlace::GROUP_KEY_ID_LEN]),
        [19; enlace::GROUP_KEY_SECRET_LEN],
    );

    let alice = PeerNamespace::open(
        alice_identity,
        peer_config(
            transport.clone(),
            vec![TrustedPeer::try_from_card(bob_card)?],
            vec![(group, key.clone())],
        ),
    )
    .await?;
    let bob = PeerNamespace::open(
        bob_identity,
        peer_config(
            transport,
            vec![TrustedPeer::try_from_card(alice_card.clone())?],
            vec![(group, key.clone())],
        ),
    )
    .await?;

    let sent = alice
        .mailbox("team")?
        .send_to_group(group, &[key.id], b"broadcast with caller group key")
        .await?;
    assert_eq!(sent.delivered, vec![TransportKind::Http]);

    let received = bob.mailbox("team")?.recv().await?;
    assert_eq!(received.sender, alice.peer_id());
    assert_eq!(received.signed_by, alice_card.signing_key);
    assert_eq!(received.payload, b"broadcast with caller group key");
    assert_eq!(received.via, TransportKind::Http);
    assert_eq!(received.group, Some(group));
    assert_eq!(received.key_id, Some(key.id));

    Ok(())
}

fn config<T>(transport: T) -> Config
where
    T: Transport + 'static,
{
    Config {
        transports: vec![ConfiguredTransport::new(
            TransportKind::Http,
            Arc::new(transport),
        )],
        ..Config::default()
    }
}

fn peer_config<T>(
    transport: T,
    trusted_peers: Vec<TrustedPeer>,
    group_keys: Vec<(GroupId, GroupKey)>,
) -> PeerConfig
where
    T: Transport + 'static,
{
    PeerConfig {
        trusted_peers,
        group_keys,
        transports: vec![ConfiguredTransport::new(
            TransportKind::Http,
            Arc::new(transport),
        )],
        ..PeerConfig::default()
    }
}
