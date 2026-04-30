use std::time::Duration;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use enlace::{
    Config, ConfiguredTransport, GroupId, GroupKey, GroupKeyId, MailboxTransport, Namespace,
    PeerConfig, PeerIdentity, PeerNamespace, PeerSlotScope, SlotTransport, TransportError,
    TransportKind, TrustedPeer,
};
use enlace_testkit::{DelayingTransport, InMemoryTransport, LossyTransport};
use tokio_stream::StreamExt;

fn channel_id(byte: u8) -> [u8; 16] {
    [byte; 16]
}

#[tokio::test]
async fn in_memory_mailbox_is_fifo_and_consuming() {
    let transport = InMemoryTransport::new();
    let id = channel_id(1);

    transport.send(&id, b"first").await.unwrap();
    transport.send(&id, b"second").await.unwrap();

    assert_eq!(
        transport.recv(&id, Duration::ZERO).await.unwrap(),
        Some(b"first".to_vec())
    );
    assert_eq!(
        transport.recv(&id, Duration::ZERO).await.unwrap(),
        Some(b"second".to_vec())
    );
    assert_eq!(transport.recv(&id, Duration::ZERO).await.unwrap(), None);
}

#[tokio::test]
async fn in_memory_mailbox_long_poll_waits_for_send() {
    let transport = InMemoryTransport::new();
    let id = channel_id(2);
    let sender = transport.clone();

    let recv = tokio::spawn(async move {
        sender
            .recv(&id, Duration::from_secs(1))
            .await
            .expect("recv should not fail")
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    transport.send(&id, b"late").await.unwrap();

    assert_eq!(recv.await.unwrap(), Some(b"late".to_vec()));
}

#[tokio::test]
async fn in_memory_slot_rejects_stale_versions() {
    let transport = InMemoryTransport::new();
    let id = channel_id(3);

    transport.put(&id, 2, b"new").await.unwrap();
    let err = transport.put(&id, 2, b"stale").await.unwrap_err();
    assert!(matches!(err, TransportError::Stale));
    assert_eq!(
        transport.get(&id).await.unwrap(),
        Some((2, b"new".to_vec()))
    );
}

#[tokio::test]
async fn in_memory_slot_watch_filters_by_id_and_version() {
    let transport = InMemoryTransport::new();
    let id = channel_id(4);
    let other = channel_id(5);
    let mut watch = transport.watch(&id, 1);

    transport.put(&other, 2, b"other").await.unwrap();
    transport.put(&id, 1, b"old").await.unwrap();
    transport.put(&id, 2, b"new").await.unwrap();

    let next = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(next, (2, b"new".to_vec()));
}

#[tokio::test]
async fn lossy_transport_can_drop_every_send() {
    let transport = LossyTransport::with_inner(InMemoryTransport::new()).with_drop_percent(100);
    let id = channel_id(6);

    transport.send(&id, b"drop").await.unwrap();
    assert_eq!(transport.recv(&id, Duration::ZERO).await.unwrap(), None);

    transport.put(&id, 1, b"drop").await.unwrap();
    assert_eq!(transport.get(&id).await.unwrap(), None);
}

#[tokio::test]
async fn delaying_transport_delegates_operations() {
    let transport = DelayingTransport::with_inner(InMemoryTransport::new())
        .with_max_delay(Duration::from_millis(1));
    let id = channel_id(7);

    transport.send(&id, b"mail").await.unwrap();
    assert_eq!(
        transport.recv(&id, Duration::ZERO).await.unwrap(),
        Some(b"mail".to_vec())
    );

    transport.put(&id, 1, b"slot").await.unwrap();
    assert_eq!(
        transport.get(&id).await.unwrap(),
        Some((1, b"slot".to_vec()))
    );
}

#[tokio::test]
async fn lossy_and_delaying_wrappers_compose() {
    let transport = DelayingTransport::with_inner(
        LossyTransport::with_inner(InMemoryTransport::new()).with_drop_percent(0),
    )
    .with_max_delay(Duration::from_millis(1));
    let id = channel_id(8);

    transport.send(&id, b"mail").await.unwrap();
    assert_eq!(
        transport.recv(&id, Duration::ZERO).await.unwrap(),
        Some(b"mail".to_vec())
    );
}

fn namespace_config<T>(transport: T) -> Config
where
    T: enlace::Transport + 'static,
{
    Config {
        transports: vec![ConfiguredTransport::new(
            TransportKind::Http,
            Arc::new(transport),
        )],
        ..Config::default()
    }
}

fn peer_namespace_config<T>(transport: T) -> PeerConfig
where
    T: enlace::Transport + 'static,
{
    PeerConfig {
        transports: vec![ConfiguredTransport::new(
            TransportKind::Http,
            Arc::new(transport),
        )],
        ..PeerConfig::default()
    }
}

fn peer_namespace_config_many(transports: Vec<ConfiguredTransport>) -> PeerConfig {
    PeerConfig {
        transports,
        ..PeerConfig::default()
    }
}

#[tokio::test]
async fn namespaces_exchange_mailbox_through_in_memory_transport() {
    let transport = InMemoryTransport::new();
    let sender = Namespace::open(&[9; 32], namespace_config(transport.clone()))
        .await
        .unwrap();
    let receiver = Namespace::open(&[9; 32], namespace_config(transport))
        .await
        .unwrap();

    sender
        .mailbox("events")
        .unwrap()
        .send(b"hello")
        .await
        .unwrap();
    let message = receiver.mailbox("events").unwrap().recv().await.unwrap();

    assert_eq!(message.payload, b"hello");
    assert_eq!(message.via, TransportKind::Http);
}

#[tokio::test]
async fn peer_namespaces_exchange_pairwise_mailbox() {
    let transport = InMemoryTransport::new();
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let stranger_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let bob_card = bob_identity.card();
    let stranger_card = stranger_identity.card();
    let alice = PeerNamespace::open(
        alice_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(bob_card.clone()).unwrap()],
            ..peer_namespace_config(transport.clone())
        },
    )
    .await
    .unwrap();
    let stranger = PeerNamespace::open(
        stranger_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(bob_card.clone()).unwrap()],
            ..peer_namespace_config(transport.clone())
        },
    )
    .await
    .unwrap();
    let bob = PeerNamespace::open(
        bob_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(alice_card.clone()).unwrap()],
            ..peer_namespace_config(transport)
        },
    )
    .await
    .unwrap();
    let inbox = bob.mailbox("chat").unwrap();

    stranger
        .mailbox("chat")
        .unwrap()
        .send_to_peers(std::slice::from_ref(&bob_card), b"drop")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            inbox.recv_timeout(Duration::ZERO)
        )
        .await
        .is_ok_and(|result| result.is_err())
    );

    alice
        .mailbox("chat")
        .unwrap()
        .send_to_peers(std::slice::from_ref(&bob_card), b"hello")
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(1), inbox.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(message.sender, alice.peer_id());
    assert_eq!(message.signed_by, alice_card.signing_key);
    assert_eq!(message.payload, b"hello");
    assert_eq!(message.via, TransportKind::Http);
    assert_eq!(message.group, None);
    assert_eq!(message.key_id, None);
    assert_eq!(stranger_card.peer_id, stranger.peer_id());
}

#[tokio::test]
async fn peer_namespaces_exchange_group_mailbox() {
    let transport = InMemoryTransport::new();
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let group = GroupId::from_bytes([41; enlace::GROUP_ID_LEN]);
    let key = GroupKey::new(
        GroupKeyId::from_bytes([42; enlace::GROUP_KEY_ID_LEN]),
        [43; enlace::GROUP_KEY_SECRET_LEN],
    );
    let alice = PeerNamespace::open(
        alice_identity,
        PeerConfig {
            group_keys: vec![(group, key.clone())],
            ..peer_namespace_config(transport.clone())
        },
    )
    .await
    .unwrap();
    let bob = PeerNamespace::open(
        bob_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(alice_card.clone()).unwrap()],
            group_keys: vec![(group, key.clone())],
            ..peer_namespace_config(transport)
        },
    )
    .await
    .unwrap();

    alice
        .mailbox("team")
        .unwrap()
        .send_to_group(group, &[key.id], b"group hello")
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(1), bob.mailbox("team").unwrap().recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(message.sender, alice.peer_id());
    assert_eq!(message.signed_by, alice_card.signing_key);
    assert_eq!(message.payload, b"group hello");
    assert_eq!(message.via, TransportKind::Http);
    assert_eq!(message.group, Some(group));
    assert_eq!(message.key_id, Some(key.id));
}

#[tokio::test]
async fn peer_namespaces_exchange_pairwise_slot() {
    let transport = InMemoryTransport::new();
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let bob_card = bob_identity.card();
    let alice = PeerNamespace::open(
        alice_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(bob_card.clone()).unwrap()],
            ..peer_namespace_config(transport.clone())
        },
    )
    .await
    .unwrap();
    let bob = PeerNamespace::open(
        bob_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(alice_card.clone()).unwrap()],
            ..peer_namespace_config(transport)
        },
    )
    .await
    .unwrap();

    let report = alice
        .slot("status")
        .unwrap()
        .put_for_peers(std::slice::from_ref(&bob_card), b"ready")
        .await
        .unwrap();
    assert_eq!(report.version, 1);

    let value = bob
        .slot("status")
        .unwrap()
        .get_pairwise()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value.version, 1);
    assert_eq!(value.sender, alice.peer_id());
    assert_eq!(value.signed_by, alice_card.signing_key);
    assert_eq!(value.payload, b"ready");
    assert_eq!(value.via, TransportKind::Http);
    assert_eq!(value.scope, PeerSlotScope::Pairwise);
    assert_eq!(value.key_id, None);
}

#[tokio::test]
async fn peer_namespaces_exchange_publisher_and_group_slots() {
    let transport = InMemoryTransport::new();
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let bob_card = bob_identity.card();
    let group = GroupId::from_bytes([51; enlace::GROUP_ID_LEN]);
    let key = GroupKey::new(
        GroupKeyId::from_bytes([52; enlace::GROUP_KEY_ID_LEN]),
        [53; enlace::GROUP_KEY_SECRET_LEN],
    );
    let alice = PeerNamespace::open(
        alice_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(bob_card.clone()).unwrap()],
            group_keys: vec![(group, key.clone())],
            ..peer_namespace_config(transport.clone())
        },
    )
    .await
    .unwrap();
    let bob = PeerNamespace::open(
        bob_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(alice_card.clone()).unwrap()],
            group_keys: vec![(group, key.clone())],
            ..peer_namespace_config(transport)
        },
    )
    .await
    .unwrap();

    alice
        .slot("profile")
        .unwrap()
        .put_publisher_for_peers(std::slice::from_ref(&bob_card), b"pub-v1")
        .await
        .unwrap();
    alice
        .slot("profile")
        .unwrap()
        .put_group(group, &[key.id], b"group-v1")
        .await
        .unwrap();

    let publisher = bob
        .slot("profile")
        .unwrap()
        .get_publisher(alice.peer_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(publisher.payload, b"pub-v1");
    assert_eq!(
        publisher.scope,
        PeerSlotScope::Publisher {
            publisher: alice.peer_id()
        }
    );
    assert_eq!(publisher.key_id, None);

    let group_value = bob
        .slot("profile")
        .unwrap()
        .get_group(group)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(group_value.payload, b"group-v1");
    assert_eq!(group_value.scope, PeerSlotScope::Group { group });
    assert_eq!(group_value.key_id, Some(key.id));
}

#[tokio::test]
async fn peer_slot_get_and_watch_select_latest_across_slot_transports() {
    let http = InMemoryTransport::new();
    let dht = InMemoryTransport::new();
    let pkarr = InMemoryTransport::new();
    let alice_identity = PeerIdentity::generate();
    let bob_identity = PeerIdentity::generate();
    let alice_card = alice_identity.card();
    let bob_card = bob_identity.card();
    let transports = |http: InMemoryTransport, dht: InMemoryTransport, pkarr: InMemoryTransport| {
        peer_namespace_config_many(vec![
            ConfiguredTransport::new(TransportKind::Http, Arc::new(http)),
            ConfiguredTransport::new(TransportKind::Dht, Arc::new(dht)),
            ConfiguredTransport::new(TransportKind::Pkarr, Arc::new(pkarr)),
        ])
    };
    let alice = PeerNamespace::open(
        alice_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(bob_card.clone()).unwrap()],
            ..transports(http.clone(), dht.clone(), pkarr.clone())
        },
    )
    .await
    .unwrap();
    let bob = PeerNamespace::open(
        bob_identity,
        PeerConfig {
            trusted_peers: vec![TrustedPeer::try_from_card(alice_card).unwrap()],
            ..transports(http, dht, pkarr)
        },
    )
    .await
    .unwrap();

    let bob_slot = bob.slot("state").unwrap();
    let mut watch = bob_slot.watch_pairwise().unwrap();
    alice
        .slot("state")
        .unwrap()
        .put_for_peers(std::slice::from_ref(&bob_card), b"v1")
        .await
        .unwrap();
    alice
        .slot("state")
        .unwrap()
        .put_for_peers(std::slice::from_ref(&bob_card), b"v2")
        .await
        .unwrap();

    let value = bob_slot.get_pairwise().await.unwrap().unwrap();
    assert_eq!(value.version, 2);
    assert_eq!(value.payload, b"v2");

    let mut watched = tokio::time::timeout(Duration::from_secs(1), watch.recv())
        .await
        .unwrap()
        .unwrap();
    if watched.version == 1 {
        watched = tokio::time::timeout(Duration::from_secs(1), watch.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(watched.version, 2);
    assert_eq!(watched.payload, b"v2");
}

#[tokio::test]
async fn receive_only_trusted_namespace_requires_signatures() {
    let transport = InMemoryTransport::new();
    let seed = [31; 32];
    let trusted_signer = SigningKey::from_bytes(&[32; 32]);
    let untrusted_signer = SigningKey::from_bytes(&[33; 32]);

    let unsigned = Namespace::open(&seed, namespace_config(transport.clone()))
        .await
        .unwrap();
    let untrusted = Namespace::open(
        &seed,
        Config {
            signing: Some(untrusted_signer),
            ..namespace_config(transport.clone())
        },
    )
    .await
    .unwrap();
    let trusted = Namespace::open(
        &seed,
        Config {
            signing: Some(trusted_signer.clone()),
            ..namespace_config(transport.clone())
        },
    )
    .await
    .unwrap();
    let receiver = Namespace::open(
        &seed,
        Config {
            trusted: vec![trusted_signer.verifying_key()],
            ..namespace_config(transport)
        },
    )
    .await
    .unwrap();
    let inbox = receiver.mailbox("events").unwrap();

    unsigned
        .mailbox("events")
        .unwrap()
        .send(b"unsigned")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), inbox.recv())
            .await
            .is_err()
    );

    untrusted
        .mailbox("events")
        .unwrap()
        .send(b"untrusted")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), inbox.recv())
            .await
            .is_err()
    );

    trusted
        .mailbox("events")
        .unwrap()
        .send(b"trusted")
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(1), inbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message.payload, b"trusted");
    assert_eq!(message.signed_by, Some(trusted_signer.verifying_key()));
}

#[tokio::test]
async fn namespaces_exchange_slot_through_in_memory_transport() {
    let transport = InMemoryTransport::new();
    let writer = Namespace::open(&[10; 32], namespace_config(transport.clone()))
        .await
        .unwrap();
    let reader = Namespace::open(&[10; 32], namespace_config(transport))
        .await
        .unwrap();

    let report = writer.slot("current").unwrap().put(b"value").await.unwrap();
    assert_eq!(report.version, 1);

    let value = reader
        .slot("current")
        .unwrap()
        .get()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value.version, 1);
    assert_eq!(value.payload, b"value");
}

#[tokio::test]
async fn mailbox_fanout_duplicate_is_delivered_once() {
    let first = InMemoryTransport::new();
    let second = InMemoryTransport::new();
    let seed = [11; 32];
    let sender = Namespace::open(
        &seed,
        Config {
            transports: vec![
                ConfiguredTransport::new(TransportKind::Http, Arc::new(first.clone())),
                ConfiguredTransport::new(TransportKind::Dht, Arc::new(second.clone())),
            ],
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let receiver = Namespace::open(
        &seed,
        Config {
            transports: vec![
                ConfiguredTransport::new(TransportKind::Http, Arc::new(first)),
                ConfiguredTransport::new(TransportKind::Dht, Arc::new(second)),
            ],
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let mailbox = receiver.mailbox("events").unwrap();

    sender
        .mailbox("events")
        .unwrap()
        .send(b"dedup")
        .await
        .unwrap();
    assert_eq!(mailbox.recv().await.unwrap().payload, b"dedup");

    let duplicate = tokio::time::timeout(Duration::from_millis(50), mailbox.recv()).await;
    assert!(duplicate.is_err());
}

#[tokio::test]
async fn lossy_and_delaying_namespace_combo_delivers_each_message_once() {
    let dropped = InMemoryTransport::new();
    let delayed = InMemoryTransport::new();
    let duplicated = InMemoryTransport::new();
    let seed = [12; 32];
    let sender = Namespace::open(
        &seed,
        Config {
            transports: vec![
                ConfiguredTransport::new(
                    TransportKind::Http,
                    Arc::new(LossyTransport::with_inner(dropped.clone()).with_drop_percent(100)),
                ),
                ConfiguredTransport::new(
                    TransportKind::Dht,
                    Arc::new(
                        DelayingTransport::with_inner(delayed.clone())
                            .with_max_delay(Duration::from_millis(2)),
                    ),
                ),
                ConfiguredTransport::new(TransportKind::Pkarr, Arc::new(duplicated.clone())),
            ],
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let receiver = Namespace::open(
        &seed,
        Config {
            transports: vec![
                ConfiguredTransport::new(
                    TransportKind::Http,
                    Arc::new(LossyTransport::with_inner(dropped).with_drop_percent(100)),
                ),
                ConfiguredTransport::new(
                    TransportKind::Dht,
                    Arc::new(
                        DelayingTransport::with_inner(delayed)
                            .with_max_delay(Duration::from_millis(2)),
                    ),
                ),
                ConfiguredTransport::new(TransportKind::Pkarr, Arc::new(duplicated)),
            ],
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let mailbox = receiver.mailbox("combo").unwrap();

    for i in 0u8..5 {
        sender.mailbox("combo").unwrap().send(&[i]).await.unwrap();
    }

    let mut received = Vec::new();
    for _ in 0..5 {
        let message = tokio::time::timeout(Duration::from_secs(1), mailbox.recv())
            .await
            .unwrap()
            .unwrap();
        received.push(message.payload);
    }
    received.sort();
    assert_eq!(received, vec![vec![0], vec![1], vec![2], vec![3], vec![4]]);

    let duplicate = tokio::time::timeout(Duration::from_millis(50), mailbox.recv()).await;
    assert!(duplicate.is_err());
}
