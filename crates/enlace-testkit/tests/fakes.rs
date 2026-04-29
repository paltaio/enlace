use std::time::Duration;

use std::sync::Arc;

use enlace::{
    Config, ConfiguredTransport, MailboxTransport, Namespace, SlotTransport, TransportError,
    TransportKind,
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
