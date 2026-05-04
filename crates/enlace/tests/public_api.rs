#![cfg(all(feature = "http", feature = "pkarr"))]

use ed25519_dalek::SigningKey;
use enlace::{
    Config, HealthState, HttpConfig, NameError, Namespace, OpenError, PkarrConfig, SendError,
    TransportError, TransportKind,
};
use url::Url;

fn seed() -> [u8; 32] {
    [0x42; 32]
}

fn http_config() -> Config {
    Config {
        http: Some(HttpConfig::new(Url::parse("https://198.51.100.1").unwrap())),
        ..Config::default()
    }
}

#[tokio::test]
async fn open_rejects_zero_seed() {
    let Err(err) = Namespace::open(&[0; 32], http_config()).await else {
        panic!("open should reject zero seed");
    };
    assert!(matches!(err, OpenError::InvalidSeed));
}

#[tokio::test]
async fn open_rejects_zero_transports() {
    let Err(err) = Namespace::open(&seed(), Config::default()).await else {
        panic!("open should reject zero transports");
    };
    assert!(matches!(err, OpenError::NoTransport));
}

#[tokio::test]
async fn open_accepts_trusted_without_signing() {
    let mut config = http_config();
    config
        .trusted
        .push(SigningKey::from_bytes(&[7; 32]).verifying_key());
    let namespace = Namespace::open(&seed(), config).await.unwrap();
    assert!(namespace.http().is_some());
}

#[tokio::test]
async fn open_accepts_signing_without_trusted() {
    let mut config = http_config();
    config.signing = Some(SigningKey::from_bytes(&[8; 32]));
    let namespace = Namespace::open(&seed(), config).await.unwrap();
    assert!(namespace.http().is_some());
}

#[tokio::test]
async fn mailbox_and_slot_validate_names() {
    let namespace = Namespace::open(&seed(), http_config()).await.unwrap();
    assert!(namespace.mailbox("alpha").is_ok());
    assert!(namespace.slot("alpha").is_ok());
    assert_eq!(
        namespace.mailbox("Alpha").err(),
        Some(NameError::InvalidChar)
    );
    assert_eq!(namespace.slot("").err(), Some(NameError::Empty));
}

#[tokio::test]
async fn health_reflects_configured_transports() {
    let namespace = Namespace::open(&seed(), http_config()).await.unwrap();
    let health = namespace.health();
    assert_eq!(health.transports.len(), 1);
    assert_eq!(health.transports[0].kind, TransportKind::Http);
    assert_eq!(health.transports[0].state, HealthState::Healthy);
    assert_eq!(health.transports[0].endpoints.len(), 1);
}

#[tokio::test]
async fn mailbox_surface_is_constructible() {
    let namespace = Namespace::open(&seed(), http_config()).await.unwrap();
    let mailbox = namespace.mailbox("ops/events").unwrap();
    assert_eq!(mailbox.name(), "ops/events");
    assert!(mailbox.try_recv().unwrap().is_none());
}

#[tokio::test]
async fn slot_surface_is_constructible() {
    let namespace = Namespace::open(&seed(), http_config()).await.unwrap();
    let slot = namespace.slot("state/current").unwrap();
    assert_eq!(slot.name(), "state/current");
}

#[tokio::test]
async fn pkarr_mailbox_send_is_unsupported() {
    let namespace = Namespace::open(
        &seed(),
        Config {
            pkarr: Some(PkarrConfig::default()),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    assert!(namespace.pkarr().is_some());

    let mailbox = namespace.mailbox("ops/events").unwrap();
    let Err(SendError::AllTransportsFailed(failures)) = mailbox.send(b"event").await else {
        panic!("pkarr mailbox send should fail as unsupported");
    };
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, TransportKind::Pkarr);
    assert!(matches!(failures[0].1, TransportError::Unsupported));
}
