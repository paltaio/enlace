use std::sync::Arc;

use enlace::{Config, ConfiguredTransport, Namespace, TransportKind};
use enlace_testkit::InMemoryTransport;
use serde::{Deserialize, Serialize};

const RECOVERY_SLOT: &str = "relay-config";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayConfig {
    version: u64,
    http_relay: String,
    iroh_endpoint: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct AppliedConfig {
    version: u64,
    http_relay: Option<String>,
    iroh_endpoint: Option<String>,
}

impl AppliedConfig {
    fn apply_if_newer(&mut self, candidate: RelayConfig) -> bool {
        if candidate.version <= self.version {
            return false;
        }

        self.version = candidate.version;
        self.http_relay = Some(candidate.http_relay);
        self.iroh_endpoint = Some(candidate.iroh_endpoint);
        true
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http = InMemoryTransport::new();
    let pkarr = InMemoryTransport::new();
    let seed = [42; 32];

    let publisher = Namespace::open(&seed, recovery_config(http.clone(), pkarr.clone())).await?;
    let subscriber = Namespace::open(&seed, recovery_config(http, pkarr)).await?;

    let next = RelayConfig {
        version: 12,
        http_relay: "https://relay.example.net".to_owned(),
        iroh_endpoint: "https://iroh.example.net:4433".to_owned(),
    };
    let payload = serde_json::to_vec(&next)?;

    let report = publisher.slot(RECOVERY_SLOT)?.put(&payload).await?;
    assert_eq!(report.version, 1);
    assert_eq!(report.stored.len(), 2);
    assert!(report.stored.contains(&TransportKind::Http));
    assert!(report.stored.contains(&TransportKind::Pkarr));

    let value = subscriber
        .slot(RECOVERY_SLOT)?
        .get()
        .await?
        .ok_or_else(|| std::io::Error::other("recovery slot should contain relay config"))?;
    assert!(matches!(
        value.via,
        TransportKind::Http | TransportKind::Pkarr
    ));

    let received: RelayConfig = serde_json::from_slice(&value.payload)?;
    let mut applied = AppliedConfig::default();
    assert!(applied.apply_if_newer(received));
    assert_eq!(
        applied,
        AppliedConfig {
            version: 12,
            http_relay: Some("https://relay.example.net".to_owned()),
            iroh_endpoint: Some("https://iroh.example.net:4433".to_owned()),
        }
    );

    let stale = RelayConfig {
        version: 11,
        http_relay: "https://old-relay.example.net".to_owned(),
        iroh_endpoint: "https://old-iroh.example.net:4433".to_owned(),
    };
    assert!(!applied.apply_if_newer(stale));

    Ok(())
}

fn recovery_config(http: InMemoryTransport, pkarr: InMemoryTransport) -> Config {
    Config {
        transports: vec![
            ConfiguredTransport::new(TransportKind::Http, Arc::new(http)),
            ConfiguredTransport::new(TransportKind::Pkarr, Arc::new(pkarr)),
        ],
        ..Config::default()
    }
}
