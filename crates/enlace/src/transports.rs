use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use futures_core::Stream;

use crate::config::Config;
#[cfg(feature = "iroh")]
use crate::config::IrohRelayMode;
#[cfg(feature = "pkarr")]
use crate::config::{PkarrConfig, PkarrNetworkMode};
use crate::error::TransportError;
use crate::kdf::TransportKind;
use crate::runtime::{Instant, SystemTime};

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "iroh")]
mod iroh;
#[cfg(feature = "pkarr")]
mod pkarr;

#[cfg(feature = "http")]
pub use http::HttpTransport;
#[cfg(all(feature = "fuzzing", feature = "http"))]
pub(crate) use http::{
    decode_empty_response, decode_mailbox_recv_response, decode_slot_get_response,
};
#[cfg(feature = "iroh")]
pub(crate) use iroh::IrohInitError;
#[cfg(feature = "iroh")]
pub use iroh::IrohTransport;
#[cfg(feature = "pkarr")]
pub use pkarr::PkarrTransport;

/// Threading marker that resolves to `Send + Sync` on native and is empty on
/// wasm32. Lets transport traits and trait objects compile under both targets
/// without duplicating bounds.
#[cfg(not(target_arch = "wasm32"))]
pub trait Threading: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> Threading for T {}

#[cfg(target_arch = "wasm32")]
pub trait Threading {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> Threading for T {}

#[cfg(not(target_arch = "wasm32"))]
pub type SlotWatchStream =
    Pin<Box<dyn Stream<Item = Result<(u64, Vec<u8>), TransportError>> + Send>>;
#[cfg(target_arch = "wasm32")]
pub type SlotWatchStream = Pin<Box<dyn Stream<Item = Result<(u64, Vec<u8>), TransportError>>>>;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait MailboxTransport: Threading {
    /// Pre-establishes any session state the transport needs to deliver
    /// messages on this channel without blocking the first send. The default
    /// implementation reports the operation as unsupported, which the
    /// coordinator treats as best-effort.
    async fn subscribe(&self, _id: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::Unsupported)
    }

    async fn send(&self, id: &[u8], sealed: &[u8]) -> Result<(), TransportError>;
    async fn recv(&self, id: &[u8], wait: Duration) -> Result<Option<Vec<u8>>, TransportError>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait SlotTransport: Threading {
    async fn put(&self, id: &[u8], version: u64, sealed: &[u8]) -> Result<(), TransportError>;
    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError>;
    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream;
}

pub trait Transport: MailboxTransport + SlotTransport {}

impl<T> Transport for T where T: MailboxTransport + SlotTransport {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub transports: Vec<TransportHealth>,
}

#[derive(Debug)]
pub(crate) struct HealthTracker {
    inner: Mutex<Vec<TrackedTransport>>,
}

#[derive(Debug)]
struct TrackedTransport {
    health: TransportHealth,
    poll_interval: Option<Duration>,
    last_success_instant: Option<Instant>,
}

impl HealthTracker {
    pub(crate) fn from_config(config: &Config) -> Self {
        let mut transports = Vec::with_capacity(config.transport_count());
        #[cfg(feature = "http")]
        if let Some(http) = &config.http {
            transports.push(TrackedTransport::new(
                TransportKind::Http,
                Some(Duration::from_secs(u64::from(http.long_poll_secs.max(1)))),
                vec![EndpointHealth::configured(http.url.to_string())],
            ));
        }
        #[cfg(feature = "pkarr")]
        if let Some(pkarr) = &config.pkarr {
            transports.push(TrackedTransport::new(
                TransportKind::Pkarr,
                Some(pkarr.republish_interval),
                pkarr_health_endpoints(pkarr),
            ));
        }
        #[cfg(feature = "iroh")]
        if let Some(iroh) = &config.iroh {
            let mut endpoints: Vec<EndpointHealth> = iroh
                .peers
                .iter()
                .flat_map(|peer| peer.relay_urls.iter().map(ToString::to_string))
                .map(EndpointHealth::configured)
                .collect();
            match &iroh.relay_mode {
                IrohRelayMode::Custom(urls) => endpoints.extend(
                    urls.iter()
                        .map(ToString::to_string)
                        .map(EndpointHealth::configured),
                ),
                IrohRelayMode::Default => {
                    endpoints.push(EndpointHealth::configured("default".to_owned()));
                }
                IrohRelayMode::Disabled => {}
            }
            transports.push(TrackedTransport::new(
                TransportKind::Iroh,
                Some(Duration::from_secs(30)),
                endpoints,
            ));
        }
        for transport in &config.transports {
            transports.push(TrackedTransport::new(transport.kind, None, Vec::new()));
        }
        Self {
            inner: Mutex::new(transports),
        }
    }

    pub(crate) fn snapshot(&self) -> HealthReport {
        let now = Instant::now();
        let transports = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|tracked| tracked.snapshot(now))
            .collect();
        HealthReport { transports }
    }

    pub(crate) fn record_success(&self, kind: TransportKind) {
        self.for_kind(kind, TrackedTransport::record_success);
    }

    pub(crate) fn record_failure(&self, kind: TransportKind) {
        self.for_kind(kind, TrackedTransport::record_failure);
    }

    #[cfg(all(test, feature = "http"))]
    fn force_last_success(&self, kind: TransportKind, age: Duration) {
        let now = Instant::now();
        let instant = now.checked_sub(age).unwrap_or(now);
        let system_now = SystemTime::now();
        let system_time = system_now
            .checked_sub(age)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        for tracked in self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter_mut()
            .filter(|tracked| tracked.health.kind == kind)
        {
            tracked.health.last_success = Some(system_time);
            tracked.last_success_instant = Some(instant);
        }
    }

    fn for_kind(&self, kind: TransportKind, f: impl Fn(&mut TrackedTransport)) {
        for tracked in self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter_mut()
            .filter(|tracked| tracked.health.kind == kind)
        {
            f(tracked);
        }
    }
}

#[cfg(feature = "pkarr")]
fn pkarr_health_endpoints(config: &PkarrConfig) -> Vec<EndpointHealth> {
    let mut endpoints = Vec::new();
    if matches!(
        config.network,
        PkarrNetworkMode::Relays | PkarrNetworkMode::Both
    ) {
        endpoints.extend(
            config
                .effective_resolvers()
                .into_iter()
                .map(EndpointHealth::configured),
        );
    }
    if matches!(
        config.network,
        PkarrNetworkMode::Dht | PkarrNetworkMode::Both
    ) {
        if config.bootstrap.is_empty() {
            endpoints.push(EndpointHealth::configured("mainline-dht".to_owned()));
        } else {
            endpoints.extend(
                config
                    .bootstrap
                    .iter()
                    .map(ToString::to_string)
                    .map(EndpointHealth::configured),
            );
        }
    }
    endpoints
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthTransitionKind {
    BecameHealthy,
    BecameDegraded,
    BecameDown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthTransition {
    pub kind: HealthTransitionKind,
    pub from: HealthState,
    pub to: HealthState,
    pub at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHealth {
    pub endpoint: String,
    pub state: HealthState,
}

impl EndpointHealth {
    #[cfg(any(feature = "http", feature = "pkarr", feature = "iroh"))]
    fn configured(endpoint: String) -> Self {
        Self {
            endpoint,
            state: HealthState::Healthy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportHealth {
    pub kind: TransportKind,
    pub configured: bool,
    pub state: HealthState,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
    pub last_success: Option<SystemTime>,
    pub last_failure: Option<SystemTime>,
    pub transitions: Vec<HealthTransition>,
    pub endpoints: Vec<EndpointHealth>,
}

impl TrackedTransport {
    fn new(
        kind: TransportKind,
        poll_interval: Option<Duration>,
        endpoints: Vec<EndpointHealth>,
    ) -> Self {
        Self {
            health: TransportHealth {
                kind,
                configured: true,
                state: HealthState::Healthy,
                consecutive_successes: 0,
                consecutive_failures: 0,
                last_success: None,
                last_failure: None,
                transitions: Vec::new(),
                endpoints,
            },
            poll_interval,
            last_success_instant: None,
        }
    }

    fn snapshot(&self, now: Instant) -> TransportHealth {
        let mut health = self.health.clone();
        if let Some(last_success) = self.last_success_instant {
            let age = now.saturating_duration_since(last_success);
            if age >= Duration::from_mins(5) {
                health.state = HealthState::Down;
            } else if self
                .poll_interval
                .is_some_and(|interval| age >= interval.saturating_mul(2))
            {
                health.state = HealthState::Degraded;
            }
        }
        for endpoint in &mut health.endpoints {
            endpoint.state = health.state;
        }
        health
    }

    fn record_success(&mut self) {
        self.health.last_success = Some(SystemTime::now());
        self.last_success_instant = Some(Instant::now());
        self.health.consecutive_successes = self.health.consecutive_successes.saturating_add(1);
        self.health.consecutive_failures = 0;
        match self.health.state {
            HealthState::Down => self.transition(HealthState::Degraded),
            HealthState::Degraded if self.health.consecutive_successes >= 3 => {
                self.transition(HealthState::Healthy);
            }
            HealthState::Healthy | HealthState::Degraded => {}
        }
    }

    fn record_failure(&mut self) {
        self.health.last_failure = Some(SystemTime::now());
        self.health.consecutive_failures = self.health.consecutive_failures.saturating_add(1);
        self.health.consecutive_successes = 0;
        match self.health.state {
            HealthState::Healthy => self.transition(HealthState::Degraded),
            HealthState::Degraded if self.health.consecutive_failures >= 3 => {
                self.transition(HealthState::Down);
            }
            HealthState::Degraded | HealthState::Down => {}
        }
    }

    fn transition(&mut self, to: HealthState) {
        if self.health.state == to {
            return;
        }
        let from = self.health.state;
        self.health.state = to;
        if self.health.transitions.len() == 64 {
            self.health.transitions.remove(0);
        }
        self.health.transitions.push(HealthTransition {
            kind: match to {
                HealthState::Healthy => HealthTransitionKind::BecameHealthy,
                HealthState::Degraded => HealthTransitionKind::BecameDegraded,
                HealthState::Down => HealthTransitionKind::BecameDown,
            },
            from,
            to,
            at: SystemTime::now(),
        });
    }
}

#[cfg(all(test, any(feature = "http", feature = "pkarr")))]
mod health_tests {
    use super::*;

    #[cfg(feature = "http")]
    use crate::config::HttpConfig;
    #[cfg(feature = "http")]
    use url::Url;

    #[test]
    #[cfg(feature = "http")]
    fn health_records_failure_and_recovery_transitions() {
        let config = Config {
            http: Some(HttpConfig::new(Url::parse("https://198.51.100.1").unwrap())),
            ..Config::default()
        };
        let tracker = HealthTracker::from_config(&config);

        tracker.record_failure(TransportKind::Http);
        tracker.record_failure(TransportKind::Http);
        tracker.record_failure(TransportKind::Http);

        let report = tracker.snapshot();
        assert_eq!(report.transports[0].state, HealthState::Down);
        assert_eq!(report.transports[0].transitions.len(), 2);
        assert_eq!(
            report.transports[0].transitions[0].kind,
            HealthTransitionKind::BecameDegraded
        );
        assert_eq!(
            report.transports[0].transitions[1].kind,
            HealthTransitionKind::BecameDown
        );

        tracker.record_success(TransportKind::Http);
        tracker.record_success(TransportKind::Http);
        tracker.record_success(TransportKind::Http);

        let report = tracker.snapshot();
        assert_eq!(report.transports[0].state, HealthState::Healthy);
        assert_eq!(report.transports[0].consecutive_successes, 3);
    }

    #[test]
    #[cfg(feature = "http")]
    fn health_snapshot_applies_staleness_windows() {
        let config = Config {
            http: Some(HttpConfig::new(Url::parse("https://198.51.100.1").unwrap())),
            ..Config::default()
        };
        let tracker = HealthTracker::from_config(&config);

        tracker.record_success(TransportKind::Http);
        tracker.force_last_success(TransportKind::Http, Duration::from_mins(1));
        assert_eq!(
            tracker.snapshot().transports[0].state,
            HealthState::Degraded
        );

        tracker.force_last_success(TransportKind::Http, Duration::from_mins(5));
        assert_eq!(tracker.snapshot().transports[0].state, HealthState::Down);
    }

    #[test]
    #[cfg(feature = "pkarr")]
    fn pkarr_health_reports_resolver_endpoints() {
        let config = Config {
            pkarr: Some(crate::config::PkarrConfig::default()),
            ..Config::default()
        };
        let report = HealthTracker::from_config(&config).snapshot();

        assert_eq!(report.transports[0].kind, TransportKind::Pkarr);
        assert!(!report.transports[0].endpoints.is_empty());
        assert!(
            report.transports[0]
                .endpoints
                .iter()
                .all(|endpoint| endpoint.state == HealthState::Healthy)
        );
    }

    #[test]
    #[cfg(feature = "pkarr")]
    fn pkarr_dht_health_reports_dht_endpoint() {
        let config = Config {
            pkarr: Some(crate::config::PkarrConfig {
                network: crate::config::PkarrNetworkMode::Dht,
                ..crate::config::PkarrConfig::default()
            }),
            ..Config::default()
        };
        let report = HealthTracker::from_config(&config).snapshot();

        assert_eq!(report.transports[0].kind, TransportKind::Pkarr);
        assert_eq!(report.transports[0].endpoints[0].endpoint, "mainline-dht");
    }

    #[test]
    #[cfg(feature = "pkarr")]
    fn pkarr_both_health_reports_relays_and_bootstrap() {
        let bootstrap = "203.0.113.7:6881".parse().unwrap();
        let config = Config {
            pkarr: Some(crate::config::PkarrConfig {
                network: crate::config::PkarrNetworkMode::Both,
                resolvers: vec!["https://relay.example".to_owned()],
                bootstrap: vec![bootstrap],
                ..crate::config::PkarrConfig::default()
            }),
            ..Config::default()
        };
        let endpoints = HealthTracker::from_config(&config).snapshot().transports[0]
            .endpoints
            .clone();

        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].endpoint, "https://relay.example");
        assert_eq!(endpoints[1].endpoint, bootstrap.to_string());
    }
}
