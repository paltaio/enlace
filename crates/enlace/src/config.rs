use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use url::Url;

use crate::TransportKind;
use crate::dedup;
use crate::state::StateStore;
use crate::transports::Transport;

pub const DEFAULT_MAX_PLAINTEXT_BYTES: usize = 65_536;
pub const DEFAULT_LONG_POLL_SECS: u32 = 25;
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_mins(30);
pub const DEFAULT_DHT_WATCH_POLL_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_DHT_BOOTSTRAP_CACHE_TTL: Duration = Duration::from_hours(24);
pub const DEFAULT_DHT_BOOTSTRAP_CACHE_MAX_PEERS: usize = 64;
pub const DEFAULT_PKARR_RELAYS: &[&str] = &[
    "https://relay.pkarr.org",
    "https://pkarr.pubky.org",
    "https://pkarr.pubky.app",
];
pub const DEFAULT_IROH_MAX_MESSAGE_BYTES: usize = DEFAULT_MAX_PLAINTEXT_BYTES + 4096;
pub const DEFAULT_IROH_MAX_STREAMS_PER_PEER: u32 = 32;
pub const DEFAULT_IROH_MAX_CONNS_PER_PEER: u32 = 4;

pub struct Config {
    pub http: Option<HttpConfig>,
    pub pkarr: Option<PkarrConfig>,
    pub dht: Option<DhtConfig>,
    pub iroh: Option<IrohConfig>,
    pub signing: Option<SigningKey>,
    pub trusted: Vec<VerifyingKey>,
    pub dedup_buffer: usize,
    pub max_plaintext_bytes: usize,
    pub state: Option<Arc<dyn StateStore>>,
    pub transports: Vec<ConfiguredTransport>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: None,
            pkarr: None,
            dht: None,
            iroh: None,
            signing: None,
            trusted: Vec::new(),
            dedup_buffer: dedup::DEFAULT_CAPACITY,
            max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
            state: None,
            transports: Vec::new(),
        }
    }
}

impl Config {
    pub(crate) fn transport_count(&self) -> usize {
        usize::from(self.http.is_some())
            + usize::from(self.pkarr.is_some())
            + usize::from(self.dht.is_some())
            + usize::from(self.iroh.is_some())
            + self.transports.len()
    }
}

#[derive(Clone)]
pub struct ConfiguredTransport {
    pub kind: TransportKind,
    pub transport: Arc<dyn Transport>,
}

impl ConfiguredTransport {
    #[must_use]
    pub fn new(kind: TransportKind, transport: Arc<dyn Transport>) -> Self {
        Self { kind, transport }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct HttpConfig {
    pub url: Url,
    pub skip_verify: bool,
    pub auth: Option<BasicAuth>,
    pub long_poll_secs: u32,
}

impl HttpConfig {
    #[must_use]
    pub fn new(url: Url) -> Self {
        Self {
            url,
            skip_verify: false,
            auth: None,
            long_poll_secs: DEFAULT_LONG_POLL_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkarrConfig {
    pub resolvers: Vec<String>,
    pub republish_interval: Duration,
}

impl Default for PkarrConfig {
    fn default() -> Self {
        Self {
            resolvers: DEFAULT_PKARR_RELAYS
                .iter()
                .map(|url| (*url).to_owned())
                .collect(),
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
        }
    }
}

impl PkarrConfig {
    #[must_use]
    pub fn effective_resolvers(&self) -> Vec<String> {
        if self.resolvers.is_empty() {
            DEFAULT_PKARR_RELAYS
                .iter()
                .map(|url| (*url).to_owned())
                .collect()
        } else {
            self.resolvers.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkarr_default_resolvers_are_public_relays() {
        let config = PkarrConfig::default();

        assert_eq!(config.resolvers, config.effective_resolvers());
        assert_eq!(config.resolvers.len(), DEFAULT_PKARR_RELAYS.len());
        for resolver in config.resolvers {
            assert!(resolver.starts_with("https://"));
        }
    }

    #[test]
    fn pkarr_empty_resolvers_fall_back_to_defaults() {
        let config = PkarrConfig {
            resolvers: Vec::new(),
            ..PkarrConfig::default()
        };

        assert_eq!(
            config.effective_resolvers(),
            DEFAULT_PKARR_RELAYS
                .iter()
                .map(|url| (*url).to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn pkarr_configured_resolvers_are_preserved() {
        let config = PkarrConfig {
            resolvers: vec!["http://127.0.0.1:8080".to_owned()],
            ..PkarrConfig::default()
        };

        assert_eq!(config.effective_resolvers(), config.resolvers);
    }

    #[test]
    fn dht_bootstrap_cache_defaults_are_bounded() {
        let config = DhtBootstrapCacheConfig::new("bootstrap.txt".into());

        assert_eq!(config.ttl, DEFAULT_DHT_BOOTSTRAP_CACHE_TTL);
        assert_eq!(config.max_peers, DEFAULT_DHT_BOOTSTRAP_CACHE_MAX_PEERS);
    }

    #[test]
    fn iroh_defaults_match_realtime_transport_shape() {
        let config = IrohConfig::default();

        assert_eq!(config.relay_mode, IrohRelayMode::Default);
        assert!(config.bind_addrs.is_empty());
        assert!(config.peers.is_empty());
        assert_eq!(config.max_message_bytes, DEFAULT_IROH_MAX_MESSAGE_BYTES);
        assert_eq!(
            config.max_streams_per_peer,
            DEFAULT_IROH_MAX_STREAMS_PER_PEER
        );
        assert_eq!(config.max_conns_per_peer, DEFAULT_IROH_MAX_CONNS_PER_PEER);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtConfig {
    pub bootstrap: Vec<SocketAddr>,
    pub watch_poll_interval: Duration,
    pub bootstrap_cache: Option<DhtBootstrapCacheConfig>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bootstrap: Vec::new(),
            watch_poll_interval: DEFAULT_DHT_WATCH_POLL_INTERVAL,
            bootstrap_cache: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtBootstrapCacheConfig {
    pub path: PathBuf,
    pub ttl: Duration,
    pub max_peers: usize,
}

impl DhtBootstrapCacheConfig {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            ttl: DEFAULT_DHT_BOOTSTRAP_CACHE_TTL,
            max_peers: DEFAULT_DHT_BOOTSTRAP_CACHE_MAX_PEERS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohConfig {
    pub relay_mode: IrohRelayMode,
    pub bind_addrs: Vec<SocketAddr>,
    pub peers: Vec<IrohEndpointAddr>,
    pub max_message_bytes: usize,
    pub max_streams_per_peer: u32,
    pub max_conns_per_peer: u32,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            relay_mode: IrohRelayMode::Default,
            bind_addrs: Vec::new(),
            peers: Vec::new(),
            max_message_bytes: DEFAULT_IROH_MAX_MESSAGE_BYTES,
            max_streams_per_peer: DEFAULT_IROH_MAX_STREAMS_PER_PEER,
            max_conns_per_peer: DEFAULT_IROH_MAX_CONNS_PER_PEER,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrohRelayMode {
    Default,
    Custom(Vec<Url>),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohEndpointAddr {
    pub endpoint_id: [u8; 32],
    pub relay_urls: Vec<Url>,
    pub direct_addrs: Vec<SocketAddr>,
}
