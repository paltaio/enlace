use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use url::Url;

use crate::TransportKind;
use crate::dedup;
use crate::state::State;
use crate::transports::Transport;

pub const DEFAULT_MAX_PLAINTEXT_BYTES: usize = 65_536;
pub const DEFAULT_LONG_POLL_SECS: u32 = 25;
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_mins(30);
pub const DEFAULT_PKARR_RELAYS: &[&str] = &[
    "https://relay.pkarr.org",
    "https://pkarr.pubky.org",
    "https://pkarr.pubky.app",
];
pub const DEFAULT_PKARR_REQUEST_TIMEOUT: Duration = Duration::ZERO;
pub const DEFAULT_IROH_MAX_MESSAGE_BYTES: usize = DEFAULT_MAX_PLAINTEXT_BYTES + 4096;
pub const DEFAULT_IROH_MAX_STREAMS_PER_PEER: u32 = 32;
pub const DEFAULT_IROH_MAX_CONNS_PER_PEER: u32 = 4;

pub struct Config {
    #[cfg(feature = "http")]
    pub http: Option<HttpConfig>,
    #[cfg(feature = "pkarr")]
    pub pkarr: Option<PkarrConfig>,
    #[cfg(feature = "iroh")]
    pub iroh: Option<IrohConfig>,
    pub signing: Option<SigningKey>,
    pub trusted: Vec<VerifyingKey>,
    pub dedup_buffer: usize,
    pub max_plaintext_bytes: usize,
    pub state: State,
    pub transports: Vec<ConfiguredTransport>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            #[cfg(feature = "http")]
            http: None,
            #[cfg(feature = "pkarr")]
            pkarr: None,
            #[cfg(feature = "iroh")]
            iroh: None,
            signing: None,
            trusted: Vec::new(),
            dedup_buffer: dedup::DEFAULT_CAPACITY,
            max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
            state: State::memory(),
            transports: Vec::new(),
        }
    }
}

impl Config {
    pub(crate) fn transport_count(&self) -> usize {
        let count = self.transports.len();
        #[cfg(feature = "http")]
        let count = count + usize::from(self.http.is_some());
        #[cfg(feature = "pkarr")]
        let count = count + usize::from(self.pkarr.is_some());
        #[cfg(feature = "iroh")]
        let count = count + usize::from(self.iroh.is_some());
        count
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
#[cfg(feature = "http")]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
#[cfg(feature = "http")]
pub struct HttpConfig {
    pub url: Url,
    pub skip_verify: bool,
    pub auth: Option<BasicAuth>,
    pub long_poll_secs: u32,
}

#[cfg(feature = "http")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg(feature = "pkarr")]
pub enum PkarrNetworkMode {
    /// Publish and resolve through pkarr HTTP relays only.
    #[default]
    Relays,
    /// Publish and resolve through the native Mainline DHT only.
    Dht,
    /// Use relays and DHT in parallel.
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "pkarr")]
pub struct PkarrConfig {
    pub network: PkarrNetworkMode,
    pub resolvers: Vec<String>,
    pub bootstrap: Vec<SocketAddr>,
    /// Zero preserves pkarr's upstream client default.
    pub request_timeout: Duration,
    pub republish_interval: Duration,
}

#[cfg(feature = "pkarr")]
impl Default for PkarrConfig {
    fn default() -> Self {
        Self {
            network: PkarrNetworkMode::Relays,
            resolvers: DEFAULT_PKARR_RELAYS
                .iter()
                .map(|url| (*url).to_owned())
                .collect(),
            bootstrap: Vec::new(),
            request_timeout: DEFAULT_PKARR_REQUEST_TIMEOUT,
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
        }
    }
}

#[cfg(feature = "pkarr")]
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

    #[must_use]
    pub fn effective_bootstrap(&self) -> Vec<SocketAddr> {
        self.bootstrap.clone()
    }
}

#[cfg(all(test, any(feature = "pkarr", feature = "iroh")))]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "pkarr")]
    fn pkarr_default_resolvers_are_public_relays() {
        let config = PkarrConfig::default();

        assert_eq!(config.resolvers, config.effective_resolvers());
        assert_eq!(config.resolvers.len(), DEFAULT_PKARR_RELAYS.len());
        for resolver in config.resolvers {
            assert!(resolver.starts_with("https://"));
        }
    }

    #[test]
    #[cfg(feature = "pkarr")]
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
    #[cfg(feature = "pkarr")]
    fn pkarr_configured_resolvers_are_preserved() {
        let config = PkarrConfig {
            resolvers: vec!["http://127.0.0.1:8080".to_owned()],
            ..PkarrConfig::default()
        };

        assert_eq!(config.effective_resolvers(), config.resolvers);
    }

    #[test]
    #[cfg(feature = "pkarr")]
    fn pkarr_default_request_timeout_uses_upstream_default() {
        let config = PkarrConfig::default();

        assert_eq!(config.request_timeout, Duration::ZERO);
    }

    #[test]
    #[cfg(feature = "iroh")]
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
#[cfg(feature = "iroh")]
pub struct IrohConfig {
    pub relay_mode: IrohRelayMode,
    pub bind_addrs: Vec<SocketAddr>,
    pub peers: Vec<IrohEndpointAddr>,
    pub max_message_bytes: usize,
    pub max_streams_per_peer: u32,
    pub max_conns_per_peer: u32,
}

#[cfg(feature = "iroh")]
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
#[cfg(feature = "iroh")]
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
