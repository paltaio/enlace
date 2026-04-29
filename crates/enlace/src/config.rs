use std::net::SocketAddr;
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

#[derive(Clone, PartialEq, Eq)]
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
            resolvers: Vec::new(),
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtConfig {
    pub bootstrap: Vec<SocketAddr>,
    pub republish_interval: Duration,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bootstrap: Vec::new(),
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohConfig {
    pub relays: Vec<Url>,
    pub max_streams_per_peer: u32,
    pub max_conns_per_peer: u32,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            max_streams_per_peer: DEFAULT_IROH_MAX_STREAMS_PER_PEER,
            max_conns_per_peer: DEFAULT_IROH_MAX_CONNS_PER_PEER,
        }
    }
}
