use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{
    AfterHandshakeOutcome, ConnectionInfo, EndpointHooks, QuicTransportConfig, VarInt, presets,
};
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, TransportAddr};
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::{Gossip, TopicId};
use tokio::sync::{Notify, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;

use crate::config::{IrohConfig, IrohEndpointAddr, IrohRelayMode};
use crate::error::TransportError;
use crate::state::{StateError, StateStore};
use crate::transports::{MailboxTransport, SlotTransport, SlotWatchStream};

const WATCH_BUFFER: usize = 64;
const SLOT_HEADER_LEN: usize = 8;
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct IrohTransport {
    inner: Arc<IrohInner>,
}

struct IrohInner {
    endpoint: Endpoint,
    gossip: Gossip,
    _router: Router,
    memory_lookup: MemoryLookup,
    endpoint_id: [u8; 32],
    peers: RwLock<Vec<IrohEndpointAddr>>,
    allowed_endpoints: Option<Arc<RwLock<HashSet<EndpointId>>>>,
    topics: Mutex<HashMap<Vec<u8>, Arc<TopicState>>>,
}

#[derive(Debug, Clone)]
struct ConnLimitHook {
    max_conns_per_peer: u32,
    allowed_endpoints: Option<Arc<RwLock<HashSet<EndpointId>>>>,
    active: Arc<Mutex<HashMap<EndpointId, u32>>>,
}

struct TopicState {
    sender: GossipSender,
    mailbox: Mutex<VecDeque<Vec<u8>>>,
    mailbox_notify: Notify,
    slot: RwLock<Option<(u64, Vec<u8>)>>,
    slot_updates: broadcast::Sender<(u64, Vec<u8>)>,
    task: JoinHandle<()>,
}

#[derive(Debug)]
pub(crate) enum IrohInitError {
    State(StateError),
    Transport(TransportError),
}

impl fmt::Display for IrohInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(err) => write!(f, "{err}"),
            Self::Transport(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for IrohInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(err) => Some(err),
            Self::Transport(err) => Some(err),
        }
    }
}

impl From<StateError> for IrohInitError {
    fn from(err: StateError) -> Self {
        Self::State(err)
    }
}

impl From<TransportError> for IrohInitError {
    fn from(err: TransportError) -> Self {
        Self::Transport(err)
    }
}

impl IrohTransport {
    pub(crate) async fn new(
        config: &IrohConfig,
        state: &dyn StateStore,
    ) -> Result<Self, IrohInitError> {
        Self::new_with_allowed_endpoints(config, state, None).await
    }

    pub(crate) async fn new_with_allowed_endpoints(
        config: &IrohConfig,
        state: &dyn StateStore,
        allowed: Option<Vec<[u8; 32]>>,
    ) -> Result<Self, IrohInitError> {
        let secret_key = if let Some(secret) = state.iroh_keypair()? {
            iroh::SecretKey::from_bytes(&secret)
        } else {
            let secret_key = iroh::SecretKey::generate();
            state.store_iroh_keypair(&secret_key.to_bytes())?;
            secret_key
        };
        let endpoint_id = *secret_key.public().as_bytes();
        let memory_lookup = MemoryLookup::new();
        for peer in &config.peers {
            memory_lookup.add_endpoint_info(endpoint_addr(peer)?);
        }
        let allowed_endpoints = allowed
            .map(|endpoints| {
                endpoints
                    .into_iter()
                    .map(|endpoint| endpoint_id_from_bytes(&endpoint))
                    .collect::<Result<HashSet<_>, _>>()
                    .map(|endpoints| Arc::new(RwLock::new(endpoints)))
            })
            .transpose()?;

        let endpoint = bind_endpoint(
            config,
            secret_key,
            memory_lookup.clone(),
            allowed_endpoints.clone(),
        )
        .await?;
        let gossip = Gossip::builder()
            .max_message_size(config.max_message_bytes)
            .spawn(endpoint.clone());
        let router = Router::builder(endpoint.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        Ok(Self {
            inner: Arc::new(IrohInner {
                endpoint,
                gossip,
                _router: router,
                memory_lookup,
                endpoint_id,
                peers: RwLock::new(config.peers.clone()),
                allowed_endpoints,
                topics: Mutex::new(HashMap::new()),
            }),
        })
    }

    #[must_use]
    pub fn endpoint_id(&self) -> [u8; 32] {
        self.inner.endpoint_id
    }

    #[must_use]
    pub fn endpoint_addr(&self) -> IrohEndpointAddr {
        endpoint_addr_to_config(&self.inner.endpoint.addr())
    }

    #[must_use]
    pub fn peers(&self) -> Vec<IrohEndpointAddr> {
        self.inner
            .peers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn add_peer(&self, peer: IrohEndpointAddr) {
        self.add_peer_addr(peer);
    }

    pub fn remove_peer(&self, endpoint_id: [u8; 32]) -> bool {
        let removed = {
            let mut peers = self
                .inner
                .peers
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let old_len = peers.len();
            peers.retain(|peer| peer.endpoint_id != endpoint_id);
            peers.len() != old_len
        };
        if removed {
            self.reset_topics();
        }
        removed
    }

    pub(crate) fn allow_peer(&self, peer: IrohEndpointAddr) {
        if let Some(allowed) = &self.inner.allowed_endpoints
            && let Ok(endpoint) = endpoint_id_from_bytes(&peer.endpoint_id)
        {
            allowed
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(endpoint);
        }
        self.add_peer_addr(peer);
    }

    pub(crate) fn revoke_peer(&self, endpoint_id: [u8; 32]) {
        if let Some(allowed) = &self.inner.allowed_endpoints
            && let Ok(endpoint) = endpoint_id_from_bytes(&endpoint_id)
        {
            allowed
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&endpoint);
        }
        self.remove_peer(endpoint_id);
        self.reset_topics();
    }

    fn add_peer_addr(&self, peer: IrohEndpointAddr) {
        if let Ok(addr) = endpoint_addr(&peer) {
            self.inner.memory_lookup.add_endpoint_info(addr);
        }

        let mut peers = self
            .inner
            .peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = peers
            .iter_mut()
            .find(|existing| existing.endpoint_id == peer.endpoint_id)
        {
            *existing = peer;
        } else {
            peers.push(peer);
        }
    }

    fn reset_topics(&self) {
        self.inner
            .topics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    async fn ensure_topic(
        &self,
        id: &[u8],
        wait_for_join: bool,
    ) -> Result<Arc<TopicState>, TransportError> {
        if let Some(topic) = self
            .inner
            .topics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
        {
            return Ok(topic);
        }

        let topic_id = topic_id(id)?;
        let bootstrap = self.bootstrap_peers();
        let has_bootstrap = !bootstrap.is_empty();
        let mut topic = self
            .inner
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(map_gossip_error)?;
        if wait_for_join && has_bootstrap {
            timeout(JOIN_TIMEOUT, topic.joined())
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(map_gossip_error)?;
        }
        let (sender, mut receiver) = topic.split();
        let (slot_updates, _) = broadcast::channel(WATCH_BUFFER);
        let state = Arc::new_cyclic(|weak: &std::sync::Weak<TopicState>| {
            let weak = weak.clone();
            let task = tokio::spawn(async move {
                while let Some(event) = receiver.next().await {
                    let Ok(Event::Received(message)) = event else {
                        continue;
                    };
                    if let Some(state) = weak.upgrade() {
                        state.record_mailbox(message.content.to_vec());
                        if let Some((version, sealed)) = decode_slot_frame(&message.content) {
                            state.record_slot(version, sealed);
                        }
                    } else {
                        break;
                    }
                }
            });
            TopicState {
                sender,
                mailbox: Mutex::new(VecDeque::new()),
                mailbox_notify: Notify::new(),
                slot: RwLock::new(None),
                slot_updates,
                task,
            }
        });

        let mut topics = self
            .inner
            .topics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(topics.entry(id.to_vec()).or_insert(state).clone())
    }

    fn bootstrap_peers(&self) -> Vec<EndpointId> {
        self.peers()
            .into_iter()
            .filter_map(|peer| EndpointId::from_bytes(&peer.endpoint_id).ok())
            .collect()
    }
}

impl fmt::Debug for IrohTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohTransport")
            .field("endpoint_id", &self.endpoint_id())
            .field("endpoint_addr", &self.endpoint_addr())
            .field("peers", &self.peers())
            .finish_non_exhaustive()
    }
}

impl Drop for TopicState {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TopicState {
    async fn recv_mailbox(&self, wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        let deadline = Instant::now() + wait;
        loop {
            let notified = self.mailbox_notify.notified();
            {
                let mut mailbox = self
                    .mailbox
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(sealed) = mailbox.pop_front() {
                    return Ok(Some(sealed));
                }
            }

            if wait.is_zero() {
                return Ok(None);
            }
            if timeout_at(deadline, notified).await.is_err() {
                return Ok(None);
            }
        }
    }

    fn record_mailbox(&self, sealed: Vec<u8>) {
        self.mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(sealed);
        self.mailbox_notify.notify_waiters();
    }

    fn record_slot(&self, version: u64, sealed: Vec<u8>) {
        let mut slot = self
            .slot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot
            .as_ref()
            .is_some_and(|(current_version, current_sealed)| {
                (version, sealed.as_slice()) <= (*current_version, current_sealed.as_slice())
            })
        {
            return;
        }
        *slot = Some((version, sealed.clone()));
        drop(slot);
        let _ = self.slot_updates.send((version, sealed));
    }

    fn current_slot(&self) -> Option<(u64, Vec<u8>)> {
        self.slot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl MailboxTransport for IrohTransport {
    async fn send(&self, id: &[u8], sealed: &[u8]) -> Result<(), TransportError> {
        let topic = self.ensure_topic(id, true).await?;
        topic
            .sender
            .broadcast(sealed.to_vec().into())
            .await
            .map_err(map_gossip_error)
    }

    async fn recv(&self, id: &[u8], wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        let topic = self.ensure_topic(id, false).await?;
        topic.recv_mailbox(wait).await
    }
}

#[async_trait]
impl SlotTransport for IrohTransport {
    async fn put(&self, id: &[u8], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        let topic = self.ensure_topic(id, true).await?;
        let frame = encode_slot_frame(version, sealed);
        topic.record_slot(version, sealed.to_vec());
        topic
            .sender
            .broadcast(frame.into())
            .await
            .map_err(map_gossip_error)
    }

    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let topic = self.ensure_topic(id, false).await?;
        Ok(topic.current_slot())
    }

    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream {
        let transport = self.clone();
        let id = id.to_vec();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);

        tokio::spawn(async move {
            let topic = match transport.ensure_topic(&id, false).await {
                Ok(topic) => topic,
                Err(err) => {
                    let _ = tx.send(Err(err)).await;
                    return;
                }
            };

            let mut since = since;
            if let Some((version, sealed)) = topic.current_slot()
                && version > since
            {
                since = version;
                if tx.send(Ok((version, sealed))).await.is_err() {
                    return;
                }
            }

            let mut updates = topic.slot_updates.subscribe();
            loop {
                match updates.recv().await {
                    Ok((version, sealed)) if version > since => {
                        since = version;
                        if tx.send(Ok((version, sealed))).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}

async fn bind_endpoint(
    config: &IrohConfig,
    secret_key: iroh::SecretKey,
    memory_lookup: MemoryLookup,
    allowed_endpoints: Option<Arc<RwLock<HashSet<EndpointId>>>>,
) -> Result<Endpoint, TransportError> {
    let stream_cap = VarInt::from_u32(config.max_streams_per_peer);
    let transport_config = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(stream_cap)
        .max_concurrent_uni_streams(stream_cap)
        .build();
    let conn_limit = ConnLimitHook {
        max_conns_per_peer: config.max_conns_per_peer,
        allowed_endpoints,
        active: Arc::new(Mutex::new(HashMap::new())),
    };
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .address_lookup(memory_lookup)
        .relay_mode(relay_mode(&config.relay_mode))
        .transport_config(transport_config)
        .hooks(conn_limit);

    if !config.bind_addrs.is_empty() {
        builder = builder.clear_ip_transports();
        for addr in &config.bind_addrs {
            builder = builder
                .bind_addr(*addr)
                .map_err(|err| TransportError::Other(Box::new(err)))?;
        }
    }

    builder
        .bind()
        .await
        .map_err(|err| TransportError::Other(Box::new(err)))
}

impl EndpointHooks for ConnLimitHook {
    async fn after_handshake<'a>(&'a self, conn: &'a ConnectionInfo) -> AfterHandshakeOutcome {
        let peer = conn.remote_id();
        if let Some(allowed) = &self.allowed_endpoints
            && !allowed
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&peer)
        {
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(403),
                reason: b"endpoint not trusted".to_vec(),
            };
        }
        {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = active.entry(peer).or_default();
            if *count >= self.max_conns_per_peer {
                return AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(0),
                    reason: b"too many connections".to_vec(),
                };
            }
            *count += 1;
        }

        let active = Arc::clone(&self.active);
        let conn = conn.clone();
        tokio::spawn(async move {
            let _ = conn.closed().await;
            let mut active = active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(count) = active.get_mut(&peer) else {
                return;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&peer);
            }
        });

        AfterHandshakeOutcome::Accept
    }
}

fn relay_mode(mode: &IrohRelayMode) -> RelayMode {
    match mode {
        IrohRelayMode::Default => RelayMode::Default,
        IrohRelayMode::Custom(urls) => RelayMode::custom(urls.iter().cloned().map(RelayUrl::from)),
        IrohRelayMode::Disabled => RelayMode::Disabled,
    }
}

fn topic_id(id: &[u8]) -> Result<TopicId, TransportError> {
    let id: [u8; 32] = id
        .try_into()
        .map_err(|_| TransportError::Network("iroh topic id must be 32 bytes".to_owned()))?;
    Ok(TopicId::from_bytes(id))
}

fn endpoint_id_from_bytes(id: &[u8; 32]) -> Result<EndpointId, TransportError> {
    EndpointId::from_bytes(id)
        .map_err(|_| TransportError::Network("invalid iroh endpoint id".to_owned()))
}

fn endpoint_addr(peer: &IrohEndpointAddr) -> Result<EndpointAddr, TransportError> {
    let id = endpoint_id_from_bytes(&peer.endpoint_id)?;
    let addrs = peer
        .relay_urls
        .iter()
        .cloned()
        .map(RelayUrl::from)
        .map(TransportAddr::Relay)
        .chain(peer.direct_addrs.iter().copied().map(TransportAddr::Ip));
    Ok(EndpointAddr::from_parts(id, addrs))
}

fn endpoint_addr_to_config(addr: &EndpointAddr) -> IrohEndpointAddr {
    IrohEndpointAddr {
        endpoint_id: *addr.id.as_bytes(),
        relay_urls: addr
            .relay_urls()
            .cloned()
            .map(url::Url::from)
            .collect::<Vec<_>>(),
        direct_addrs: addr.ip_addrs().copied().collect(),
    }
}

fn encode_slot_frame(version: u64, sealed: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SLOT_HEADER_LEN + sealed.len());
    frame.extend_from_slice(&version.to_be_bytes());
    frame.extend_from_slice(sealed);
    frame
}

fn decode_slot_frame(frame: &[u8]) -> Option<(u64, Vec<u8>)> {
    let (version, sealed) = frame.split_at_checked(SLOT_HEADER_LEN)?;
    let version = u64::from_be_bytes(version.try_into().ok()?);
    Some((version, sealed.to_vec()))
}

fn map_gossip_error(err: iroh_gossip::api::ApiError) -> TransportError {
    TransportError::Other(Box::new(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::state::InMemoryStateStore;

    #[tokio::test]
    async fn endpoint_id_comes_from_persisted_keypair() {
        let state = InMemoryStateStore::new();
        let first = IrohTransport::new(&IrohConfig::default(), &state)
            .await
            .unwrap();
        let second = IrohTransport::new(&IrohConfig::default(), &state)
            .await
            .unwrap();

        assert_eq!(first.endpoint_id(), second.endpoint_id());
        assert_eq!(first.endpoint_addr().endpoint_id, first.endpoint_id());
    }

    #[tokio::test]
    async fn peers_can_be_seeded_and_replaced() {
        let peer_id = *iroh::SecretKey::generate().public().as_bytes();
        let original = IrohEndpointAddr {
            endpoint_id: peer_id,
            relay_urls: vec![url::Url::parse("https://relay.example").unwrap()],
            direct_addrs: Vec::new(),
        };
        let state = InMemoryStateStore::new();
        let config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            peers: vec![original],
            max_message_bytes: 1024,
            max_streams_per_peer: 2,
            max_conns_per_peer: 1,
        };
        let transport = IrohTransport::new(&config, &state).await.unwrap();

        assert_eq!(transport.peers().len(), 1);

        transport.add_peer(IrohEndpointAddr {
            endpoint_id: peer_id,
            relay_urls: Vec::new(),
            direct_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)],
        });

        let peers = transport.peers();
        assert_eq!(peers.len(), 1);
        assert!(peers[0].relay_urls.is_empty());
        assert_eq!(peers[0].direct_addrs.len(), 1);
    }

    #[tokio::test]
    async fn max_conns_per_peer_rejects_excess_connections() {
        let server_state = InMemoryStateStore::new();
        let server_config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            max_conns_per_peer: 1,
            ..IrohConfig::default()
        };
        let server = IrohTransport::new(&server_config, &server_state)
            .await
            .unwrap();
        let client_config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            ..IrohConfig::default()
        };
        let client_secret = iroh::SecretKey::generate();
        let first_client = bind_endpoint(
            &client_config,
            client_secret.clone(),
            MemoryLookup::new(),
            None,
        )
        .await
        .unwrap();
        let second_client = bind_endpoint(&client_config, client_secret, MemoryLookup::new(), None)
            .await
            .unwrap();

        let first_conn = first_client
            .connect(server.inner.endpoint.addr(), iroh_gossip::ALPN)
            .await
            .unwrap();

        let second_conn = second_client
            .connect(server.inner.endpoint.addr(), iroh_gossip::ALPN)
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), second_conn.closed())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), first_conn.closed())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn endpoint_allowlist_rejects_unknown_and_accepts_runtime_peer() {
        let server_state = InMemoryStateStore::new();
        let server_config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            ..IrohConfig::default()
        };
        let server =
            IrohTransport::new_with_allowed_endpoints(&server_config, &server_state, Some(vec![]))
                .await
                .unwrap();

        let client_config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            ..IrohConfig::default()
        };
        let client_secret = iroh::SecretKey::generate();
        let client_id = *client_secret.public().as_bytes();
        let first_client = bind_endpoint(
            &client_config,
            client_secret.clone(),
            MemoryLookup::new(),
            None,
        )
        .await
        .unwrap();

        let rejected = first_client
            .connect(server.inner.endpoint.addr(), iroh_gossip::ALPN)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), rejected.closed())
            .await
            .unwrap();

        server.allow_peer(IrohEndpointAddr {
            endpoint_id: client_id,
            relay_urls: Vec::new(),
            direct_addrs: Vec::new(),
        });
        let second_client = bind_endpoint(&client_config, client_secret, MemoryLookup::new(), None)
            .await
            .unwrap();
        let accepted = second_client
            .connect(server.inner.endpoint.addr(), iroh_gossip::ALPN)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), accepted.closed())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn revoking_peer_resets_topics() {
        let state = InMemoryStateStore::new();
        let config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            ..IrohConfig::default()
        };
        let transport = IrohTransport::new_with_allowed_endpoints(&config, &state, Some(vec![]))
            .await
            .unwrap();
        let peer_id = *iroh::SecretKey::generate().public().as_bytes();
        let topic = [7u8; 32];

        transport.allow_peer(IrohEndpointAddr {
            endpoint_id: peer_id,
            relay_urls: Vec::new(),
            direct_addrs: Vec::new(),
        });
        transport.ensure_topic(&topic, false).await.unwrap();
        assert_eq!(
            transport
                .inner
                .topics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );

        transport.revoke_peer(peer_id);

        assert!(
            transport
                .inner
                .topics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
        let allowed = transport.inner.allowed_endpoints.as_ref().unwrap();
        assert!(
            !allowed
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&EndpointId::from_bytes(&peer_id).unwrap())
        );
    }

    #[tokio::test]
    async fn local_slot_round_trips_through_transport() {
        let state = InMemoryStateStore::new();
        let config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            ..IrohConfig::default()
        };
        let transport = IrohTransport::new(&config, &state).await.unwrap();
        let topic = [9u8; 32];

        transport.put(&topic, 7, b"sealed").await.unwrap();

        assert_eq!(
            transport.get(&topic).await.unwrap(),
            Some((7, b"sealed".to_vec()))
        );
    }
}
