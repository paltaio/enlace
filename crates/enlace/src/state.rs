//! Persistent endpoint state used by slot writers and the iroh adapter.
//!
//! Two distinct kinds of slot-version state are tracked:
//!
//! - A **local write counter** per slot, incremented each time this endpoint
//!   calls `Slot::put`. Two endpoints sharing a seed each maintain their own
//!   counter; they may collide, and that is handled by the transport layer
//!   (HTTP returns `409`, broadcast transports last-write-win).
//! - A **last-seen high-water mark** per slot, recording the largest version
//!   this endpoint has observed from any source. Used by `Slot::watch` to
//!   filter out stale updates that arrive over a slower transport.
//!
//! Optional iroh keypair storage lets that adapter preserve peer identity
//! across restarts.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use ed25519_dalek::SigningKey;
#[cfg(not(target_arch = "wasm32"))]
use ed25519_dalek::VerifyingKey;
#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
#[cfg(not(target_arch = "wasm32"))]
use url::Url;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

#[cfg(not(target_arch = "wasm32"))]
use crate::config::IrohEndpointAddr;
use crate::peer::{
    GroupId, GroupKey, GroupKeyId, PeerCard, PeerId, PeerIdentity, TrustError, TrustedPeer,
};

#[cfg(not(target_arch = "wasm32"))]
const SNAPSHOT_VERSION: u8 = 1;
#[cfg(not(target_arch = "wasm32"))]
const STATE_FILE_NAME: &str = "state.msgpack";
#[cfg(not(target_arch = "wasm32"))]
const STATE_TMP_FILE_NAME: &str = "state.msgpack.tmp";

/// Failure modes for a [`StateStore`] backend.
///
/// The in-memory implementation is infallible in practice; these variants exist
/// for backends that touch disk, the network, or external storage.
#[derive(Debug)]
pub enum StateError {
    /// A backend-specific I/O failure (file system, …).
    Backend(Box<dyn StdError + Send + Sync>),
    /// Persisted state failed to deserialize or violated an invariant.
    Corrupted(String),
    /// The selected backend does not support this state record type.
    Unsupported(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "state backend error: {e}"),
            Self::Corrupted(msg) => write!(f, "state corrupted: {msg}"),
            Self::Unsupported(msg) => write!(f, "state operation unsupported: {msg}"),
        }
    }
}

impl StdError for StateError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Backend(e) => Some(&**e),
            Self::Corrupted(_) | Self::Unsupported(_) => None,
        }
    }
}

/// Ergonomic handle for endpoint-local state.
///
/// The default is volatile memory state. Callers that need restart-stable slot
/// counters or iroh identity can pass a directory path or a custom backend.
#[derive(Clone)]
pub struct State {
    store: Arc<dyn StateStore>,
}

impl State {
    /// Construct volatile state that resets when dropped.
    #[must_use]
    pub fn memory() -> Self {
        Self::custom(Arc::new(InMemoryStateStore::new()))
    }

    /// Open persistent state rooted at `dir`. The directory is created if it
    /// does not exist; state is held in `<dir>/state.msgpack` and rewritten
    /// atomically on every mutation via temp file + rename.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn file(dir: impl AsRef<Path>) -> Result<Self, StateError> {
        Ok(Self::custom(Arc::new(FileStateStore::open(dir)?)))
    }

    /// Wrap caller-owned state storage.
    #[must_use]
    pub fn custom(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }

    pub(crate) fn store(&self) -> Arc<dyn StateStore> {
        Arc::clone(&self.store)
    }

    pub fn peer_identity(&self) -> Result<Option<PeerIdentity>, StateError> {
        self.store.peer_identity()
    }

    pub fn store_peer_identity(&self, identity: &PeerIdentity) -> Result<(), StateError> {
        self.store.store_peer_identity(identity)
    }

    pub fn trusted_peer(&self, peer_id: PeerId) -> Result<Option<TrustedPeer>, StateError> {
        self.store.trusted_peer(peer_id)
    }

    pub fn trusted_peers(&self) -> Result<Vec<TrustedPeer>, StateError> {
        self.store.trusted_peers()
    }

    pub fn trust_peer(&self, card: PeerCard) -> Result<TrustedPeer, TrustError> {
        let peer = TrustedPeer::try_from_card(card)?;
        self.store_trusted_peer(&peer)?;
        Ok(peer)
    }

    pub fn store_trusted_peer(&self, peer: &TrustedPeer) -> Result<(), StateError> {
        self.store.store_trusted_peer(peer)
    }

    pub fn remove_trusted_peer(&self, peer_id: PeerId) -> Result<(), StateError> {
        self.store.remove_trusted_peer(peer_id)
    }

    pub fn group_keys(&self, group: GroupId) -> Result<Vec<GroupKey>, StateError> {
        self.store.group_keys(group)
    }

    pub fn store_group_key(&self, group: GroupId, key: &GroupKey) -> Result<(), StateError> {
        self.store.store_group_key(group, key)
    }

    pub fn remove_group_key(&self, group: GroupId, key_id: GroupKeyId) -> Result<(), StateError> {
        self.store.remove_group_key(group, key_id)
    }
}

impl Default for State {
    fn default() -> Self {
        Self::memory()
    }
}

/// Endpoint-local state shared across the slot and iroh layers.
///
/// All methods are synchronous; an implementation that needs to do real I/O
/// should perform it on its own thread or use a blocking-friendly storage
/// layer.
pub trait StateStore: Send + Sync {
    /// Increment and return the next local-write counter for `slot`.
    ///
    /// Counters start at 1; the value 0 is reserved for "this endpoint has
    /// never written to this slot."
    fn next_local_slot_version(&self, slot: &str) -> Result<u64, StateError>;

    /// Highest version observed by this endpoint on `slot` from any source.
    ///
    /// Returns `Ok(None)` when the slot has not yet been recorded.
    fn last_seen_slot_version(&self, slot: &str) -> Result<Option<u64>, StateError>;

    /// Record an observed version for `slot`.
    ///
    /// Implementations must not move the high-water mark backwards: a `version`
    /// less than or equal to the current high-water mark is silently ignored.
    fn record_seen_slot_version(&self, slot: &str, version: u64) -> Result<(), StateError>;

    /// Load the persisted iroh secret key, if one was previously stored.
    ///
    /// Returning `Ok(None)` causes the iroh adapter to generate a fresh
    /// keypair on open; callers that want stable peer identities across
    /// restarts should pair this with [`store_iroh_keypair`].
    ///
    /// [`store_iroh_keypair`]: StateStore::store_iroh_keypair
    fn iroh_keypair(&self) -> Result<Option<[u8; 32]>, StateError>;

    /// Persist the iroh secret key for reuse on the next adapter open.
    fn store_iroh_keypair(&self, secret: &[u8; 32]) -> Result<(), StateError>;

    /// Load local public-key identity material.
    fn peer_identity(&self) -> Result<Option<PeerIdentity>, StateError> {
        Err(unsupported_state("peer identity"))
    }

    /// Persist local public-key identity material.
    fn store_peer_identity(&self, _identity: &PeerIdentity) -> Result<(), StateError> {
        Err(unsupported_state("peer identity"))
    }

    /// Load one trusted peer by id.
    fn trusted_peer(&self, _peer_id: PeerId) -> Result<Option<TrustedPeer>, StateError> {
        Err(unsupported_state("trusted peer"))
    }

    /// Load all trusted peers.
    fn trusted_peers(&self) -> Result<Vec<TrustedPeer>, StateError> {
        Err(unsupported_state("trusted peer"))
    }

    /// Store or replace a trusted peer.
    fn store_trusted_peer(&self, _peer: &TrustedPeer) -> Result<(), StateError> {
        Err(unsupported_state("trusted peer"))
    }

    /// Remove a trusted peer if present.
    fn remove_trusted_peer(&self, _peer_id: PeerId) -> Result<(), StateError> {
        Err(unsupported_state("trusted peer"))
    }

    /// Load all keys known for a public-key group.
    fn group_keys(&self, _group: GroupId) -> Result<Vec<GroupKey>, StateError> {
        Err(unsupported_state("group key"))
    }

    /// Store or replace a public-key group key.
    fn store_group_key(&self, _group: GroupId, _key: &GroupKey) -> Result<(), StateError> {
        Err(unsupported_state("group key"))
    }

    /// Remove a public-key group key if present.
    fn remove_group_key(&self, _group: GroupId, _key_id: GroupKeyId) -> Result<(), StateError> {
        Err(unsupported_state("group key"))
    }
}

/// In-memory [`StateStore`] used when no persistence is configured.
///
/// State resets on construction. Suitable for tests and short-lived endpoints
/// that don't care about peer identity stability across restarts.
#[derive(Default)]
pub struct InMemoryStateStore {
    inner: RwLock<InMemoryInner>,
}

#[derive(Default)]
struct InMemoryInner {
    local_slot_versions: HashMap<String, u64>,
    last_seen_slot_versions: HashMap<String, u64>,
    iroh_keypair: Option<Zeroizing<[u8; 32]>>,
    peer_identity: Option<StoredPeerIdentity>,
    trusted_peers: HashMap<PeerId, TrustedPeer>,
    group_keys: HashMap<(GroupId, GroupKeyId), GroupKey>,
}

impl InMemoryInner {
    fn next_local_slot_version(&mut self, slot: &str) -> u64 {
        // Floor next at the highest version we've observed, so a peer that
        // joins mid-conversation in a shared-seed namespace doesn't try to
        // write at v=1 over an existing v=N.
        let observed = self.last_seen_slot_versions.get(slot).copied().unwrap_or(0);
        let entry = self.local_slot_versions.entry(slot.to_owned()).or_insert(0);
        let floor = (*entry).max(observed);
        let next = floor
            .checked_add(1)
            .expect("local slot version counter overflowed u64");
        *entry = next;
        next
    }

    fn last_seen_slot_version(&self, slot: &str) -> Option<u64> {
        self.last_seen_slot_versions.get(slot).copied()
    }

    /// Returns `true` if the high-water mark advanced and persistent backends
    /// should flush.
    fn record_seen_slot_version(&mut self, slot: &str, version: u64) -> bool {
        match self.last_seen_slot_versions.get(slot).copied() {
            Some(current) if version <= current => false,
            _ => {
                self.last_seen_slot_versions
                    .insert(slot.to_owned(), version);
                true
            }
        }
    }

    fn iroh_keypair(&self) -> Option<[u8; 32]> {
        self.iroh_keypair.as_ref().map(|secret| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&secret[..]);
            out
        })
    }

    fn store_iroh_keypair(&mut self, secret: &[u8; 32]) {
        self.iroh_keypair = Some(Zeroizing::new(*secret));
    }

    fn peer_identity(&self) -> Option<PeerIdentity> {
        self.peer_identity
            .as_ref()
            .map(StoredPeerIdentity::to_identity)
    }

    fn store_peer_identity(&mut self, identity: &PeerIdentity) {
        self.peer_identity = Some(StoredPeerIdentity::from_identity(identity));
    }

    fn trusted_peer(&self, peer_id: PeerId) -> Option<TrustedPeer> {
        self.trusted_peers.get(&peer_id).cloned()
    }

    fn trusted_peers(&self) -> Vec<TrustedPeer> {
        self.trusted_peers.values().cloned().collect()
    }

    fn store_trusted_peer(&mut self, peer: &TrustedPeer) {
        self.trusted_peers.insert(peer.peer_id(), peer.clone());
    }

    /// Returns `true` if the peer was present and removed.
    fn remove_trusted_peer(&mut self, peer_id: PeerId) -> bool {
        self.trusted_peers.remove(&peer_id).is_some()
    }

    fn group_keys(&self, group: GroupId) -> Vec<GroupKey> {
        self.group_keys
            .iter()
            .filter(|&(&(candidate, _), _)| candidate == group)
            .map(|(_, key)| key.clone())
            .collect()
    }

    fn store_group_key(&mut self, group: GroupId, key: &GroupKey) {
        self.group_keys.insert((group, key.id), key.clone());
    }

    /// Returns `true` if the group key was present and removed.
    fn remove_group_key(&mut self, group: GroupId, key_id: GroupKeyId) -> bool {
        self.group_keys.remove(&(group, key_id)).is_some()
    }
}

impl InMemoryStateStore {
    /// Construct an empty in-memory state store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    // A poisoned lock means another thread panicked while holding it. The
    // hashmaps and Options below are mutated atomically at safe points, so the
    // contents remain consistent — recover and continue rather than propagate
    // a failure mode the caller can't act on.
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl StateStore for InMemoryStateStore {
    fn next_local_slot_version(&self, slot: &str) -> Result<u64, StateError> {
        Ok(write_lock(&self.inner).next_local_slot_version(slot))
    }

    fn last_seen_slot_version(&self, slot: &str) -> Result<Option<u64>, StateError> {
        Ok(read_lock(&self.inner).last_seen_slot_version(slot))
    }

    fn record_seen_slot_version(&self, slot: &str, version: u64) -> Result<(), StateError> {
        write_lock(&self.inner).record_seen_slot_version(slot, version);
        Ok(())
    }

    fn iroh_keypair(&self) -> Result<Option<[u8; 32]>, StateError> {
        Ok(read_lock(&self.inner).iroh_keypair())
    }

    fn store_iroh_keypair(&self, secret: &[u8; 32]) -> Result<(), StateError> {
        write_lock(&self.inner).store_iroh_keypair(secret);
        Ok(())
    }

    fn peer_identity(&self) -> Result<Option<PeerIdentity>, StateError> {
        Ok(read_lock(&self.inner).peer_identity())
    }

    fn store_peer_identity(&self, identity: &PeerIdentity) -> Result<(), StateError> {
        write_lock(&self.inner).store_peer_identity(identity);
        Ok(())
    }

    fn trusted_peer(&self, peer_id: PeerId) -> Result<Option<TrustedPeer>, StateError> {
        Ok(read_lock(&self.inner).trusted_peer(peer_id))
    }

    fn trusted_peers(&self) -> Result<Vec<TrustedPeer>, StateError> {
        Ok(read_lock(&self.inner).trusted_peers())
    }

    fn store_trusted_peer(&self, peer: &TrustedPeer) -> Result<(), StateError> {
        write_lock(&self.inner).store_trusted_peer(peer);
        Ok(())
    }

    fn remove_trusted_peer(&self, peer_id: PeerId) -> Result<(), StateError> {
        write_lock(&self.inner).remove_trusted_peer(peer_id);
        Ok(())
    }

    fn group_keys(&self, group: GroupId) -> Result<Vec<GroupKey>, StateError> {
        Ok(read_lock(&self.inner).group_keys(group))
    }

    fn store_group_key(&self, group: GroupId, key: &GroupKey) -> Result<(), StateError> {
        write_lock(&self.inner).store_group_key(group, key);
        Ok(())
    }

    fn remove_group_key(&self, group: GroupId, key_id: GroupKeyId) -> Result<(), StateError> {
        write_lock(&self.inner).remove_group_key(group, key_id);
        Ok(())
    }
}

#[derive(Clone)]
struct StoredPeerIdentity {
    signing: Zeroizing<[u8; 32]>,
    exchange: Zeroizing<[u8; 32]>,
    iroh_secret: Option<Zeroizing<[u8; 32]>>,
}

impl StoredPeerIdentity {
    fn from_identity(identity: &PeerIdentity) -> Self {
        Self {
            signing: Zeroizing::new(identity.signing.to_bytes()),
            exchange: Zeroizing::new(identity.exchange.to_bytes()),
            iroh_secret: identity.iroh_secret.clone(),
        }
    }

    fn to_identity(&self) -> PeerIdentity {
        PeerIdentity::from_parts(
            SigningKey::from_bytes(&self.signing),
            StaticSecret::from(*self.exchange),
            self.iroh_secret.as_ref().map(|secret| **secret),
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct FileStateStore {
    inner: RwLock<InMemoryInner>,
    file_path: PathBuf,
    tmp_path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileStateStore {
    fn open(dir: impl AsRef<Path>) -> Result<Self, StateError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(backend_error)?;
        let file_path = dir.join(STATE_FILE_NAME);
        let tmp_path = dir.join(STATE_TMP_FILE_NAME);
        let inner = match std::fs::read(&file_path) {
            Ok(bytes) => Snapshot::decode(&bytes)?.into_inner()?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => InMemoryInner::default(),
            Err(err) => return Err(backend_error(err)),
        };
        Ok(Self {
            inner: RwLock::new(inner),
            file_path,
            tmp_path,
        })
    }

    fn flush_locked(&self, inner: &InMemoryInner) -> Result<(), StateError> {
        let snapshot = Snapshot::from_inner(inner);
        let bytes = snapshot.encode()?;
        std::fs::write(&self.tmp_path, &bytes).map_err(backend_error)?;
        std::fs::rename(&self.tmp_path, &self.file_path).map_err(backend_error)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl StateStore for FileStateStore {
    fn next_local_slot_version(&self, slot: &str) -> Result<u64, StateError> {
        let mut inner = write_lock(&self.inner);
        let next = inner.next_local_slot_version(slot);
        self.flush_locked(&inner)?;
        Ok(next)
    }

    fn last_seen_slot_version(&self, slot: &str) -> Result<Option<u64>, StateError> {
        Ok(read_lock(&self.inner).last_seen_slot_version(slot))
    }

    fn record_seen_slot_version(&self, slot: &str, version: u64) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        if inner.record_seen_slot_version(slot, version) {
            self.flush_locked(&inner)?;
        }
        Ok(())
    }

    fn iroh_keypair(&self) -> Result<Option<[u8; 32]>, StateError> {
        Ok(read_lock(&self.inner).iroh_keypair())
    }

    fn store_iroh_keypair(&self, secret: &[u8; 32]) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.store_iroh_keypair(secret);
        self.flush_locked(&inner)
    }

    fn peer_identity(&self) -> Result<Option<PeerIdentity>, StateError> {
        Ok(read_lock(&self.inner).peer_identity())
    }

    fn store_peer_identity(&self, identity: &PeerIdentity) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.store_peer_identity(identity);
        self.flush_locked(&inner)
    }

    fn trusted_peer(&self, peer_id: PeerId) -> Result<Option<TrustedPeer>, StateError> {
        Ok(read_lock(&self.inner).trusted_peer(peer_id))
    }

    fn trusted_peers(&self) -> Result<Vec<TrustedPeer>, StateError> {
        Ok(read_lock(&self.inner).trusted_peers())
    }

    fn store_trusted_peer(&self, peer: &TrustedPeer) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.store_trusted_peer(peer);
        self.flush_locked(&inner)
    }

    fn remove_trusted_peer(&self, peer_id: PeerId) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        if inner.remove_trusted_peer(peer_id) {
            self.flush_locked(&inner)?;
        }
        Ok(())
    }

    fn group_keys(&self, group: GroupId) -> Result<Vec<GroupKey>, StateError> {
        Ok(read_lock(&self.inner).group_keys(group))
    }

    fn store_group_key(&self, group: GroupId, key: &GroupKey) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.store_group_key(group, key);
        self.flush_locked(&inner)
    }

    fn remove_group_key(&self, group: GroupId, key_id: GroupKeyId) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        if inner.remove_group_key(group, key_id) {
            self.flush_locked(&inner)?;
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    version: u8,
    #[serde(default)]
    local_slot_versions: BTreeMap<String, u64>,
    #[serde(default)]
    last_seen_slot_versions: BTreeMap<String, u64>,
    #[serde(default)]
    iroh_keypair: Option<[u8; 32]>,
    #[serde(default)]
    peer_identity: Option<SnapshotPeerIdentity>,
    #[serde(default)]
    trusted_peers: Vec<SnapshotTrustedPeer>,
    #[serde(default)]
    group_keys: Vec<SnapshotGroupKey>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize, Deserialize)]
struct SnapshotPeerIdentity {
    signing: [u8; 32],
    exchange: [u8; 32],
    iroh_secret: Option<[u8; 32]>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize, Deserialize)]
struct SnapshotTrustedPeer {
    peer_id: [u8; 32],
    signing_key: [u8; 32],
    exchange_key: [u8; 32],
    iroh_endpoint: Option<SnapshotIrohEndpoint>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize, Deserialize)]
struct SnapshotIrohEndpoint {
    endpoint_id: [u8; 32],
    relay_urls: Vec<String>,
    direct_addrs: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize, Deserialize)]
struct SnapshotGroupKey {
    group: [u8; 32],
    id: [u8; 32],
    secret: [u8; 32],
}

#[cfg(not(target_arch = "wasm32"))]
impl Snapshot {
    fn from_inner(inner: &InMemoryInner) -> Self {
        let local_slot_versions = inner
            .local_slot_versions
            .iter()
            .map(|(slot, version)| (slot.clone(), *version))
            .collect();
        let last_seen_slot_versions = inner
            .last_seen_slot_versions
            .iter()
            .map(|(slot, version)| (slot.clone(), *version))
            .collect();
        let iroh_keypair = inner.iroh_keypair.as_ref().map(|secret| **secret);
        let peer_identity = inner
            .peer_identity
            .as_ref()
            .map(|stored| SnapshotPeerIdentity {
                signing: *stored.signing,
                exchange: *stored.exchange,
                iroh_secret: stored.iroh_secret.as_ref().map(|secret| **secret),
            });
        let trusted_peers = inner
            .trusted_peers
            .values()
            .map(|peer| SnapshotTrustedPeer {
                peer_id: peer.card.peer_id.to_bytes(),
                signing_key: peer.card.signing_key.to_bytes(),
                exchange_key: peer.card.exchange_key,
                iroh_endpoint: peer.card.iroh_endpoint.as_ref().map(|endpoint| {
                    SnapshotIrohEndpoint {
                        endpoint_id: endpoint.endpoint_id,
                        relay_urls: endpoint.relay_urls.iter().map(Url::to_string).collect(),
                        direct_addrs: endpoint
                            .direct_addrs
                            .iter()
                            .map(SocketAddr::to_string)
                            .collect(),
                    }
                }),
            })
            .collect();
        let group_keys = inner
            .group_keys
            .iter()
            .map(|(&(group, _), key)| SnapshotGroupKey {
                group: group.to_bytes(),
                id: key.id.to_bytes(),
                secret: *key.secret,
            })
            .collect();
        Self {
            version: SNAPSHOT_VERSION,
            local_slot_versions,
            last_seen_slot_versions,
            iroh_keypair,
            peer_identity,
            trusted_peers,
            group_keys,
        }
    }

    fn into_inner(self) -> Result<InMemoryInner, StateError> {
        if self.version != SNAPSHOT_VERSION {
            return Err(StateError::Corrupted(format!(
                "snapshot has unsupported version {}",
                self.version
            )));
        }
        let local_slot_versions = self.local_slot_versions.into_iter().collect();
        let last_seen_slot_versions = self.last_seen_slot_versions.into_iter().collect();
        let iroh_keypair = self.iroh_keypair.map(Zeroizing::new);
        let peer_identity = self.peer_identity.map(|stored| StoredPeerIdentity {
            signing: Zeroizing::new(stored.signing),
            exchange: Zeroizing::new(stored.exchange),
            iroh_secret: stored.iroh_secret.map(Zeroizing::new),
        });

        let mut trusted_peers = HashMap::with_capacity(self.trusted_peers.len());
        for snapshot_peer in self.trusted_peers {
            let signing_key =
                VerifyingKey::from_bytes(&snapshot_peer.signing_key).map_err(|_| {
                    StateError::Corrupted("trusted peer signing key invalid".to_owned())
                })?;
            let iroh_endpoint = snapshot_peer
                .iroh_endpoint
                .map(|endpoint| -> Result<IrohEndpointAddr, StateError> {
                    let relay_urls = endpoint
                        .relay_urls
                        .into_iter()
                        .map(|raw| {
                            Url::parse(&raw).map_err(|_| {
                                StateError::Corrupted("trusted peer relay url invalid".to_owned())
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let direct_addrs = endpoint
                        .direct_addrs
                        .into_iter()
                        .map(|raw| {
                            raw.parse::<SocketAddr>().map_err(|_| {
                                StateError::Corrupted(
                                    "trusted peer direct address invalid".to_owned(),
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(IrohEndpointAddr {
                        endpoint_id: endpoint.endpoint_id,
                        relay_urls,
                        direct_addrs,
                    })
                })
                .transpose()?;
            let card = PeerCard {
                peer_id: PeerId::from_bytes(snapshot_peer.peer_id),
                signing_key,
                exchange_key: snapshot_peer.exchange_key,
                iroh_endpoint,
            };
            let trusted = TrustedPeer::try_from_card(card).map_err(|err| {
                StateError::Corrupted(format!("trusted peer card is invalid: {err}"))
            })?;
            trusted_peers.insert(trusted.peer_id(), trusted);
        }

        let mut group_keys = HashMap::with_capacity(self.group_keys.len());
        for snapshot_group_key in self.group_keys {
            let group = GroupId::from_bytes(snapshot_group_key.group);
            let id = GroupKeyId::from_bytes(snapshot_group_key.id);
            group_keys.insert((group, id), GroupKey::new(id, snapshot_group_key.secret));
        }

        Ok(InMemoryInner {
            local_slot_versions,
            last_seen_slot_versions,
            iroh_keypair,
            peer_identity,
            trusted_peers,
            group_keys,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, StateError> {
        rmp_serde::to_vec_named(self).map_err(backend_error)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        rmp_serde::from_slice(bytes)
            .map_err(|err| StateError::Corrupted(format!("snapshot decode failed: {err}")))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn backend_error(err: impl StdError + Send + Sync + 'static) -> StateError {
    StateError::Backend(Box::new(err))
}

fn unsupported_state(record: &str) -> StateError {
    StateError::Unsupported(format!("{record} storage"))
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_arch = "wasm32"))]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::PathBuf;
    use std::sync::Arc;
    #[cfg(not(target_arch = "wasm32"))]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[cfg(not(target_arch = "wasm32"))]
    use url::Url;

    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::config::IrohEndpointAddr;

    #[cfg(not(target_arch = "wasm32"))]
    static TEMP_ID: AtomicUsize = AtomicUsize::new(0);

    #[cfg(not(target_arch = "wasm32"))]
    fn temp_state_path(name: &str) -> PathBuf {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("enlace-state-{name}-{}-{id}", std::process::id()))
    }

    fn identity(signing_byte: u8, exchange_byte: u8) -> PeerIdentity {
        PeerIdentity::from_parts(
            SigningKey::from_bytes(&[signing_byte; 32]),
            StaticSecret::from([exchange_byte; 32]),
            Some([signing_byte ^ exchange_byte; 32]),
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn trusted_peer(signing_byte: u8, exchange_byte: u8) -> TrustedPeer {
        let endpoint = IrohEndpointAddr {
            endpoint_id: [signing_byte; 32],
            relay_urls: vec![Url::parse("https://relay.example.test").unwrap()],
            direct_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433)],
        };
        TrustedPeer::new(identity(signing_byte, exchange_byte).card_with_iroh_endpoint(endpoint))
    }

    #[test]
    fn next_local_slot_version_starts_at_one() {
        let s = InMemoryStateStore::new();
        assert_eq!(s.next_local_slot_version("alpha").unwrap(), 1);
    }

    #[test]
    fn next_local_slot_version_is_monotonic() {
        let s = InMemoryStateStore::new();
        for expected in 1u64..=10 {
            assert_eq!(s.next_local_slot_version("alpha").unwrap(), expected);
        }
    }

    #[test]
    fn next_local_slot_version_is_per_slot() {
        let s = InMemoryStateStore::new();
        assert_eq!(s.next_local_slot_version("alpha").unwrap(), 1);
        assert_eq!(s.next_local_slot_version("beta").unwrap(), 1);
        assert_eq!(s.next_local_slot_version("alpha").unwrap(), 2);
        assert_eq!(s.next_local_slot_version("beta").unwrap(), 2);
    }

    #[test]
    fn last_seen_slot_version_initial_is_none() {
        let s = InMemoryStateStore::new();
        assert_eq!(s.last_seen_slot_version("alpha").unwrap(), None);
    }

    #[test]
    fn record_seen_slot_version_sets_initial() {
        let s = InMemoryStateStore::new();
        s.record_seen_slot_version("alpha", 5).unwrap();
        assert_eq!(s.last_seen_slot_version("alpha").unwrap(), Some(5));
    }

    #[test]
    fn record_seen_slot_version_advances_on_higher() {
        let s = InMemoryStateStore::new();
        s.record_seen_slot_version("alpha", 5).unwrap();
        s.record_seen_slot_version("alpha", 7).unwrap();
        assert_eq!(s.last_seen_slot_version("alpha").unwrap(), Some(7));
    }

    #[test]
    fn record_seen_slot_version_ignores_equal_or_lower() {
        let s = InMemoryStateStore::new();
        s.record_seen_slot_version("alpha", 10).unwrap();
        s.record_seen_slot_version("alpha", 10).unwrap();
        s.record_seen_slot_version("alpha", 3).unwrap();
        s.record_seen_slot_version("alpha", 9).unwrap();
        assert_eq!(s.last_seen_slot_version("alpha").unwrap(), Some(10));
    }

    #[test]
    fn next_local_slot_version_floors_at_seen() {
        let s = InMemoryStateStore::new();
        s.record_seen_slot_version("alpha", 9).unwrap();
        assert_eq!(s.next_local_slot_version("alpha").unwrap(), 10);
        assert_eq!(s.next_local_slot_version("alpha").unwrap(), 11);
    }

    #[test]
    fn record_seen_slot_version_is_per_slot() {
        let s = InMemoryStateStore::new();
        s.record_seen_slot_version("alpha", 5).unwrap();
        s.record_seen_slot_version("beta", 100).unwrap();
        assert_eq!(s.last_seen_slot_version("alpha").unwrap(), Some(5));
        assert_eq!(s.last_seen_slot_version("beta").unwrap(), Some(100));
    }

    #[test]
    fn iroh_keypair_initially_absent() {
        let s = InMemoryStateStore::new();
        assert_eq!(s.iroh_keypair().unwrap(), None);
    }

    #[test]
    fn iroh_keypair_round_trips() {
        let s = InMemoryStateStore::new();
        let secret = [7u8; 32];
        s.store_iroh_keypair(&secret).unwrap();
        assert_eq!(s.iroh_keypair().unwrap(), Some(secret));
    }

    #[test]
    fn iroh_keypair_overwrites() {
        let s = InMemoryStateStore::new();
        s.store_iroh_keypair(&[1u8; 32]).unwrap();
        s.store_iroh_keypair(&[2u8; 32]).unwrap();
        assert_eq!(s.iroh_keypair().unwrap(), Some([2u8; 32]));
    }

    #[test]
    fn usable_as_trait_object() {
        let s: Box<dyn StateStore> = Box::new(InMemoryStateStore::new());
        assert_eq!(s.next_local_slot_version("x").unwrap(), 1);
        s.record_seen_slot_version("x", 42).unwrap();
        assert_eq!(s.last_seen_slot_version("x").unwrap(), Some(42));
    }

    #[test]
    fn state_memory_wraps_volatile_store() {
        let state = State::memory();
        let store = state.store();
        assert_eq!(store.next_local_slot_version("x").unwrap(), 1);
    }

    #[test]
    fn state_custom_wraps_caller_store() {
        let store = Arc::new(InMemoryStateStore::new());
        let state = State::custom(store.clone());
        assert_eq!(state.store().next_local_slot_version("x").unwrap(), 1);
        assert_eq!(store.next_local_slot_version("x").unwrap(), 2);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn state_file_persists_shared_seed_state() {
        let path = temp_state_path("shared-seed");
        {
            let state = State::file(&path).unwrap();
            let store = state.store();
            assert_eq!(store.next_local_slot_version("slot").unwrap(), 1);
            store.record_seen_slot_version("slot", 9).unwrap();
            store.store_iroh_keypair(&[7u8; 32]).unwrap();
        }
        {
            let state = State::file(&path).unwrap();
            let store = state.store();
            // last_seen=9 floors the next local slot to 10 even though the
            // persisted local counter is 1.
            assert_eq!(store.next_local_slot_version("slot").unwrap(), 10);
            assert_eq!(store.last_seen_slot_version("slot").unwrap(), Some(9));
            assert_eq!(store.iroh_keypair().unwrap(), Some([7u8; 32]));
        }
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn state_memory_stores_public_key_material() {
        let state = State::memory();
        let identity = identity(10, 11);
        #[cfg(not(target_arch = "wasm32"))]
        let trusted = trusted_peer(12, 13);
        let group = GroupId::from_bytes([14; 32]);
        let key = GroupKey::new(GroupKeyId::from_bytes([15; 32]), [16; 32]);

        assert!(state.peer_identity().unwrap().is_none());
        identity.save(&state).unwrap();
        #[cfg(not(target_arch = "wasm32"))]
        state.store_trusted_peer(&trusted).unwrap();
        state.store_group_key(group, &key).unwrap();

        assert_eq!(
            state.peer_identity().unwrap().unwrap().card(),
            identity.card()
        );
        #[cfg(not(target_arch = "wasm32"))]
        {
            assert_eq!(
                state.trusted_peer(trusted.peer_id()).unwrap(),
                Some(trusted.clone())
            );
            assert_eq!(state.trusted_peers().unwrap(), vec![trusted.clone()]);
        }
        assert_eq!(state.group_keys(group).unwrap(), vec![key.clone()]);

        #[cfg(not(target_arch = "wasm32"))]
        state.remove_trusted_peer(trusted.peer_id()).unwrap();
        state.remove_group_key(group, key.id).unwrap();

        #[cfg(not(target_arch = "wasm32"))]
        assert!(state.trusted_peer(trusted.peer_id()).unwrap().is_none());
        assert!(state.group_keys(group).unwrap().is_empty());
    }

    #[test]
    fn state_trust_peer_validates_and_stores_one_way_card() {
        let state = State::memory();
        let trusted = state.trust_peer(identity(30, 31).card()).unwrap();

        assert_eq!(
            state.trusted_peer(trusted.peer_id()).unwrap(),
            Some(trusted.clone())
        );

        let mut invalid = identity(32, 33).card();
        invalid.peer_id = trusted.peer_id();
        assert!(matches!(
            state.trust_peer(invalid),
            Err(TrustError::InvalidPeerCard(_))
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn state_file_persists_public_key_material() {
        let path = temp_state_path("public-key");
        let identity = identity(20, 21);
        let trusted = trusted_peer(22, 23);
        let group = GroupId::from_bytes([24; 32]);
        let key = GroupKey::new(GroupKeyId::from_bytes([25; 32]), [26; 32]);

        {
            let state = State::file(&path).unwrap();
            identity.save(&state).unwrap();
            state.store_trusted_peer(&trusted).unwrap();
            state.store_group_key(group, &key).unwrap();
        }
        {
            let state = State::file(&path).unwrap();
            let loaded_identity = state.peer_identity().unwrap().unwrap();
            assert_eq!(loaded_identity.card(), identity.card());
            assert_eq!(
                loaded_identity.iroh_secret.as_ref().map(|secret| **secret),
                identity.iroh_secret.as_ref().map(|secret| **secret)
            );
            assert_eq!(
                state.trusted_peer(trusted.peer_id()).unwrap(),
                Some(trusted.clone())
            );
            assert_eq!(state.group_keys(group).unwrap(), vec![key.clone()]);

            state.remove_trusted_peer(trusted.peer_id()).unwrap();
            state.remove_group_key(group, key.id).unwrap();
        }
        {
            let state = State::file(&path).unwrap();
            assert!(state.trusted_peer(trusted.peer_id()).unwrap().is_none());
            assert!(state.group_keys(group).unwrap().is_empty());
        }
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn shared_arc_concurrent_writers_preserve_total_count() {
        let s = Arc::new(InMemoryStateStore::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    for _ in 0..100 {
                        s.next_local_slot_version("hot").unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // 8 threads × 100 increments = 800. Counter should land at exactly 800.
        assert_eq!(s.next_local_slot_version("hot").unwrap(), 801);
    }

    #[test]
    fn shared_arc_concurrent_record_settles_at_max() {
        let s = Arc::new(InMemoryStateStore::new());
        let threads: Vec<_> = (1u64..=20)
            .map(|v| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    s.record_seen_slot_version("watch", v).unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(s.last_seen_slot_version("watch").unwrap(), Some(20));
    }

    #[test]
    fn state_error_displays_chain() {
        let inner: Box<dyn StdError + Send + Sync> = Box::new(std::io::Error::other("disk full"));
        let e = StateError::Backend(inner);
        let rendered = e.to_string();
        assert!(rendered.contains("state backend error"));
        assert!(rendered.contains("disk full"));
        assert!(e.source().is_some());

        let c = StateError::Corrupted("bad header".into());
        assert!(c.to_string().contains("bad header"));
        assert!(c.source().is_none());
    }
}
