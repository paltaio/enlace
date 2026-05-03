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
#[cfg(feature = "sled")]
use std::convert::TryInto;
use std::error::Error as StdError;
use std::fmt;
#[cfg(feature = "sled")]
use std::net::SocketAddr;
#[cfg(feature = "sled")]
use std::path::Path;
use std::sync::{Arc, RwLock};

use ed25519_dalek::SigningKey;
#[cfg(feature = "sled")]
use ed25519_dalek::VerifyingKey;
#[cfg(feature = "sled")]
use url::Url;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

#[cfg(feature = "sled")]
use crate::config::IrohEndpointAddr;
use crate::peer::{
    GroupId, GroupKey, GroupKeyId, PeerCard, PeerId, PeerIdentity, TrustError, TrustedPeer,
};

#[cfg(feature = "sled")]
const LOCAL_SLOT_PREFIX: &[u8] = b"local-slot\0";
#[cfg(feature = "sled")]
const SEEN_SLOT_PREFIX: &[u8] = b"seen-slot\0";
#[cfg(feature = "sled")]
const IROH_KEYPAIR_KEY: &[u8] = b"iroh-keypair";
#[cfg(feature = "sled")]
const PEER_IDENTITY_KEY: &[u8] = b"peer-identity";
#[cfg(feature = "sled")]
const TRUSTED_PEER_PREFIX: &[u8] = b"trusted-peer\0";
#[cfg(feature = "sled")]
const GROUP_KEY_PREFIX: &[u8] = b"group-key\0";
#[cfg(feature = "sled")]
const RECORD_VERSION: u8 = 1;

/// Failure modes for a [`StateStore`] backend.
///
/// The in-memory implementation is infallible in practice; these variants exist
/// for backends that touch disk, the network, or external storage.
#[derive(Debug)]
pub enum StateError {
    /// A backend-specific I/O failure (sled, file system, …).
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
/// counters or iroh identity can pass a file path or a custom backend.
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

    /// Open persistent state rooted at `path`.
    #[cfg(feature = "sled")]
    pub fn file(path: impl AsRef<Path>) -> Result<Self, StateError> {
        Ok(Self::custom(Arc::new(FileStateStore::open(path)?)))
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
/// layer such as sled.
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
        let mut inner = write_lock(&self.inner);
        // Floor next at the highest version we've observed, so a peer that
        // joins mid-conversation in a shared-seed namespace doesn't try to
        // write at v=1 over an existing v=N.
        let observed = inner
            .last_seen_slot_versions
            .get(slot)
            .copied()
            .unwrap_or(0);
        let entry = inner
            .local_slot_versions
            .entry(slot.to_owned())
            .or_insert(0);
        let floor = (*entry).max(observed);
        let next = floor
            .checked_add(1)
            .expect("local slot version counter overflowed u64");
        *entry = next;
        Ok(next)
    }

    fn last_seen_slot_version(&self, slot: &str) -> Result<Option<u64>, StateError> {
        let inner = read_lock(&self.inner);
        Ok(inner.last_seen_slot_versions.get(slot).copied())
    }

    fn record_seen_slot_version(&self, slot: &str, version: u64) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        match inner.last_seen_slot_versions.get(slot).copied() {
            Some(current) if version <= current => {}
            _ => {
                inner
                    .last_seen_slot_versions
                    .insert(slot.to_owned(), version);
            }
        }
        Ok(())
    }

    fn iroh_keypair(&self) -> Result<Option<[u8; 32]>, StateError> {
        let inner = read_lock(&self.inner);
        Ok(inner.iroh_keypair.as_ref().map(|secret| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&secret[..]);
            out
        }))
    }

    fn store_iroh_keypair(&self, secret: &[u8; 32]) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.iroh_keypair = Some(Zeroizing::new(*secret));
        Ok(())
    }

    fn peer_identity(&self) -> Result<Option<PeerIdentity>, StateError> {
        let inner = read_lock(&self.inner);
        Ok(inner
            .peer_identity
            .as_ref()
            .map(StoredPeerIdentity::to_identity))
    }

    fn store_peer_identity(&self, identity: &PeerIdentity) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.peer_identity = Some(StoredPeerIdentity::from_identity(identity));
        Ok(())
    }

    fn trusted_peer(&self, peer_id: PeerId) -> Result<Option<TrustedPeer>, StateError> {
        let inner = read_lock(&self.inner);
        Ok(inner.trusted_peers.get(&peer_id).cloned())
    }

    fn trusted_peers(&self) -> Result<Vec<TrustedPeer>, StateError> {
        let inner = read_lock(&self.inner);
        Ok(inner.trusted_peers.values().cloned().collect())
    }

    fn store_trusted_peer(&self, peer: &TrustedPeer) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.trusted_peers.insert(peer.peer_id(), peer.clone());
        Ok(())
    }

    fn remove_trusted_peer(&self, peer_id: PeerId) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.trusted_peers.remove(&peer_id);
        Ok(())
    }

    fn group_keys(&self, group: GroupId) -> Result<Vec<GroupKey>, StateError> {
        let inner = read_lock(&self.inner);
        Ok(inner
            .group_keys
            .iter()
            .filter(|&(&(candidate, _), _)| candidate == group)
            .map(|(_, key)| key.clone())
            .collect())
    }

    fn store_group_key(&self, group: GroupId, key: &GroupKey) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.group_keys.insert((group, key.id), key.clone());
        Ok(())
    }

    fn remove_group_key(&self, group: GroupId, key_id: GroupKeyId) -> Result<(), StateError> {
        let mut inner = write_lock(&self.inner);
        inner.group_keys.remove(&(group, key_id));
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

#[cfg(feature = "sled")]
struct FileStateStore {
    db: sled::Db,
}

#[cfg(feature = "sled")]
impl FileStateStore {
    fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let db = sled::open(path).map_err(backend_error)?;
        Ok(Self { db })
    }

    fn slot_key(prefix: &[u8], slot: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(prefix.len() + slot.len());
        key.extend_from_slice(prefix);
        key.extend_from_slice(slot.as_bytes());
        key
    }

    fn flush(&self) -> Result<(), StateError> {
        self.db.flush().map(|_| ()).map_err(backend_error)
    }

    fn trusted_peer_key(peer_id: PeerId) -> Vec<u8> {
        let mut key = Vec::with_capacity(TRUSTED_PEER_PREFIX.len() + 32);
        key.extend_from_slice(TRUSTED_PEER_PREFIX);
        key.extend_from_slice(&peer_id.to_bytes());
        key
    }

    fn group_key_key(group: GroupId, key_id: GroupKeyId) -> Vec<u8> {
        let mut key = Vec::with_capacity(GROUP_KEY_PREFIX.len() + 64);
        key.extend_from_slice(GROUP_KEY_PREFIX);
        key.extend_from_slice(&group.to_bytes());
        key.extend_from_slice(&key_id.to_bytes());
        key
    }

    fn group_key_prefix(group: GroupId) -> Vec<u8> {
        let mut key = Vec::with_capacity(GROUP_KEY_PREFIX.len() + 32);
        key.extend_from_slice(GROUP_KEY_PREFIX);
        key.extend_from_slice(&group.to_bytes());
        key
    }
}

#[cfg(feature = "sled")]
impl StateStore for FileStateStore {
    fn next_local_slot_version(&self, slot: &str) -> Result<u64, StateError> {
        let key = Self::slot_key(LOCAL_SLOT_PREFIX, slot);
        loop {
            let observed = self.last_seen_slot_version(slot)?.unwrap_or(0);
            let current = self.db.get(&key).map_err(backend_error)?;
            let current_version = current
                .as_deref()
                .map(|bytes| decode_u64(bytes, "local slot version"))
                .transpose()?
                .unwrap_or(0);
            let next = current_version
                .max(observed)
                .checked_add(1)
                .expect("local slot version counter overflowed u64");
            let encoded = next.to_be_bytes().to_vec();
            if let Ok(()) = self
                .db
                .compare_and_swap(&key, current.as_deref(), Some(encoded))
                .map_err(backend_error)?
            {
                self.flush()?;
                return Ok(next);
            }
        }
    }

    fn last_seen_slot_version(&self, slot: &str) -> Result<Option<u64>, StateError> {
        let key = Self::slot_key(SEEN_SLOT_PREFIX, slot);
        self.db
            .get(key)
            .map_err(backend_error)?
            .as_deref()
            .map(|bytes| decode_u64(bytes, "seen slot version"))
            .transpose()
    }

    fn record_seen_slot_version(&self, slot: &str, version: u64) -> Result<(), StateError> {
        let key = Self::slot_key(SEEN_SLOT_PREFIX, slot);
        loop {
            let current = self.db.get(&key).map_err(backend_error)?;
            let current_version = current
                .as_deref()
                .map(|bytes| decode_u64(bytes, "seen slot version"))
                .transpose()?;
            if current_version.is_some_and(|current| version <= current) {
                return Ok(());
            }
            let encoded = version.to_be_bytes().to_vec();
            if let Ok(()) = self
                .db
                .compare_and_swap(&key, current.as_deref(), Some(encoded))
                .map_err(backend_error)?
            {
                self.flush()?;
                return Ok(());
            }
        }
    }

    fn iroh_keypair(&self) -> Result<Option<[u8; 32]>, StateError> {
        self.db
            .get(IROH_KEYPAIR_KEY)
            .map_err(backend_error)?
            .as_deref()
            .map(decode_iroh_keypair)
            .transpose()
    }

    fn store_iroh_keypair(&self, secret: &[u8; 32]) -> Result<(), StateError> {
        self.db
            .insert(IROH_KEYPAIR_KEY, &secret[..])
            .map_err(backend_error)?;
        self.flush()
    }

    fn peer_identity(&self) -> Result<Option<PeerIdentity>, StateError> {
        self.db
            .get(PEER_IDENTITY_KEY)
            .map_err(backend_error)?
            .as_deref()
            .map(decode_peer_identity)
            .transpose()
    }

    fn store_peer_identity(&self, identity: &PeerIdentity) -> Result<(), StateError> {
        self.db
            .insert(PEER_IDENTITY_KEY, encode_peer_identity(identity))
            .map_err(backend_error)?;
        self.flush()
    }

    fn trusted_peer(&self, peer_id: PeerId) -> Result<Option<TrustedPeer>, StateError> {
        self.db
            .get(Self::trusted_peer_key(peer_id))
            .map_err(backend_error)?
            .as_deref()
            .map(decode_trusted_peer)
            .transpose()
    }

    fn trusted_peers(&self) -> Result<Vec<TrustedPeer>, StateError> {
        self.db
            .scan_prefix(TRUSTED_PEER_PREFIX)
            .map(|item| {
                let (_, value) = item.map_err(backend_error)?;
                decode_trusted_peer(&value)
            })
            .collect()
    }

    fn store_trusted_peer(&self, peer: &TrustedPeer) -> Result<(), StateError> {
        self.db
            .insert(
                Self::trusted_peer_key(peer.peer_id()),
                encode_trusted_peer(peer),
            )
            .map_err(backend_error)?;
        self.flush()
    }

    fn remove_trusted_peer(&self, peer_id: PeerId) -> Result<(), StateError> {
        self.db
            .remove(Self::trusted_peer_key(peer_id))
            .map_err(backend_error)?;
        self.flush()
    }

    fn group_keys(&self, group: GroupId) -> Result<Vec<GroupKey>, StateError> {
        self.db
            .scan_prefix(Self::group_key_prefix(group))
            .map(|item| {
                let (_, value) = item.map_err(backend_error)?;
                decode_group_key(&value)
            })
            .collect()
    }

    fn store_group_key(&self, group: GroupId, key: &GroupKey) -> Result<(), StateError> {
        self.db
            .insert(Self::group_key_key(group, key.id), encode_group_key(key))
            .map_err(backend_error)?;
        self.flush()
    }

    fn remove_group_key(&self, group: GroupId, key_id: GroupKeyId) -> Result<(), StateError> {
        self.db
            .remove(Self::group_key_key(group, key_id))
            .map_err(backend_error)?;
        self.flush()
    }
}

#[cfg(feature = "sled")]
fn encode_peer_identity(identity: &PeerIdentity) -> Vec<u8> {
    let has_iroh = u8::from(identity.iroh_secret.is_some());
    let mut out = Vec::with_capacity(66 + usize::from(has_iroh) * 32);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&identity.signing.to_bytes());
    out.extend_from_slice(&identity.exchange.to_bytes());
    out.push(has_iroh);
    if let Some(secret) = &identity.iroh_secret {
        out.extend_from_slice(&secret[..]);
    }
    out
}

#[cfg(feature = "sled")]
fn decode_peer_identity(bytes: &[u8]) -> Result<PeerIdentity, StateError> {
    let mut cursor = Decoder::new(bytes, "peer identity");
    cursor.version()?;
    let signing = cursor.array::<32>("signing key")?;
    let exchange = cursor.array::<32>("exchange key")?;
    let has_iroh = cursor.u8("iroh flag")?;
    let iroh_secret = match has_iroh {
        0 => None,
        1 => Some(cursor.array::<32>("iroh keypair")?),
        _ => {
            return Err(StateError::Corrupted(
                "peer identity has invalid iroh flag".to_owned(),
            ));
        }
    };
    cursor.finish()?;
    Ok(PeerIdentity::from_parts(
        SigningKey::from_bytes(&signing),
        StaticSecret::from(exchange),
        iroh_secret,
    ))
}

#[cfg(feature = "sled")]
fn encode_trusted_peer(peer: &TrustedPeer) -> Vec<u8> {
    let card = &peer.card;
    let mut out = Vec::new();
    out.push(RECORD_VERSION);
    out.extend_from_slice(&card.peer_id.to_bytes());
    out.extend_from_slice(&card.signing_key.to_bytes());
    out.extend_from_slice(&card.exchange_key);
    write_endpoint(&mut out, card.iroh_endpoint.as_ref());
    out
}

#[cfg(feature = "sled")]
fn decode_trusted_peer(bytes: &[u8]) -> Result<TrustedPeer, StateError> {
    let mut cursor = Decoder::new(bytes, "trusted peer");
    cursor.version()?;
    let peer_id = PeerId::from_bytes(cursor.array::<32>("peer id")?);
    let signing_key = VerifyingKey::from_bytes(&cursor.array::<32>("signing key")?)
        .map_err(|_| StateError::Corrupted("trusted peer signing key is invalid".to_owned()))?;
    let exchange_key = cursor.array::<32>("exchange key")?;
    let iroh_endpoint = read_endpoint(&mut cursor)?;
    cursor.finish()?;
    let card = PeerCard {
        peer_id,
        signing_key,
        exchange_key,
        iroh_endpoint,
    };
    TrustedPeer::try_from_card(card)
        .map_err(|err| StateError::Corrupted(format!("trusted peer card is invalid: {err}")))
}

#[cfg(feature = "sled")]
fn encode_group_key(key: &GroupKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&key.id.to_bytes());
    out.extend_from_slice(&key.secret[..]);
    out
}

#[cfg(feature = "sled")]
fn decode_group_key(bytes: &[u8]) -> Result<GroupKey, StateError> {
    let mut cursor = Decoder::new(bytes, "group key");
    cursor.version()?;
    let id = GroupKeyId::from_bytes(cursor.array::<32>("group key id")?);
    let secret = cursor.array::<32>("group key secret")?;
    cursor.finish()?;
    Ok(GroupKey::new(id, secret))
}

#[cfg(feature = "sled")]
fn write_endpoint(out: &mut Vec<u8>, endpoint: Option<&IrohEndpointAddr>) {
    let Some(endpoint) = endpoint else {
        out.push(0);
        return;
    };
    out.push(1);
    out.extend_from_slice(&endpoint.endpoint_id);
    write_string_list(out, endpoint.relay_urls.iter().map(Url::as_str));
    write_string_list(out, endpoint.direct_addrs.iter().map(ToString::to_string));
}

#[cfg(feature = "sled")]
fn read_endpoint(cursor: &mut Decoder<'_>) -> Result<Option<IrohEndpointAddr>, StateError> {
    match cursor.u8("iroh endpoint flag")? {
        0 => Ok(None),
        1 => {
            let endpoint_id = cursor.array::<32>("iroh endpoint id")?;
            let relay_urls = read_string_list(cursor, "relay url")?
                .into_iter()
                .map(|raw| {
                    Url::parse(&raw)
                        .map_err(|_| StateError::Corrupted("relay url is invalid".to_owned()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let direct_addrs = read_string_list(cursor, "direct address")?
                .into_iter()
                .map(|raw| {
                    raw.parse::<SocketAddr>()
                        .map_err(|_| StateError::Corrupted("direct address is invalid".to_owned()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(IrohEndpointAddr {
                endpoint_id,
                relay_urls,
                direct_addrs,
            }))
        }
        _ => Err(StateError::Corrupted(
            "iroh endpoint flag is invalid".to_owned(),
        )),
    }
}

#[cfg(feature = "sled")]
fn write_string_list<'a>(out: &mut Vec<u8>, values: impl Iterator<Item = impl AsRef<str> + 'a>) {
    let start = out.len();
    out.extend_from_slice(&0u32.to_be_bytes());
    let mut count = 0u32;
    for value in values {
        write_bytes(out, value.as_ref().as_bytes());
        count = count
            .checked_add(1)
            .expect("state record string count overflowed u32");
    }
    out[start..start + 4].copy_from_slice(&count.to_be_bytes());
}

#[cfg(feature = "sled")]
fn read_string_list(cursor: &mut Decoder<'_>, field: &str) -> Result<Vec<String>, StateError> {
    let count = cursor.u32(field)?;
    let count = usize::try_from(count)
        .map_err(|_| StateError::Corrupted(format!("{field} count is too large")))?;
    (0..count)
        .map(|_| {
            let bytes = cursor.bytes(field)?;
            String::from_utf8(bytes.to_vec())
                .map_err(|_| StateError::Corrupted(format!("{field} is not utf-8")))
        })
        .collect()
}

#[cfg(feature = "sled")]
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("state record field length overflowed u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(feature = "sled")]
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    record: &'static str,
}

#[cfg(feature = "sled")]
impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8], record: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            record,
        }
    }

    fn version(&mut self) -> Result<(), StateError> {
        let version = self.u8("version")?;
        if version != RECORD_VERSION {
            return Err(StateError::Corrupted(format!(
                "{} has unsupported version",
                self.record
            )));
        }
        Ok(())
    }

    fn u8(&mut self, field: &str) -> Result<u8, StateError> {
        Ok(self.take(field, 1)?[0])
    }

    fn u32(&mut self, field: &str) -> Result<u32, StateError> {
        Ok(u32::from_be_bytes(self.array(field)?))
    }

    fn array<const N: usize>(&mut self, field: &str) -> Result<[u8; N], StateError> {
        self.take(field, N)?
            .try_into()
            .map_err(|_| StateError::Corrupted(format!("{field} has invalid length")))
    }

    fn bytes(&mut self, field: &str) -> Result<&'a [u8], StateError> {
        let len = usize::try_from(self.u32(field)?)
            .map_err(|_| StateError::Corrupted(format!("{field} length is too large")))?;
        self.take(field, len)
    }

    fn take(&mut self, field: &str, len: usize) -> Result<&'a [u8], StateError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| StateError::Corrupted(format!("{field} length is too large")))?;
        let Some(bytes) = self.bytes.get(self.offset..end) else {
            return Err(StateError::Corrupted(format!(
                "{} ended inside {field}",
                self.record
            )));
        };
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), StateError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StateError::Corrupted(format!(
                "{} has trailing bytes",
                self.record
            )))
        }
    }
}

#[cfg(feature = "sled")]
fn decode_u64(bytes: &[u8], field: &str) -> Result<u64, StateError> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| StateError::Corrupted(format!("{field} has invalid length")))?;
    Ok(u64::from_be_bytes(array))
}

#[cfg(feature = "sled")]
fn decode_iroh_keypair(bytes: &[u8]) -> Result<[u8; 32], StateError> {
    bytes
        .try_into()
        .map_err(|_| StateError::Corrupted("iroh keypair has invalid length".to_owned()))
}

#[cfg(feature = "sled")]
fn backend_error(err: impl StdError + Send + Sync + 'static) -> StateError {
    StateError::Backend(Box::new(err))
}

fn unsupported_state(record: &str) -> StateError {
    StateError::Unsupported(format!("{record} storage"))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::*;

    static TEMP_ID: AtomicUsize = AtomicUsize::new(0);

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
        let trusted = trusted_peer(12, 13);
        let group = GroupId::from_bytes([14; 32]);
        let key = GroupKey::new(GroupKeyId::from_bytes([15; 32]), [16; 32]);

        assert!(state.peer_identity().unwrap().is_none());
        identity.save(&state).unwrap();
        state.store_trusted_peer(&trusted).unwrap();
        state.store_group_key(group, &key).unwrap();

        assert_eq!(
            state.peer_identity().unwrap().unwrap().card(),
            identity.card()
        );
        assert_eq!(
            state.trusted_peer(trusted.peer_id()).unwrap(),
            Some(trusted.clone())
        );
        assert_eq!(state.trusted_peers().unwrap(), vec![trusted.clone()]);
        assert_eq!(state.group_keys(group).unwrap(), vec![key.clone()]);

        state.remove_trusted_peer(trusted.peer_id()).unwrap();
        state.remove_group_key(group, key.id).unwrap();

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
