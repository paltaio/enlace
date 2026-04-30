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
use std::convert::TryInto;
use std::error::Error as StdError;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, RwLock};

use zeroize::Zeroizing;

const LOCAL_SLOT_PREFIX: &[u8] = b"local-slot\0";
const SEEN_SLOT_PREFIX: &[u8] = b"seen-slot\0";
const IROH_KEYPAIR_KEY: &[u8] = b"iroh-keypair";

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
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "state backend error: {e}"),
            Self::Corrupted(msg) => write!(f, "state corrupted: {msg}"),
        }
    }
}

impl StdError for StateError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Backend(e) => Some(&**e),
            Self::Corrupted(_) => None,
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
        let entry = inner
            .local_slot_versions
            .entry(slot.to_owned())
            .or_insert(0);
        *entry = entry
            .checked_add(1)
            .expect("local slot version counter overflowed u64");
        Ok(*entry)
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
}

struct FileStateStore {
    db: sled::Db,
}

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
}

impl StateStore for FileStateStore {
    fn next_local_slot_version(&self, slot: &str) -> Result<u64, StateError> {
        let key = Self::slot_key(LOCAL_SLOT_PREFIX, slot);
        loop {
            let current = self.db.get(&key).map_err(backend_error)?;
            let current_version = current
                .as_deref()
                .map(|bytes| decode_u64(bytes, "local slot version"))
                .transpose()?
                .unwrap_or(0);
            let next = current_version
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
}

fn decode_u64(bytes: &[u8], field: &str) -> Result<u64, StateError> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| StateError::Corrupted(format!("{field} has invalid length")))?;
    Ok(u64::from_be_bytes(array))
}

fn decode_iroh_keypair(bytes: &[u8]) -> Result<[u8; 32], StateError> {
    bytes
        .try_into()
        .map_err(|_| StateError::Corrupted("iroh keypair has invalid length".to_owned()))
}

fn backend_error(err: impl StdError + Send + Sync + 'static) -> StateError {
    StateError::Backend(Box::new(err))
}

#[cfg(test)]
mod tests {
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
            assert_eq!(store.next_local_slot_version("slot").unwrap(), 2);
            assert_eq!(store.last_seen_slot_version("slot").unwrap(), Some(9));
            assert_eq!(store.iroh_keypair().unwrap(), Some([7u8; 32]));
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
