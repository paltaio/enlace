use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mainline::errors::{PutMutableError, PutQueryError};
use mainline::{Dht, MutableItem, SigningKey};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::config::{DhtBootstrapCacheConfig, DhtConfig};
use crate::crypto::derive_key32;
use crate::error::TransportError;
use crate::transports::{MailboxTransport, SlotTransport, SlotWatchStream};

const MAX_MUTABLE_VALUE_BYTES: usize = 1000;
const WATCH_BUFFER: usize = 64;
const BOOTSTRAP_CACHE_WRITE_INTERVAL: Duration = Duration::from_mins(5);

#[derive(Clone)]
pub struct DhtTransport {
    dht: Dht,
    signing_key: SigningKey,
    public_key: [u8; 32],
    watch_poll_interval: Duration,
    bootstrap_cache: Option<Arc<BootstrapCache>>,
}

impl DhtTransport {
    pub fn new(seed: &[u8; 32], config: &DhtConfig) -> Result<Self, TransportError> {
        if config.watch_poll_interval.is_zero() {
            return Err(TransportError::Network(
                "DHT watch poll interval must be nonzero".to_owned(),
            ));
        }
        validate_bootstrap_cache(config.bootstrap_cache.as_ref())?;

        let cached_bootstrap = load_bootstrap_cache(config.bootstrap_cache.as_ref())?;
        let mut builder = Dht::builder();
        let bootstrap = combined_bootstrap(&config.bootstrap, cached_bootstrap.as_deref());
        if !bootstrap.is_empty() {
            builder.bootstrap(&bootstrap);
        }
        let dht = builder.build().map_err(map_io_error)?;
        Ok(Self::from_dht(
            seed,
            dht,
            config.watch_poll_interval,
            config.bootstrap_cache.clone(),
        ))
    }

    fn from_dht(
        seed: &[u8; 32],
        dht: Dht,
        watch_poll_interval: Duration,
        bootstrap_cache: Option<DhtBootstrapCacheConfig>,
    ) -> Self {
        let signing_key = dht_signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            dht,
            signing_key,
            public_key,
            watch_poll_interval,
            bootstrap_cache: bootstrap_cache.map(BootstrapCache::new).map(Arc::new),
        }
    }

    fn get_latest(&self, id: &DhtSlotId, after: Option<i64>) -> Option<MutableItem> {
        let mut best: Option<MutableItem> = None;
        for item in self.dht.get_mutable(&id.public_key, Some(&id.salt), after) {
            if best
                .as_ref()
                .is_none_or(|current| mutable_item_is_newer(&item, current))
            {
                best = Some(item);
            }
        }
        self.maybe_persist_bootstrap_cache();
        best
    }

    fn maybe_persist_bootstrap_cache(&self) {
        let Some(cache) = &self.bootstrap_cache else {
            return;
        };
        if !cache.should_write() {
            return;
        }
        let peers: Vec<SocketAddr> = self
            .dht
            .to_bootstrap()
            .into_iter()
            .filter_map(|peer| peer.parse().ok())
            .take(cache.config.max_peers)
            .collect();
        let _ = persist_bootstrap_cache(&cache.config.path, &peers, now_secs());
    }

    async fn slot_get_since(
        &self,
        id: DhtSlotId,
        since: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let transport = self.clone();
        let after = u64_to_seq(since)?;
        run_blocking(move || {
            let Some(current) = transport.get_latest(&id, Some(after)) else {
                return Ok(None);
            };
            let version = seq_to_u64(current.seq())?;
            if version <= since {
                return Ok(None);
            }
            Ok(Some((version, current.value().to_vec())))
        })
        .await
    }
}

impl fmt::Debug for DhtTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhtTransport")
            .field("public_key", &self.public_key)
            .field("watch_poll_interval", &self.watch_poll_interval)
            .field("bootstrap_cache", &self.bootstrap_cache.is_some())
            .finish_non_exhaustive()
    }
}

struct BootstrapCache {
    config: DhtBootstrapCacheConfig,
    last_write: Mutex<Option<Instant>>,
}

impl BootstrapCache {
    fn new(config: DhtBootstrapCacheConfig) -> Self {
        Self {
            config,
            last_write: Mutex::new(None),
        }
    }

    fn should_write(&self) -> bool {
        let mut last_write = self
            .last_write
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last_write
            .as_ref()
            .is_some_and(|last| last.elapsed() < BOOTSTRAP_CACHE_WRITE_INTERVAL)
        {
            return false;
        }
        *last_write = Some(Instant::now());
        true
    }
}

#[async_trait]
impl MailboxTransport for DhtTransport {
    async fn send(&self, _id: &[u8], _sealed: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::Unsupported)
    }

    async fn recv(&self, _id: &[u8], _wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        Err(TransportError::Unsupported)
    }
}

#[async_trait]
impl SlotTransport for DhtTransport {
    async fn put(&self, id: &[u8], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        let id = self.dht_slot_id(id)?;
        ensure_value_fits(sealed)?;
        let transport = self.clone();
        let sealed = sealed.to_vec();
        let seq = u64_to_seq(version)?;
        run_blocking(move || {
            let current = transport.get_latest(&id, None);
            if current.as_ref().is_some_and(|item| item.seq() >= seq) {
                return Err(TransportError::Stale);
            }
            let cas = current.as_ref().map(MutableItem::seq);
            let item = MutableItem::new(id.signing_key, &sealed, seq, Some(&id.salt));
            put_mutable_with_bootstrap_retry(&transport.dht, item, cas)?;
            transport.maybe_persist_bootstrap_cache();
            Ok(())
        })
        .await
    }

    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let id = self.dht_slot_id(id)?;
        self.slot_get_since(id, 0).await
    }

    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream {
        let Ok(id) = self.dht_slot_id(id) else {
            return Box::pin(tokio_stream::iter([Err(TransportError::Network(
                "DHT channel id must be 16 or 32 bytes".to_owned(),
            ))]));
        };
        let transport = self.clone();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);

        tokio::spawn(async move {
            let mut since = since;
            loop {
                match transport.slot_get_since(id.clone(), since).await {
                    Ok(Some((version, value))) => {
                        since = version;
                        if tx.send(Ok((version, value))).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if tx.send(Err(err)).await.is_err() {
                            break;
                        }
                    }
                }
                tokio::time::sleep(transport.watch_poll_interval).await;
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}

#[derive(Clone)]
struct DhtSlotId {
    signing_key: SigningKey,
    public_key: [u8; 32],
    salt: [u8; 16],
}

impl DhtTransport {
    fn dht_slot_id(&self, id: &[u8]) -> Result<DhtSlotId, TransportError> {
        match id.len() {
            16 => {
                let salt: [u8; 16] = id.try_into().map_err(|_| {
                    TransportError::Network("DHT channel id must be 16 bytes".to_owned())
                })?;
                Ok(DhtSlotId {
                    signing_key: self.signing_key.clone(),
                    public_key: self.public_key,
                    salt,
                })
            }
            32 => {
                let seed: [u8; 32] = id.try_into().map_err(|_| {
                    TransportError::Network("DHT address id must be 32 bytes".to_owned())
                })?;
                let signing_key = dht_signing_key(&seed);
                Ok(DhtSlotId {
                    public_key: signing_key.verifying_key().to_bytes(),
                    signing_key,
                    salt: [0; 16],
                })
            }
            _ => Err(TransportError::Network(
                "DHT channel id must be 16 or 32 bytes".to_owned(),
            )),
        }
    }
}

async fn run_blocking<T, F>(f: F) -> Result<T, TransportError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, TransportError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| TransportError::Other(Box::new(err)))?
}

fn dht_signing_key(seed: &[u8; 32]) -> SigningKey {
    let key = derive_key32(seed, b"enlace/v1/key/dht-id");
    SigningKey::from_bytes(&key)
}

fn ensure_value_fits(value: &[u8]) -> Result<(), TransportError> {
    if value.len() > MAX_MUTABLE_VALUE_BYTES {
        return Err(TransportError::BodyTooLarge);
    }
    Ok(())
}

fn u64_to_seq(version: u64) -> Result<i64, TransportError> {
    i64::try_from(version)
        .map_err(|_| TransportError::Network("slot version exceeds DHT sequence range".to_owned()))
}

fn seq_to_u64(seq: i64) -> Result<u64, TransportError> {
    u64::try_from(seq)
        .map_err(|_| TransportError::Network("DHT returned negative mutable sequence".to_owned()))
}

fn mutable_item_is_newer(candidate: &MutableItem, current: &MutableItem) -> bool {
    (candidate.seq(), candidate.value()) > (current.seq(), current.value())
}

fn put_mutable_with_bootstrap_retry(
    dht: &Dht,
    item: MutableItem,
    cas: Option<i64>,
) -> Result<(), TransportError> {
    match dht.put_mutable(item.clone(), cas) {
        Ok(_) => Ok(()),
        Err(PutMutableError::Query(PutQueryError::NoClosestNodes)) => {
            let _ = dht.bootstrapped();
            dht.put_mutable(item, cas).map(drop).map_err(map_put_error)
        }
        Err(err) => Err(map_put_error(err)),
    }
}

fn combined_bootstrap(configured: &[SocketAddr], cached: Option<&[SocketAddr]>) -> Vec<SocketAddr> {
    let cached = cached.unwrap_or_default();
    let mut bootstrap = Vec::with_capacity(configured.len() + cached.len());
    bootstrap.extend_from_slice(configured);
    bootstrap.extend_from_slice(cached);
    bootstrap
}

fn validate_bootstrap_cache(
    config: Option<&DhtBootstrapCacheConfig>,
) -> Result<(), TransportError> {
    let Some(config) = config else {
        return Ok(());
    };
    if config.ttl.is_zero() {
        return Err(TransportError::Network(
            "DHT bootstrap cache TTL must be nonzero".to_owned(),
        ));
    }
    if config.max_peers == 0 {
        return Err(TransportError::Network(
            "DHT bootstrap cache max peers must be nonzero".to_owned(),
        ));
    }
    Ok(())
}

fn load_bootstrap_cache(
    config: Option<&DhtBootstrapCacheConfig>,
) -> Result<Option<Vec<SocketAddr>>, TransportError> {
    let Some(config) = config else {
        return Ok(None);
    };
    let raw = match fs::read_to_string(&config.path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(map_io_error(err)),
    };
    Ok(decode_bootstrap_cache(
        &raw,
        now_secs(),
        config.ttl,
        config.max_peers,
    ))
}

fn decode_bootstrap_cache(
    raw: &str,
    now_secs: u64,
    ttl: Duration,
    max_peers: usize,
) -> Option<Vec<SocketAddr>> {
    let mut lines = raw.lines();
    let timestamp_line = lines.next()?;
    let timestamp = timestamp_line
        .strip_prefix("timestamp=")
        .and_then(|value| value.parse::<u64>().ok())?;
    if now_secs.saturating_sub(timestamp) > ttl.as_secs() {
        return None;
    }

    let peers: Vec<SocketAddr> = lines
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.parse().ok())
        .take(max_peers)
        .collect();
    if peers.is_empty() { None } else { Some(peers) }
}

fn persist_bootstrap_cache(
    path: &Path,
    peers: &[SocketAddr],
    now_secs: u64,
) -> Result<(), TransportError> {
    if peers.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(map_io_error)?;
    }
    let mut body = format!("timestamp={now_secs}\n");
    for peer in peers {
        body.push_str(&peer.to_string());
        body.push('\n');
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, body).map_err(map_io_error)?;
    fs::rename(tmp, path).map_err(map_io_error)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn map_io_error(err: std::io::Error) -> TransportError {
    TransportError::Other(Box::new(err))
}

fn map_put_error(err: PutMutableError) -> TransportError {
    match err {
        mainline::errors::PutMutableError::Concurrency(_) => TransportError::Stale,
        mainline::errors::PutMutableError::Query(err) => TransportError::Other(Box::new(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "enlace-dht-bootstrap-cache-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn value_limit_matches_bep44_cap() {
        assert!(ensure_value_fits(&vec![0; MAX_MUTABLE_VALUE_BYTES]).is_ok());
        assert!(matches!(
            ensure_value_fits(&vec![0; MAX_MUTABLE_VALUE_BYTES + 1]),
            Err(TransportError::BodyTooLarge)
        ));
    }

    #[test]
    fn mutable_order_uses_seq_then_value() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let older = MutableItem::new(key.clone(), b"z", 1, Some(b"id"));
        let newer_seq = MutableItem::new(key.clone(), b"a", 2, Some(b"id"));
        let newer_value = MutableItem::new(key, b"z", 2, Some(b"id"));

        assert!(mutable_item_is_newer(&newer_seq, &older));
        assert!(mutable_item_is_newer(&newer_value, &newer_seq));
        assert!(!mutable_item_is_newer(&older, &newer_value));
    }

    #[test]
    fn slot_id_accepts_shared_seed_and_public_key_addresses() {
        let transport = DhtTransport::new(&[1; 32], &DhtConfig::default()).unwrap();

        let shared = transport.dht_slot_id(&[2; 16]).unwrap();
        let public = transport.dht_slot_id(&[3; 32]).unwrap();

        assert_eq!(shared.salt, [2; 16]);
        assert_eq!(public.salt, [0; 16]);
        assert_ne!(shared.public_key, public.public_key);
    }

    #[test]
    fn combines_configured_and_cached_bootstrap() {
        let configured = [peer("127.0.0.1:1001")];
        let cached = [peer("127.0.0.1:1002")];

        assert_eq!(
            combined_bootstrap(&configured, Some(&cached)),
            vec![configured[0], cached[0]]
        );
    }

    #[test]
    fn decodes_fresh_bootstrap_cache() {
        let raw = "timestamp=100\n127.0.0.1:1001\nbad\n127.0.0.1:1002\n";

        let peers = decode_bootstrap_cache(raw, 120, Duration::from_mins(1), 2).unwrap();

        assert_eq!(peers, vec![peer("127.0.0.1:1001"), peer("127.0.0.1:1002")]);
    }

    #[test]
    fn ignores_stale_bootstrap_cache() {
        let raw = "timestamp=100\n127.0.0.1:1001\n";

        let peers = decode_bootstrap_cache(raw, 161, Duration::from_mins(1), 64);

        assert_eq!(peers, None);
    }

    #[test]
    fn caps_bootstrap_cache_peers() {
        let raw = "timestamp=100\n127.0.0.1:1001\n127.0.0.1:1002\n127.0.0.1:1003\n";

        let peers = decode_bootstrap_cache(raw, 100, Duration::from_mins(1), 2).unwrap();

        assert_eq!(peers, vec![peer("127.0.0.1:1001"), peer("127.0.0.1:1002")]);
    }

    #[test]
    fn persists_bootstrap_cache_atomically() {
        let path = temp_path("roundtrip").join("dht-bootstrap.txt");
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
        let peers = vec![peer("127.0.0.1:1001"), peer("127.0.0.1:1002")];

        persist_bootstrap_cache(&path, &peers, 100).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        let decoded = decode_bootstrap_cache(&raw, 100, Duration::from_mins(1), 64).unwrap();

        assert_eq!(decoded, peers);
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn bootstrap_cache_rejects_zero_ttl() {
        let config = DhtConfig {
            bootstrap_cache: Some(DhtBootstrapCacheConfig {
                path: temp_path("zero-ttl"),
                ttl: Duration::ZERO,
                max_peers: 64,
            }),
            ..DhtConfig::default()
        };

        let err = DhtTransport::new(&[1; 32], &config).unwrap_err();

        assert!(matches!(err, TransportError::Network(_)));
    }

    #[test]
    fn bootstrap_cache_rejects_zero_max_peers() {
        let config = DhtConfig {
            bootstrap_cache: Some(DhtBootstrapCacheConfig {
                path: temp_path("zero-peers"),
                ttl: Duration::from_mins(1),
                max_peers: 0,
            }),
            ..DhtConfig::default()
        };

        let err = DhtTransport::new(&[1; 32], &config).unwrap_err();

        assert!(matches!(err, TransportError::Network(_)));
    }

    #[tokio::test]
    async fn mailbox_send_is_unsupported() {
        let transport = DhtTransport::new(&[1; 32], &DhtConfig::default()).unwrap();
        let err = transport.send(&[2; 16], b"sealed").await.unwrap_err();
        assert!(matches!(err, TransportError::Unsupported));
    }

    #[tokio::test]
    async fn mailbox_recv_is_unsupported() {
        let transport = DhtTransport::new(&[1; 32], &DhtConfig::default()).unwrap();
        let err = transport.recv(&[2; 16], Duration::ZERO).await.unwrap_err();
        assert!(matches!(err, TransportError::Unsupported));
    }

    #[test]
    fn watch_poll_interval_comes_from_config() {
        let config = DhtConfig {
            watch_poll_interval: Duration::from_secs(42),
            ..DhtConfig::default()
        };
        let transport = DhtTransport::new(&[1; 32], &config).unwrap();
        assert_eq!(transport.watch_poll_interval, Duration::from_secs(42));
    }

    #[test]
    fn watch_poll_interval_rejects_zero() {
        let config = DhtConfig {
            watch_poll_interval: Duration::ZERO,
            ..DhtConfig::default()
        };
        let err = DhtTransport::new(&[1; 32], &config).unwrap_err();
        assert!(matches!(err, TransportError::Network(_)));
    }
}
