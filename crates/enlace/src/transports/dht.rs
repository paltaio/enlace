use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use mainline::{Dht, MutableItem, SigningKey};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::config::DhtConfig;
use crate::crypto::derive_key32;
use crate::error::TransportError;
use crate::transports::{MailboxTransport, SlotTransport, SlotWatchStream};

const MAX_MUTABLE_VALUE_BYTES: usize = 1000;
const WATCH_BUFFER: usize = 64;

#[derive(Clone)]
pub struct DhtTransport {
    dht: Dht,
    signing_key: SigningKey,
    public_key: [u8; 32],
    watch_poll_interval: Duration,
}

impl DhtTransport {
    pub fn new(seed: &[u8; 32], config: &DhtConfig) -> Result<Self, TransportError> {
        if config.watch_poll_interval.is_zero() {
            return Err(TransportError::Network(
                "DHT watch poll interval must be nonzero".to_owned(),
            ));
        }
        let mut builder = Dht::builder();
        if !config.bootstrap.is_empty() {
            builder.bootstrap(&config.bootstrap);
        }
        let dht = builder.build().map_err(map_io_error)?;
        Ok(Self::from_dht(seed, dht, config.watch_poll_interval))
    }

    fn from_dht(seed: &[u8; 32], dht: Dht, watch_poll_interval: Duration) -> Self {
        let signing_key = dht_signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            dht,
            signing_key,
            public_key,
            watch_poll_interval,
        }
    }

    fn get_latest(&self, id: &[u8; 16], after: Option<i64>) -> Option<MutableItem> {
        let mut best: Option<MutableItem> = None;
        for item in self.dht.get_mutable(&self.public_key, Some(id), after) {
            if best
                .as_ref()
                .is_none_or(|current| mutable_item_is_newer(&item, current))
            {
                best = Some(item);
            }
        }
        best
    }

    async fn slot_get_since(
        &self,
        id: &[u8; 16],
        since: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let transport = self.clone();
        let id = *id;
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
            .finish_non_exhaustive()
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
        let id = dht_channel_id(id)?;
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
            let item = MutableItem::new(transport.signing_key.clone(), &sealed, seq, Some(&id));
            transport
                .dht
                .put_mutable(item, cas)
                .map(drop)
                .map_err(map_put_error)
        })
        .await
    }

    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let id = dht_channel_id(id)?;
        self.slot_get_since(&id, 0).await
    }

    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream {
        let Ok(id) = dht_channel_id(id) else {
            return Box::pin(tokio_stream::iter([Err(TransportError::Network(
                "DHT channel id must be 16 bytes".to_owned(),
            ))]));
        };
        let transport = self.clone();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);

        tokio::spawn(async move {
            let mut since = since;
            loop {
                match transport.slot_get_since(&id, since).await {
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

fn dht_channel_id(id: &[u8]) -> Result<[u8; 16], TransportError> {
    id.try_into()
        .map_err(|_| TransportError::Network("DHT channel id must be 16 bytes".to_owned()))
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

fn map_io_error(err: std::io::Error) -> TransportError {
    TransportError::Other(Box::new(err))
}

fn map_put_error(err: mainline::errors::PutMutableError) -> TransportError {
    match err {
        mainline::errors::PutMutableError::Concurrency(_) => TransportError::Stale,
        mainline::errors::PutMutableError::Query(err) => TransportError::Other(Box::new(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
