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
const WATCH_POLL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct DhtTransport {
    dht: Dht,
    signing_key: SigningKey,
    public_key: [u8; 32],
}

impl DhtTransport {
    pub fn new(seed: &[u8; 32], config: &DhtConfig) -> Result<Self, TransportError> {
        let mut builder = Dht::builder();
        if !config.bootstrap.is_empty() {
            builder.bootstrap(&config.bootstrap);
        }
        let dht = builder.build().map_err(map_io_error)?;
        Ok(Self::from_dht(seed, dht))
    }

    fn from_dht(seed: &[u8; 32], dht: Dht) -> Self {
        let signing_key = dht_signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            dht,
            signing_key,
            public_key,
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

    async fn get_mailbox_once(&self, id: &[u8; 16]) -> Result<Option<Vec<u8>>, TransportError> {
        let transport = self.clone();
        let id = *id;
        run_blocking(move || {
            let Some(current) = transport.get_latest(&id, None) else {
                return Ok(None);
            };
            if current.value().is_empty() {
                return Ok(None);
            }

            let clear_seq = next_seq(current.seq())?;
            let clear = MutableItem::new(transport.signing_key.clone(), &[], clear_seq, Some(&id));
            transport
                .dht
                .put_mutable(clear, Some(current.seq()))
                .map_err(map_put_error)?;
            Ok(Some(current.value().to_vec()))
        })
        .await
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
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MailboxTransport for DhtTransport {
    async fn send(&self, id: &[u8; 16], sealed: &[u8]) -> Result<(), TransportError> {
        ensure_value_fits(sealed)?;
        let transport = self.clone();
        let id = *id;
        let sealed = sealed.to_vec();
        run_blocking(move || {
            let current = transport.get_latest(&id, None);
            let (seq, cas) = current.as_ref().map_or(Ok((1, None)), |item| {
                next_seq(item.seq()).map(|seq| (seq, Some(item.seq())))
            })?;
            let item = MutableItem::new(transport.signing_key.clone(), &sealed, seq, Some(&id));
            transport
                .dht
                .put_mutable(item, cas)
                .map(drop)
                .map_err(map_put_error)
        })
        .await
    }

    async fn recv(&self, id: &[u8; 16], wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        let start = tokio::time::Instant::now();
        loop {
            if let Some(value) = self.get_mailbox_once(id).await? {
                return Ok(Some(value));
            }
            if wait.is_zero() || start.elapsed() >= wait {
                return Ok(None);
            }
            tokio::time::sleep(WATCH_POLL.min(wait.saturating_sub(start.elapsed()))).await;
        }
    }
}

#[async_trait]
impl SlotTransport for DhtTransport {
    async fn put(&self, id: &[u8; 16], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        ensure_value_fits(sealed)?;
        let transport = self.clone();
        let id = *id;
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

    async fn get(&self, id: &[u8; 16]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        self.slot_get_since(id, 0).await
    }

    fn watch(&self, id: &[u8; 16], since: u64) -> SlotWatchStream {
        let transport = self.clone();
        let id = *id;
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
                tokio::time::sleep(WATCH_POLL).await;
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

fn ensure_value_fits(value: &[u8]) -> Result<(), TransportError> {
    if value.len() > MAX_MUTABLE_VALUE_BYTES {
        return Err(TransportError::BodyTooLarge);
    }
    Ok(())
}

fn next_seq(seq: i64) -> Result<i64, TransportError> {
    seq.checked_add(1)
        .ok_or_else(|| TransportError::Network("DHT mutable sequence overflow".to_owned()))
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
}
