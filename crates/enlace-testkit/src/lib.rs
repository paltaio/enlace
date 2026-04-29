#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use enlace::{MailboxTransport, SlotTransport, SlotWatchStream, TransportError};
use tokio::sync::{Mutex, Notify, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;

const DEFAULT_DROP_PERCENT: u8 = 30;
const WATCH_BUFFER: usize = 64;

#[derive(Clone)]
pub struct InMemoryTransport {
    inner: Arc<InMemoryInner>,
}

struct InMemoryInner {
    state: Mutex<TransportState>,
    mailbox_notify: Notify,
    slot_updates: broadcast::Sender<SlotUpdate>,
}

#[derive(Default)]
struct TransportState {
    mailboxes: HashMap<Vec<u8>, VecDeque<Vec<u8>>>,
    slots: HashMap<Vec<u8>, (u64, Vec<u8>)>,
}

#[derive(Clone)]
struct SlotUpdate {
    id: Vec<u8>,
    version: u64,
    sealed: Vec<u8>,
}

impl InMemoryTransport {
    pub fn new() -> Self {
        let (slot_updates, _) = broadcast::channel(WATCH_BUFFER);
        Self {
            inner: Arc::new(InMemoryInner {
                state: Mutex::new(TransportState::default()),
                mailbox_notify: Notify::new(),
                slot_updates,
            }),
        }
    }
}

impl Default for InMemoryTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MailboxTransport for InMemoryTransport {
    async fn send(&self, id: &[u8], sealed: &[u8]) -> Result<(), TransportError> {
        let mut state = self.inner.state.lock().await;
        state
            .mailboxes
            .entry(id.to_vec())
            .or_default()
            .push_back(sealed.to_vec());
        drop(state);
        self.inner.mailbox_notify.notify_waiters();
        Ok(())
    }

    async fn recv(&self, id: &[u8], wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            let notified = self.inner.mailbox_notify.notified();
            {
                let mut state = self.inner.state.lock().await;
                if let Some(queue) = state.mailboxes.get_mut(id)
                    && let Some(sealed) = queue.pop_front()
                {
                    return Ok(Some(sealed));
                }
            }

            if wait.is_zero() {
                return Ok(None);
            }

            if tokio::time::timeout(wait, notified).await.is_err() {
                return Ok(None);
            }
        }
    }
}

#[async_trait]
impl SlotTransport for InMemoryTransport {
    async fn put(&self, id: &[u8], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        let mut state = self.inner.state.lock().await;
        if state
            .slots
            .get(id)
            .is_some_and(|(current, _)| *current >= version)
        {
            return Err(TransportError::Stale);
        }
        state.slots.insert(id.to_vec(), (version, sealed.to_vec()));
        drop(state);

        let _ = self.inner.slot_updates.send(SlotUpdate {
            id: id.to_vec(),
            version,
            sealed: sealed.to_vec(),
        });
        Ok(())
    }

    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let state = self.inner.state.lock().await;
        Ok(state.slots.get(id).cloned())
    }

    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream {
        let id = id.to_vec();
        let mut updates = self.inner.slot_updates.subscribe();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);

        tokio::spawn(async move {
            loop {
                match updates.recv().await {
                    Ok(update) if update.id == id && update.version > since => {
                        if tx.send(Ok((update.version, update.sealed))).await.is_err() {
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

#[derive(Clone)]
pub struct LossyTransport<T = InMemoryTransport> {
    inner: T,
    drop_percent: u8,
}

impl LossyTransport<InMemoryTransport> {
    pub fn new() -> Self {
        Self::with_inner(InMemoryTransport::new())
    }
}

impl Default for LossyTransport<InMemoryTransport> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LossyTransport<T> {
    pub fn with_inner(inner: T) -> Self {
        Self {
            inner,
            drop_percent: DEFAULT_DROP_PERCENT,
        }
    }

    #[must_use]
    pub fn with_drop_percent(mut self, drop_percent: u8) -> Self {
        self.drop_percent = drop_percent.min(100);
        self
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    fn should_drop(&self) -> bool {
        self.drop_percent > 0 && rand::random::<u8>() % 100 < self.drop_percent
    }
}

#[async_trait]
impl<T> MailboxTransport for LossyTransport<T>
where
    T: MailboxTransport + Send + Sync,
{
    async fn send(&self, id: &[u8], sealed: &[u8]) -> Result<(), TransportError> {
        if self.should_drop() {
            return Ok(());
        }
        self.inner.send(id, sealed).await
    }

    async fn recv(&self, id: &[u8], wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        self.inner.recv(id, wait).await
    }
}

#[async_trait]
impl<T> SlotTransport for LossyTransport<T>
where
    T: SlotTransport + Send + Sync,
{
    async fn put(&self, id: &[u8], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        if self.should_drop() {
            return Ok(());
        }
        self.inner.put(id, version, sealed).await
    }

    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        self.inner.get(id).await
    }

    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream {
        self.inner.watch(id, since)
    }
}

#[derive(Clone)]
pub struct DelayingTransport<T = InMemoryTransport> {
    inner: T,
    max_delay: Duration,
}

impl DelayingTransport<InMemoryTransport> {
    pub fn new() -> Self {
        Self::with_inner(InMemoryTransport::new())
    }
}

impl Default for DelayingTransport<InMemoryTransport> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> DelayingTransport<T> {
    pub fn with_inner(inner: T) -> Self {
        Self {
            inner,
            max_delay: Duration::from_millis(25),
        }
    }

    #[must_use]
    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    async fn delay(&self) {
        if self.max_delay.is_zero() {
            return;
        }
        let max_millis = u64::try_from(self.max_delay.as_millis()).unwrap_or(u64::MAX);
        let delay = rand::random::<u64>() % max_millis.saturating_add(1);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

#[async_trait]
impl<T> MailboxTransport for DelayingTransport<T>
where
    T: MailboxTransport + Send + Sync,
{
    async fn send(&self, id: &[u8], sealed: &[u8]) -> Result<(), TransportError> {
        self.delay().await;
        self.inner.send(id, sealed).await
    }

    async fn recv(&self, id: &[u8], wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        self.delay().await;
        self.inner.recv(id, wait).await
    }
}

#[async_trait]
impl<T> SlotTransport for DelayingTransport<T>
where
    T: SlotTransport + Send + Sync,
{
    async fn put(&self, id: &[u8], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        self.delay().await;
        self.inner.put(id, version, sealed).await
    }

    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        self.delay().await;
        self.inner.get(id).await
    }

    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream {
        self.inner.watch(id, since)
    }
}
