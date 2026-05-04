use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use crate::config::DEFAULT_LONG_POLL_SECS;
use crate::dedup::Dedup;
use crate::error::{RecvError, SendError};
use crate::kdf::{NameError, TransportKind, validate_name};
use crate::namespace::NamespaceInner;

#[derive(Clone)]
pub struct Mailbox {
    pub(crate) inner: Arc<NamespaceInner>,
    pub(crate) name: String,
    dedup: Arc<std::sync::Mutex<Dedup>>,
}

impl Mailbox {
    pub(crate) fn new(inner: Arc<NamespaceInner>, name: &str) -> Result<Self, NameError> {
        validate_name(name)?;
        Ok(Self {
            dedup: Arc::new(std::sync::Mutex::new(Dedup::new(
                inner.coordinator.dedup_buffer(),
            ))),
            inner,
            name: name.to_owned(),
        })
    }

    pub async fn send(&self, payload: &[u8]) -> Result<SendReport, SendError> {
        self.inner
            .coordinator
            .mailbox_send(&self.name, payload)
            .await
    }

    pub async fn recv(&self) -> Result<RecvMessage, RecvError> {
        self.inner
            .coordinator
            .mailbox_recv(
                &self.name,
                std::time::Duration::from_secs(DEFAULT_LONG_POLL_SECS.into()),
                &self.dedup,
            )
            .await
    }

    /// Pre-warms underlying transports for this mailbox so the first message
    /// can be delivered without paying the per-transport setup cost. Reports
    /// success when at least one transport supports it; transports without
    /// session state report `Unsupported`.
    pub async fn subscribe(&self) -> Result<(), RecvError> {
        self.inner.coordinator.mailbox_subscribe(&self.name).await
    }

    pub fn try_recv(&self) -> Result<Option<RecvMessage>, RecvError> {
        Ok(None)
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvMessage {
    pub payload: Vec<u8>,
    pub via: TransportKind,
    pub signed_by: Option<VerifyingKey>,
}

#[derive(Debug)]
pub struct SendReport {
    pub delivered: Vec<TransportKind>,
    pub failed: Vec<(TransportKind, crate::TransportError)>,
}
