use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;

use crate::error::{RecvError, SlotError};
use crate::kdf::{NameError, TransportKind, validate_name};
use crate::namespace::NamespaceInner;

#[derive(Clone)]
pub struct Slot {
    pub(crate) inner: Arc<NamespaceInner>,
    pub(crate) name: String,
}

impl Slot {
    pub(crate) fn new(inner: Arc<NamespaceInner>, name: &str) -> Result<Self, NameError> {
        validate_name(name)?;
        Ok(Self {
            inner,
            name: name.to_owned(),
        })
    }

    pub async fn put(&self, payload: &[u8]) -> Result<PutReport, SlotError> {
        self.inner.coordinator.slot_put(&self.name, payload).await
    }

    pub async fn get(&self) -> Result<Option<SlotValue>, SlotError> {
        self.inner.coordinator.slot_get(&self.name).await
    }

    #[must_use]
    pub fn watch(&self) -> SlotWatch {
        self.inner.coordinator.slot_watch(self.name.clone())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotValue {
    pub version: u64,
    pub payload: Vec<u8>,
    pub via: TransportKind,
    pub signed_by: Option<VerifyingKey>,
}

#[derive(Debug)]
pub struct PutReport {
    pub version: u64,
    pub stored: Vec<TransportKind>,
    pub failed: Vec<(TransportKind, crate::TransportError)>,
}

#[derive(Debug)]
pub struct SlotWatch {
    name: String,
    rx: mpsc::Receiver<SlotValue>,
}

impl SlotWatch {
    pub(crate) fn new(name: String, rx: mpsc::Receiver<SlotValue>) -> Self {
        Self { name, rx }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn recv(&mut self) -> Result<SlotValue, RecvError> {
        self.rx.recv().await.ok_or(RecvError::Closed)
    }
}
