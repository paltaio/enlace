use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use crate::error::SlotError;
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

    #[allow(clippy::unused_async)]
    pub async fn put(&self, _payload: &[u8]) -> Result<PutReport, SlotError> {
        let _version = self.inner.state.next_local_slot_version(&self.name)?;
        Err(SlotError::AllTransportsFailed(Vec::new()))
    }

    #[allow(clippy::unused_async)]
    pub async fn get(&self) -> Result<Option<SlotValue>, SlotError> {
        Ok(None)
    }

    #[must_use]
    pub fn watch(&self) -> SlotWatch {
        SlotWatch {
            name: self.name.clone(),
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotWatch {
    name: String,
}

impl SlotWatch {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}
