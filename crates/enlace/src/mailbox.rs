use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use crate::error::{RecvError, SendError};
use crate::kdf::{NameError, TransportKind, validate_name};
use crate::namespace::NamespaceInner;

#[derive(Clone)]
pub struct Mailbox {
    pub(crate) inner: Arc<NamespaceInner>,
    pub(crate) name: String,
}

impl Mailbox {
    pub(crate) fn new(inner: Arc<NamespaceInner>, name: &str) -> Result<Self, NameError> {
        validate_name(name)?;
        Ok(Self {
            inner,
            name: name.to_owned(),
        })
    }

    #[allow(clippy::unused_async)]
    pub async fn send(&self, _payload: &[u8]) -> Result<SendReport, SendError> {
        let _configured_transports = self.inner.config.transport_count();
        Err(SendError::AllTransportsFailed(Vec::new()))
    }

    #[allow(clippy::unused_async)]
    pub async fn recv(&self) -> Result<RecvMessage, RecvError> {
        Err(RecvError::Closed)
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
