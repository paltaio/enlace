use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use futures_core::Stream;

use crate::config::Config;
use crate::error::TransportError;
use crate::kdf::TransportKind;

mod dht;
mod http;
mod pkarr;

pub use dht::DhtTransport;
pub use http::HttpTransport;
pub use pkarr::PkarrTransport;

pub type SlotWatchStream =
    Pin<Box<dyn Stream<Item = Result<(u64, Vec<u8>), TransportError>> + Send>>;

#[async_trait]
pub trait MailboxTransport: Send + Sync {
    async fn send(&self, id: &[u8; 16], sealed: &[u8]) -> Result<(), TransportError>;
    async fn recv(&self, id: &[u8; 16], wait: Duration) -> Result<Option<Vec<u8>>, TransportError>;
}

#[async_trait]
pub trait SlotTransport: Send + Sync {
    async fn put(&self, id: &[u8; 16], version: u64, sealed: &[u8]) -> Result<(), TransportError>;
    async fn get(&self, id: &[u8; 16]) -> Result<Option<(u64, Vec<u8>)>, TransportError>;
    fn watch(&self, id: &[u8; 16], since: u64) -> SlotWatchStream;
}

pub trait Transport: MailboxTransport + SlotTransport {}

impl<T> Transport for T where T: MailboxTransport + SlotTransport {}

#[derive(Debug)]
pub struct IrohTransport {
    _private: (),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub transports: Vec<TransportHealth>,
}

impl HealthReport {
    pub(crate) fn from_config(config: &Config) -> Self {
        let mut transports = Vec::with_capacity(config.transport_count());
        if config.http.is_some() {
            transports.push(TransportHealth::configured(TransportKind::Http));
        }
        if config.pkarr.is_some() {
            transports.push(TransportHealth::configured(TransportKind::Pkarr));
        }
        if config.dht.is_some() {
            transports.push(TransportHealth::configured(TransportKind::Dht));
        }
        if config.iroh.is_some() {
            transports.push(TransportHealth::configured(TransportKind::Iroh));
        }
        for transport in &config.transports {
            transports.push(TransportHealth::configured(transport.kind));
        }
        Self { transports }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHealth {
    pub kind: TransportKind,
    pub configured: bool,
}

impl TransportHealth {
    const fn configured(kind: TransportKind) -> Self {
        Self {
            kind,
            configured: true,
        }
    }
}
