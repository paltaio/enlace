use crate::config::Config;
use crate::kdf::TransportKind;

#[derive(Debug)]
pub struct HttpTransport {
    _private: (),
}

#[derive(Debug)]
pub struct PkarrTransport {
    _private: (),
}

#[derive(Debug)]
pub struct DhtTransport {
    _private: (),
}

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
