use std::sync::Arc;

use crate::config::Config;
use crate::coordinator::{Coordinator, TransportEndpoint};
use crate::error::OpenError;
use crate::kdf::NameError;
use crate::mailbox::Mailbox;
use crate::slot::Slot;
use crate::state::InMemoryStateStore;
use crate::transports::{DhtTransport, HealthReport, HttpTransport, IrohTransport, PkarrTransport};

#[derive(Clone)]
pub struct Namespace {
    pub(crate) inner: Arc<NamespaceInner>,
}

pub(crate) struct NamespaceInner {
    pub(crate) config: Config,
    pub(crate) coordinator: Arc<Coordinator>,
    pub(crate) http: Option<Arc<HttpTransport>>,
}

impl Namespace {
    #[allow(clippy::unused_async)]
    pub async fn open(seed: &[u8; 32], mut config: Config) -> Result<Self, OpenError> {
        validate_seed(seed)?;
        validate_config(&config)?;

        if config.signing.is_some() && config.trusted.is_empty() {
            tracing::warn!(
                "signing key configured without trusted keys; incoming messages will not be verified"
            );
        }

        let state = config
            .state
            .take()
            .unwrap_or_else(|| Arc::new(InMemoryStateStore::new()));
        let mut transports = Vec::new();
        let http = if let Some(http_config) = config.http.clone() {
            let http = Arc::new(HttpTransport::new(http_config).map_err(|err| {
                OpenError::TransportInit(crate::TransportKind::Http, Box::new(err))
            })?);
            let transport: Arc<dyn crate::transports::Transport> = http.clone();
            transports.push(TransportEndpoint {
                kind: crate::TransportKind::Http,
                transport,
            });
            Some(http)
        } else {
            None
        };
        for configured in &config.transports {
            transports.push(TransportEndpoint {
                kind: configured.kind,
                transport: Arc::clone(&configured.transport),
            });
        }
        let coordinator = Arc::new(Coordinator::new(
            seed,
            transports,
            config.signing.clone(),
            config.trusted.clone(),
            config.dedup_buffer,
            config.max_plaintext_bytes,
            state,
        ));

        Ok(Self {
            inner: Arc::new(NamespaceInner {
                config,
                coordinator,
                http,
            }),
        })
    }

    pub fn mailbox(&self, name: &str) -> Result<Mailbox, NameError> {
        Mailbox::new(Arc::clone(&self.inner), name)
    }

    pub fn slot(&self, name: &str) -> Result<Slot, NameError> {
        Slot::new(Arc::clone(&self.inner), name)
    }

    #[must_use]
    pub fn http(&self) -> Option<&HttpTransport> {
        self.inner.http.as_deref()
    }

    #[must_use]
    pub fn pkarr(&self) -> Option<&PkarrTransport> {
        None
    }

    #[must_use]
    pub fn dht(&self) -> Option<&DhtTransport> {
        None
    }

    #[must_use]
    pub fn iroh(&self) -> Option<&IrohTransport> {
        None
    }

    #[must_use]
    pub fn health(&self) -> HealthReport {
        HealthReport::from_config(&self.inner.config)
    }
}

fn validate_seed(seed: &[u8; 32]) -> Result<(), OpenError> {
    if seed.iter().all(|&b| b == 0) {
        return Err(OpenError::InvalidSeed);
    }
    Ok(())
}

fn validate_config(config: &Config) -> Result<(), OpenError> {
    if config.transport_count() == 0 {
        return Err(OpenError::NoTransport);
    }
    if !config.trusted.is_empty() && config.signing.is_none() {
        return Err(OpenError::TrustedWithoutSigning);
    }
    Ok(())
}
