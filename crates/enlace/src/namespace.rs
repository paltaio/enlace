use std::sync::Arc;

use crate::config::Config;
use crate::coordinator::{Coordinator, TransportEndpoint};
use crate::error::OpenError;
use crate::kdf::NameError;
use crate::mailbox::Mailbox;
use crate::slot::Slot;
#[cfg(feature = "http")]
use crate::transports::HttpTransport;
#[cfg(feature = "iroh")]
use crate::transports::IrohTransport;
#[cfg(feature = "pkarr")]
use crate::transports::PkarrTransport;
use crate::transports::{HealthReport, HealthTracker};

#[derive(Clone)]
pub struct Namespace {
    pub(crate) inner: Arc<NamespaceInner>,
}

pub(crate) struct NamespaceInner {
    pub(crate) coordinator: Arc<Coordinator>,
    #[cfg(feature = "http")]
    pub(crate) http: Option<Arc<HttpTransport>>,
    #[cfg(feature = "pkarr")]
    pub(crate) pkarr: Option<Arc<PkarrTransport>>,
    #[cfg(feature = "iroh")]
    pub(crate) iroh: Option<Arc<IrohTransport>>,
}

impl Namespace {
    #[allow(clippy::unused_async)]
    pub async fn open(seed: &[u8; 32], config: Config) -> Result<Self, OpenError> {
        validate_seed(seed)?;
        validate_config(&config)?;

        if config.signing.is_some() && config.trusted.is_empty() {
            tracing::warn!(
                "signing key configured without trusted keys; incoming messages will not be verified"
            );
        }

        let state = config.state.store();
        let mut transports = Vec::new();
        #[cfg(feature = "http")]
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
        #[cfg(feature = "pkarr")]
        let pkarr = if let Some(pkarr_config) = &config.pkarr {
            let pkarr = Arc::new(PkarrTransport::new(seed, pkarr_config).map_err(|err| {
                OpenError::TransportInit(crate::TransportKind::Pkarr, Box::new(err))
            })?);
            let transport: Arc<dyn crate::transports::Transport> = pkarr.clone();
            transports.push(TransportEndpoint {
                kind: crate::TransportKind::Pkarr,
                transport,
            });
            Some(pkarr)
        } else {
            None
        };
        #[cfg(feature = "iroh")]
        let iroh = open_iroh_transport(&config, state.as_ref(), &mut transports).await?;
        for configured in &config.transports {
            transports.push(TransportEndpoint {
                kind: configured.kind,
                transport: Arc::clone(&configured.transport),
            });
        }
        let health = Arc::new(HealthTracker::from_config(&config));
        let coordinator = Arc::new(Coordinator::new(seed, transports, &config, state, health));

        Ok(Self {
            inner: Arc::new(NamespaceInner {
                coordinator,
                #[cfg(feature = "http")]
                http,
                #[cfg(feature = "pkarr")]
                pkarr,
                #[cfg(feature = "iroh")]
                iroh,
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
    #[cfg(feature = "http")]
    pub fn http(&self) -> Option<&HttpTransport> {
        self.inner.http.as_deref()
    }

    #[must_use]
    #[cfg(feature = "pkarr")]
    pub fn pkarr(&self) -> Option<&PkarrTransport> {
        self.inner.pkarr.as_deref()
    }

    #[must_use]
    #[cfg(feature = "iroh")]
    pub fn iroh(&self) -> Option<&IrohTransport> {
        self.inner.iroh.as_deref()
    }

    #[must_use]
    pub fn health(&self) -> HealthReport {
        self.inner.coordinator.health()
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
    Ok(())
}

#[cfg(feature = "iroh")]
async fn open_iroh_transport(
    config: &Config,
    state: &dyn crate::state::StateStore,
    transports: &mut Vec<TransportEndpoint>,
) -> Result<Option<Arc<IrohTransport>>, OpenError> {
    if let Some(iroh_config) = &config.iroh {
        let iroh = Arc::new(IrohTransport::new(iroh_config, state).await.map_err(
            |err| match err {
                crate::transports::IrohInitError::State(err) => OpenError::State(err),
                crate::transports::IrohInitError::Transport(err) => {
                    OpenError::TransportInit(crate::TransportKind::Iroh, Box::new(err))
                }
            },
        )?);
        let transport: Arc<dyn crate::transports::Transport> = iroh.clone();
        transports.push(TransportEndpoint {
            kind: crate::TransportKind::Iroh,
            transport,
        });
        Ok(Some(iroh))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
#[cfg(feature = "iroh")]
mod tests {
    use super::*;

    use crate::config::IrohConfig;

    #[tokio::test]
    async fn iroh_config_exposes_transport_handle() {
        let namespace = Namespace::open(
            &[1; 32],
            Config {
                iroh: Some(IrohConfig::default()),
                ..Config::default()
            },
        )
        .await
        .unwrap();

        assert!(namespace.iroh().is_some());
    }
}
