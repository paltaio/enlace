use std::fmt;
use std::sync::RwLock;

use crate::config::{IrohConfig, IrohEndpointAddr};
use crate::state::{StateError, StateStore};

pub struct IrohTransport {
    endpoint_id: [u8; 32],
    peers: RwLock<Vec<IrohEndpointAddr>>,
}

impl IrohTransport {
    pub(crate) fn new(config: &IrohConfig, state: &dyn StateStore) -> Result<Self, StateError> {
        let secret_key = if let Some(secret) = state.iroh_keypair()? {
            iroh::SecretKey::from_bytes(&secret)
        } else {
            let secret_key = iroh::SecretKey::generate();
            state.store_iroh_keypair(&secret_key.to_bytes())?;
            secret_key
        };
        let endpoint_id = *secret_key.public().as_bytes();

        Ok(Self {
            endpoint_id,
            peers: RwLock::new(config.peers.clone()),
        })
    }

    #[must_use]
    pub fn endpoint_id(&self) -> [u8; 32] {
        self.endpoint_id
    }

    #[must_use]
    pub fn endpoint_addr(&self) -> IrohEndpointAddr {
        IrohEndpointAddr {
            endpoint_id: self.endpoint_id,
            relay_urls: Vec::new(),
            direct_addrs: Vec::new(),
        }
    }

    #[must_use]
    pub fn peers(&self) -> Vec<IrohEndpointAddr> {
        self.peers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn add_peer(&self, peer: IrohEndpointAddr) {
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = peers
            .iter_mut()
            .find(|existing| existing.endpoint_id == peer.endpoint_id)
        {
            *existing = peer;
        } else {
            peers.push(peer);
        }
    }
}

impl fmt::Debug for IrohTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohTransport")
            .field("endpoint_id", &self.endpoint_id)
            .field("peers", &self.peers())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use url::Url;

    use crate::config::IrohRelayMode;
    use crate::state::InMemoryStateStore;

    #[test]
    fn endpoint_id_comes_from_persisted_keypair() {
        let state = InMemoryStateStore::new();
        let first = IrohTransport::new(&IrohConfig::default(), &state).unwrap();
        let second = IrohTransport::new(&IrohConfig::default(), &state).unwrap();

        assert_eq!(first.endpoint_id(), second.endpoint_id());
        assert_eq!(first.endpoint_addr().endpoint_id, first.endpoint_id());
    }

    #[test]
    fn peers_can_be_seeded_and_replaced() {
        let peer_id = [7; 32];
        let original = IrohEndpointAddr {
            endpoint_id: peer_id,
            relay_urls: vec![Url::parse("https://relay.example").unwrap()],
            direct_addrs: Vec::new(),
        };
        let state = InMemoryStateStore::new();
        let config = IrohConfig {
            relay_mode: IrohRelayMode::Disabled,
            bind_addrs: Vec::new(),
            peers: vec![original],
            max_message_bytes: 1024,
            max_streams_per_peer: 2,
            max_conns_per_peer: 1,
        };
        let transport = IrohTransport::new(&config, &state).unwrap();

        assert_eq!(transport.peers().len(), 1);

        transport.add_peer(IrohEndpointAddr {
            endpoint_id: peer_id,
            relay_urls: Vec::new(),
            direct_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)],
        });

        let peers = transport.peers();
        assert_eq!(peers.len(), 1);
        assert!(peers[0].relay_urls.is_empty());
        assert_eq!(peers[0].direct_addrs.len(), 1);
    }
}
