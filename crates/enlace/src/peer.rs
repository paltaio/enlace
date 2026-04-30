//! Public-key peer identity types.

use std::fmt;

use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::config::IrohEndpointAddr;
use crate::state::{State, StateError};

pub const PEER_ID_LEN: usize = 32;
pub const GROUP_ID_LEN: usize = 32;
pub const GROUP_KEY_ID_LEN: usize = 32;
pub const GROUP_KEY_SECRET_LEN: usize = 32;

/// Stable cryptographic peer identity derived from the signing public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; PEER_ID_LEN]);

impl PeerId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PEER_ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; PEER_ID_LEN] {
        self.0
    }

    #[must_use]
    pub fn from_signing_key(signing_key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"enlace/v1/pkey/peer-id");
        hasher.update(signing_key.to_bytes());
        Self(hasher.finalize().into())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({self})")
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Local identity material for public-key mode.
pub struct PeerIdentity {
    pub signing: SigningKey,
    pub exchange: StaticSecret,
    pub iroh_secret: Option<Zeroizing<[u8; 32]>>,
}

impl PeerIdentity {
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut signing = Zeroizing::new([0u8; 32]);
        let mut exchange = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(signing.as_mut_slice());
        rng.fill_bytes(exchange.as_mut_slice());

        Self {
            signing: SigningKey::from_bytes(&signing),
            exchange: StaticSecret::from(*exchange),
            iroh_secret: None,
        }
    }

    #[must_use]
    pub fn from_parts(
        signing: SigningKey,
        exchange: StaticSecret,
        iroh_secret: Option<[u8; 32]>,
    ) -> Self {
        Self {
            signing,
            exchange,
            iroh_secret: iroh_secret.map(Zeroizing::new),
        }
    }

    pub fn load_or_generate(state: &State) -> Result<Self, StateError> {
        if let Some(identity) = state.peer_identity()? {
            return Ok(identity);
        }

        let identity = Self::generate();
        identity.save(state)?;
        Ok(identity)
    }

    pub fn save(&self, state: &State) -> Result<(), StateError> {
        state.store_peer_identity(self)
    }

    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_signing_key(&self.signing.verifying_key())
    }

    #[must_use]
    pub fn card(&self) -> PeerCard {
        PeerCard::new(
            self.signing.verifying_key(),
            X25519PublicKey::from(&self.exchange).to_bytes(),
            None,
        )
    }

    #[must_use]
    pub fn card_with_iroh_endpoint(&self, endpoint: IrohEndpointAddr) -> PeerCard {
        PeerCard::new(
            self.signing.verifying_key(),
            X25519PublicKey::from(&self.exchange).to_bytes(),
            Some(endpoint),
        )
    }
}

/// Caller-defined public-key group address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId([u8; GROUP_ID_LEN]);

impl GroupId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; GROUP_ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; GROUP_ID_LEN] {
        self.0
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupId({self})")
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Caller-defined group key id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupKeyId([u8; GROUP_KEY_ID_LEN]);

impl GroupKeyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; GROUP_KEY_ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; GROUP_KEY_ID_LEN] {
        self.0
    }
}

impl fmt::Debug for GroupKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupKeyId({self})")
    }
}

impl fmt::Display for GroupKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Symmetric key material supplied by caller code for group mode.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupKey {
    pub id: GroupKeyId,
    pub secret: Zeroizing<[u8; GROUP_KEY_SECRET_LEN]>,
}

impl GroupKey {
    #[must_use]
    pub fn new(id: GroupKeyId, secret: [u8; GROUP_KEY_SECRET_LEN]) -> Self {
        Self {
            id,
            secret: Zeroizing::new(secret),
        }
    }
}

impl fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupKey")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerIdentity")
            .field("peer_id", &self.peer_id())
            .field("signing", &"<redacted>")
            .field("exchange", &"<redacted>")
            .field(
                "iroh_secret",
                &self.iroh_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Public card exchanged out of band when pairing peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCard {
    pub peer_id: PeerId,
    pub signing_key: VerifyingKey,
    pub exchange_key: [u8; 32],
    pub iroh_endpoint: Option<IrohEndpointAddr>,
}

impl PeerCard {
    #[must_use]
    pub fn new(
        signing_key: VerifyingKey,
        exchange_key: [u8; 32],
        iroh_endpoint: Option<IrohEndpointAddr>,
    ) -> Self {
        Self {
            peer_id: PeerId::from_signing_key(&signing_key),
            signing_key,
            exchange_key,
            iroh_endpoint,
        }
    }

    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.peer_id == PeerId::from_signing_key(&self.signing_key)
    }
}

/// One-way trust entry. Authorization policy stays with caller code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPeer {
    pub card: PeerCard,
}

impl TrustedPeer {
    #[must_use]
    pub const fn new(card: PeerCard) -> Self {
        Self { card }
    }

    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.card.peer_id
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn identity(signing_byte: u8, exchange_byte: u8) -> PeerIdentity {
        PeerIdentity::from_parts(
            SigningKey::from_bytes(&[signing_byte; 32]),
            StaticSecret::from([exchange_byte; 32]),
            None,
        )
    }

    #[test]
    fn peer_id_is_derived_from_signing_public_key() {
        let identity = identity(7, 9);
        let expected = PeerId::from_signing_key(&identity.signing.verifying_key());

        assert_eq!(identity.peer_id(), expected);
        assert_eq!(identity.peer_id().to_bytes().len(), PEER_ID_LEN);
    }

    #[test]
    fn peer_id_changes_with_signing_key() {
        assert_ne!(identity(1, 9).peer_id(), identity(2, 9).peer_id());
    }

    #[test]
    fn peer_id_round_trips_bytes_and_formats_hex() {
        let peer_id = PeerId::from_bytes([0xabu8; PEER_ID_LEN]);

        assert_eq!(PeerId::from_bytes(peer_id.to_bytes()), peer_id);
        assert_eq!(peer_id.to_string().len(), PEER_ID_LEN * 2);
        assert!(peer_id.to_string().chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn card_exports_public_material() {
        let identity = identity(3, 4);
        let card = identity.card();

        assert_eq!(card.peer_id, identity.peer_id());
        assert_eq!(card.signing_key, identity.signing.verifying_key());
        assert_eq!(
            card.exchange_key,
            X25519PublicKey::from(&identity.exchange).to_bytes()
        );
        assert_eq!(card.iroh_endpoint, None);
        assert!(card.is_consistent());
    }

    #[test]
    fn card_can_include_iroh_endpoint_hint() {
        let endpoint = IrohEndpointAddr {
            endpoint_id: [8u8; 32],
            relay_urls: Vec::new(),
            direct_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4096)],
        };
        let card = identity(5, 6).card_with_iroh_endpoint(endpoint.clone());

        assert_eq!(card.iroh_endpoint, Some(endpoint));
    }

    #[test]
    fn peer_card_detects_mismatched_peer_id() {
        let mut card = identity(1, 2).card();
        card.peer_id = identity(3, 2).peer_id();

        assert!(!card.is_consistent());
    }

    #[test]
    fn trusted_peer_keeps_one_way_card() {
        let card = identity(11, 12).card();
        let trusted = TrustedPeer::new(card.clone());

        assert_eq!(trusted.peer_id(), card.peer_id);
        assert_eq!(trusted.card, card);
    }

    #[test]
    fn identity_debug_redacts_secret_material() {
        let identity = PeerIdentity::from_parts(
            SigningKey::from_bytes(&[0x11; 32]),
            StaticSecret::from([0x22; 32]),
            Some([0x33; 32]),
        );
        let rendered = format!("{identity:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("11, 11"));
        assert!(!rendered.contains("22, 22"));
        assert!(!rendered.contains("33, 33"));
    }

    #[test]
    fn group_ids_round_trip_and_format_hex() {
        let group = GroupId::from_bytes([0x12; GROUP_ID_LEN]);
        let key = GroupKeyId::from_bytes([0x34; GROUP_KEY_ID_LEN]);

        assert_eq!(GroupId::from_bytes(group.to_bytes()), group);
        assert_eq!(GroupKeyId::from_bytes(key.to_bytes()), key);
        assert_eq!(group.to_string().len(), GROUP_ID_LEN * 2);
        assert_eq!(key.to_string().len(), GROUP_KEY_ID_LEN * 2);
    }

    #[test]
    fn group_key_debug_redacts_secret() {
        let key = GroupKey::new(GroupKeyId::from_bytes([1; GROUP_KEY_ID_LEN]), [0x55; 32]);
        let rendered = format!("{key:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("55, 55"));
    }

    #[test]
    fn identity_saves_through_state() {
        let state = State::memory();
        let identity = identity(9, 10);

        identity.save(&state).unwrap();
        let loaded = PeerIdentity::load_or_generate(&state).unwrap();

        assert_eq!(loaded.peer_id(), identity.peer_id());
        assert_eq!(loaded.card(), identity.card());
    }
}
