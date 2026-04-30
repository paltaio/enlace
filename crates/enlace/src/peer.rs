//! Public-key peer identity types.

use std::convert::TryInto;
use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use url::Url;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::config::IrohEndpointAddr;
use crate::state::{State, StateError};

pub const PEER_ID_LEN: usize = 32;
pub const GROUP_ID_LEN: usize = 32;
pub const GROUP_KEY_ID_LEN: usize = 32;
pub const GROUP_KEY_SECRET_LEN: usize = 32;
const PEER_CARD_EXPORT_PREFIX: &str = "enlace-peer-card-v1:";
const PEER_CARD_RECORD_VERSION: u8 = 1;

/// Failure modes when importing or validating a public peer card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCardError {
    /// Exported text did not use the expected prefix.
    MissingPrefix,
    /// Exported text was not valid unpadded URL-safe base64.
    InvalidEncoding,
    /// Binary card used an unsupported version.
    UnsupportedVersion,
    /// Binary card ended before a required field was complete.
    Truncated(&'static str),
    /// Binary card had extra bytes after the last field.
    TrailingBytes,
    /// Card contained an invalid Ed25519 verifying key.
    InvalidSigningKey,
    /// `peer_id` did not match the signing public key.
    InconsistentPeerId,
    /// X25519 public exchange key was all zero.
    EmptyExchangeKey,
    /// Iroh endpoint id was all zero.
    InvalidIrohEndpoint,
    /// String field was not UTF-8.
    InvalidUtf8(&'static str),
    /// Relay URL field was not a valid URL.
    InvalidRelayUrl,
    /// Direct address field was not a socket address.
    InvalidDirectAddr,
    /// Repeated field count exceeded platform limits.
    CountTooLarge(&'static str),
    /// Field length exceeded the binary card format.
    FieldTooLarge(&'static str),
}

impl fmt::Display for PeerCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => f.write_str("peer card export prefix missing"),
            Self::InvalidEncoding => f.write_str("peer card export encoding invalid"),
            Self::UnsupportedVersion => f.write_str("peer card version unsupported"),
            Self::Truncated(field) => write!(f, "peer card ended inside {field}"),
            Self::TrailingBytes => f.write_str("peer card has trailing bytes"),
            Self::InvalidSigningKey => f.write_str("peer card signing key invalid"),
            Self::InconsistentPeerId => f.write_str("peer card id does not match signing key"),
            Self::EmptyExchangeKey => f.write_str("peer card exchange key is empty"),
            Self::InvalidIrohEndpoint => f.write_str("peer card iroh endpoint invalid"),
            Self::InvalidUtf8(field) => write!(f, "peer card {field} is not utf-8"),
            Self::InvalidRelayUrl => f.write_str("peer card relay url invalid"),
            Self::InvalidDirectAddr => f.write_str("peer card direct address invalid"),
            Self::CountTooLarge(field) => write!(f, "peer card {field} count too large"),
            Self::FieldTooLarge(field) => write!(f, "peer card {field} too large"),
        }
    }
}

impl StdError for PeerCardError {}

/// Failure modes for trust-set mutations.
#[derive(Debug)]
pub enum TrustError {
    /// The supplied card failed validation.
    InvalidPeerCard(PeerCardError),
    /// Trust storage failed.
    State(StateError),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPeerCard(err) => write!(f, "invalid peer card: {err}"),
            Self::State(err) => write!(f, "state store error: {err}"),
        }
    }
}

impl StdError for TrustError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidPeerCard(err) => Some(err),
            Self::State(err) => Some(err),
        }
    }
}

impl From<PeerCardError> for TrustError {
    fn from(err: PeerCardError) -> Self {
        Self::InvalidPeerCard(err)
    }
}

impl From<StateError> for TrustError {
    fn from(err: StateError) -> Self {
        Self::State(err)
    }
}

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

    pub fn validate(&self) -> Result<(), PeerCardError> {
        if !self.is_consistent() {
            return Err(PeerCardError::InconsistentPeerId);
        }
        if self.exchange_key.iter().all(|&byte| byte == 0) {
            return Err(PeerCardError::EmptyExchangeKey);
        }
        if self
            .iroh_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.endpoint_id.iter().all(|&byte| byte == 0))
        {
            return Err(PeerCardError::InvalidIrohEndpoint);
        }
        Ok(())
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(PEER_CARD_RECORD_VERSION);
        out.extend_from_slice(&self.peer_id.to_bytes());
        out.extend_from_slice(&self.signing_key.to_bytes());
        out.extend_from_slice(&self.exchange_key);
        write_endpoint(&mut out, self.iroh_endpoint.as_ref());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerCardError> {
        let mut cursor = CardDecoder::new(bytes);
        cursor.version()?;
        let peer_id = PeerId::from_bytes(cursor.array("peer id")?);
        let signing_key = VerifyingKey::from_bytes(&cursor.array("signing key")?)
            .map_err(|_| PeerCardError::InvalidSigningKey)?;
        let exchange_key = cursor.array("exchange key")?;
        let iroh_endpoint = read_endpoint(&mut cursor)?;
        cursor.finish()?;

        let card = Self {
            peer_id,
            signing_key,
            exchange_key,
            iroh_endpoint,
        };
        card.validate()?;
        Ok(card)
    }

    #[must_use]
    pub fn export_string(&self) -> String {
        let mut out = String::from(PEER_CARD_EXPORT_PREFIX);
        out.push_str(&URL_SAFE_NO_PAD.encode(self.to_bytes()));
        out
    }

    pub fn import_string(exported: &str) -> Result<Self, PeerCardError> {
        let encoded = exported
            .strip_prefix(PEER_CARD_EXPORT_PREFIX)
            .ok_or(PeerCardError::MissingPrefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| PeerCardError::InvalidEncoding)?;
        Self::from_bytes(&bytes)
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

    pub fn try_from_card(card: PeerCard) -> Result<Self, PeerCardError> {
        card.validate()?;
        Ok(Self { card })
    }

    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.card.peer_id
    }
}

fn write_endpoint(out: &mut Vec<u8>, endpoint: Option<&IrohEndpointAddr>) {
    let Some(endpoint) = endpoint else {
        out.push(0);
        return;
    };
    out.push(1);
    out.extend_from_slice(&endpoint.endpoint_id);
    write_string_list(out, endpoint.relay_urls.iter().map(Url::as_str));
    write_string_list(out, endpoint.direct_addrs.iter().map(ToString::to_string));
}

fn read_endpoint(cursor: &mut CardDecoder<'_>) -> Result<Option<IrohEndpointAddr>, PeerCardError> {
    match cursor.u8("iroh endpoint flag")? {
        0 => Ok(None),
        1 => {
            let endpoint_id = cursor.array("iroh endpoint id")?;
            let relay_urls = read_string_list(cursor, "relay url")?
                .into_iter()
                .map(|raw| Url::parse(&raw).map_err(|_| PeerCardError::InvalidRelayUrl))
                .collect::<Result<Vec<_>, _>>()?;
            let direct_addrs = read_string_list(cursor, "direct address")?
                .into_iter()
                .map(|raw| {
                    raw.parse::<SocketAddr>()
                        .map_err(|_| PeerCardError::InvalidDirectAddr)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(IrohEndpointAddr {
                endpoint_id,
                relay_urls,
                direct_addrs,
            }))
        }
        _ => Err(PeerCardError::InvalidIrohEndpoint),
    }
}

fn write_string_list<'a>(out: &mut Vec<u8>, values: impl Iterator<Item = impl AsRef<str> + 'a>) {
    let start = out.len();
    out.extend_from_slice(&0u32.to_be_bytes());
    let mut count = 0u32;
    for value in values {
        write_bytes(out, value.as_ref().as_bytes());
        count = count
            .checked_add(1)
            .expect("peer card string count overflowed u32");
    }
    out[start..start + 4].copy_from_slice(&count.to_be_bytes());
}

fn read_string_list(
    cursor: &mut CardDecoder<'_>,
    field: &'static str,
) -> Result<Vec<String>, PeerCardError> {
    let count = cursor.u32(field)?;
    let count = usize::try_from(count).map_err(|_| PeerCardError::CountTooLarge(field))?;
    (0..count)
        .map(|_| {
            let bytes = cursor.bytes(field)?;
            String::from_utf8(bytes.to_vec()).map_err(|_| PeerCardError::InvalidUtf8(field))
        })
        .collect()
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("peer card field length overflowed u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

struct CardDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CardDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn version(&mut self) -> Result<(), PeerCardError> {
        let version = self.u8("version")?;
        if version != PEER_CARD_RECORD_VERSION {
            return Err(PeerCardError::UnsupportedVersion);
        }
        Ok(())
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, PeerCardError> {
        Ok(self.take(field, 1)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, PeerCardError> {
        Ok(u32::from_be_bytes(self.array(field)?))
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], PeerCardError> {
        self.take(field, N)?
            .try_into()
            .map_err(|_| PeerCardError::Truncated(field))
    }

    fn bytes(&mut self, field: &'static str) -> Result<&'a [u8], PeerCardError> {
        let len =
            usize::try_from(self.u32(field)?).map_err(|_| PeerCardError::FieldTooLarge(field))?;
        self.take(field, len)
    }

    fn take(&mut self, field: &'static str, len: usize) -> Result<&'a [u8], PeerCardError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PeerCardError::FieldTooLarge(field))?;
        let Some(bytes) = self.bytes.get(self.offset..end) else {
            return Err(PeerCardError::Truncated(field));
        };
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), PeerCardError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PeerCardError::TrailingBytes)
        }
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
        assert_eq!(card.validate(), Err(PeerCardError::InconsistentPeerId));
    }

    #[test]
    fn peer_card_export_round_trips_text_and_bytes() {
        let endpoint = IrohEndpointAddr {
            endpoint_id: [8u8; 32],
            relay_urls: vec![Url::parse("https://relay.example.test").unwrap()],
            direct_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4096)],
        };
        let card = identity(5, 6).card_with_iroh_endpoint(endpoint);

        let exported = card.export_string();

        assert!(exported.starts_with(PEER_CARD_EXPORT_PREFIX));
        assert_eq!(PeerCard::import_string(&exported).unwrap(), card);
        assert_eq!(PeerCard::from_bytes(&card.to_bytes()).unwrap(), card);
    }

    #[test]
    fn peer_card_import_rejects_bad_exports() {
        assert_eq!(
            PeerCard::import_string("bad").unwrap_err(),
            PeerCardError::MissingPrefix
        );
        assert_eq!(
            PeerCard::import_string("enlace-peer-card-v1:***").unwrap_err(),
            PeerCardError::InvalidEncoding
        );

        let mut card = identity(1, 2).card().to_bytes();
        card[0] = PEER_CARD_RECORD_VERSION.wrapping_add(1);
        assert_eq!(
            PeerCard::from_bytes(&card).unwrap_err(),
            PeerCardError::UnsupportedVersion
        );
    }

    #[test]
    fn peer_card_import_rejects_invalid_card_material() {
        let mut inconsistent = identity(1, 2).card().to_bytes();
        inconsistent[1] ^= 0xff;
        assert_eq!(
            PeerCard::from_bytes(&inconsistent).unwrap_err(),
            PeerCardError::InconsistentPeerId
        );

        let mut empty_exchange = identity(1, 2).card();
        empty_exchange.exchange_key = [0; 32];
        assert_eq!(
            empty_exchange.validate().unwrap_err(),
            PeerCardError::EmptyExchangeKey
        );
    }

    #[test]
    fn trusted_peer_try_from_card_validates() {
        let mut card = identity(7, 8).card();
        card.peer_id = identity(9, 8).peer_id();

        assert_eq!(
            TrustedPeer::try_from_card(card).unwrap_err(),
            PeerCardError::InconsistentPeerId
        );
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
