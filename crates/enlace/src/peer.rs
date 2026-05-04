//! Public-key peer identity types.

use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, Payload, rand_core::RngCore},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, mpsc};
use url::Url;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[cfg(feature = "dht")]
use crate::config::DhtConfig;
#[cfg(feature = "http")]
use crate::config::HttpConfig;
#[cfg(feature = "iroh")]
use crate::config::IrohConfig;
#[cfg(feature = "pkarr")]
use crate::config::PkarrConfig;
use crate::config::{ConfiguredTransport, DEFAULT_LONG_POLL_SECS, IrohEndpointAddr};
use crate::crypto::{self, AEAD_KEY_LEN, NONCE_LEN, SIG_LEN};
use crate::dedup::Dedup;
use crate::error::{OpenError, RecvError, TransportError};
use crate::kdf::{ChannelKind, NameError, TransportKind, validate_name};
use crate::state::{State, StateError};
#[cfg(feature = "dht")]
use crate::transports::DhtTransport;
#[cfg(feature = "http")]
use crate::transports::HttpTransport;
#[cfg(feature = "iroh")]
use crate::transports::IrohTransport;
#[cfg(feature = "pkarr")]
use crate::transports::PkarrTransport;
use crate::transports::Transport;

pub const PEER_ID_LEN: usize = 32;
pub const GROUP_ID_LEN: usize = 32;
pub const GROUP_KEY_ID_LEN: usize = 32;
pub const GROUP_KEY_SECRET_LEN: usize = 32;
const PEER_CARD_EXPORT_PREFIX: &str = "enlace-peer-card-v1:";
const PEER_CARD_RECORD_VERSION: u8 = 1;
const PEER_ENVELOPE_RECORD_VERSION: u8 = 1;
const GROUP_ENVELOPE_RECORD_VERSION: u8 = 1;
const PEER_SLOT_INNER_VERSION: u8 = 1;
const PEER_SLOT_WATCH_BUFFER: usize = 64;

type PeerSendTask = crate::runtime::BoxedFuture<(TransportKind, Result<(), TransportError>)>;
type PeerRecvTask = crate::runtime::BoxedFuture<(
    TransportKind,
    PeerAddress,
    Result<Option<Vec<u8>>, TransportError>,
)>;
type PeerSlotGetTask = crate::runtime::BoxedFuture<(
    TransportKind,
    Result<Option<(u64, Vec<u8>)>, TransportError>,
)>;

/// Failure modes for public-key peer envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEnvelopeError {
    /// Channel name failed normal validation.
    Name(NameError),
    /// The recipient list was empty.
    NoRecipients,
    /// A recipient card failed validation.
    InvalidRecipient(PeerCardError),
    /// Binary envelope failed to decode.
    MsgpackFailed,
    /// Envelope version is unsupported.
    UnsupportedVersion,
    /// Envelope was not addressed to the local peer.
    NotAddressed,
    /// Encrypted recipient payload failed authentication.
    AeadFailed,
    /// Envelope signature was malformed or failed verification.
    SignatureInvalid,
    /// Sender is absent from the trusted peer set.
    UntrustedSender,
    /// Envelope channel did not match the expected channel.
    WrongChannel,
}

impl fmt::Display for PeerEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(err) => write!(f, "channel name invalid: {err}"),
            Self::NoRecipients => f.write_str("peer envelope has no recipients"),
            Self::InvalidRecipient(err) => write!(f, "peer envelope recipient invalid: {err}"),
            Self::MsgpackFailed => f.write_str("peer envelope is malformed"),
            Self::UnsupportedVersion => f.write_str("peer envelope version unsupported"),
            Self::NotAddressed => f.write_str("peer envelope is not addressed to this peer"),
            Self::AeadFailed => f.write_str("peer envelope authentication failed"),
            Self::SignatureInvalid => f.write_str("peer envelope signature invalid"),
            Self::UntrustedSender => f.write_str("peer envelope sender is not trusted"),
            Self::WrongChannel => f.write_str("peer envelope channel mismatch"),
        }
    }
}

impl StdError for PeerEnvelopeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Name(err) => Some(err),
            Self::InvalidRecipient(err) => Some(err),
            Self::NoRecipients
            | Self::MsgpackFailed
            | Self::UnsupportedVersion
            | Self::NotAddressed
            | Self::AeadFailed
            | Self::SignatureInvalid
            | Self::UntrustedSender
            | Self::WrongChannel => None,
        }
    }
}

impl From<NameError> for PeerEnvelopeError {
    fn from(err: NameError) -> Self {
        Self::Name(err)
    }
}

/// Failure modes for public-key group envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEnvelopeError {
    /// Channel name failed normal validation.
    Name(NameError),
    /// No group keys were available for encryption or decryption.
    NoGroupKeys,
    /// Binary envelope failed to decode.
    MsgpackFailed,
    /// Envelope version is unsupported.
    UnsupportedVersion,
    /// None of the envelope entries matched a live group key.
    MissingGroupKey,
    /// Encrypted group payload failed authentication.
    AeadFailed,
    /// Envelope signature was malformed or failed verification.
    SignatureInvalid,
    /// Sender is absent from the trusted peer set.
    UntrustedSender,
    /// Envelope channel did not match the expected channel.
    WrongChannel,
}

impl fmt::Display for GroupEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(err) => write!(f, "channel name invalid: {err}"),
            Self::NoGroupKeys => f.write_str("group envelope has no keys"),
            Self::MsgpackFailed => f.write_str("group envelope is malformed"),
            Self::UnsupportedVersion => f.write_str("group envelope version unsupported"),
            Self::MissingGroupKey => f.write_str("group envelope key is missing"),
            Self::AeadFailed => f.write_str("group envelope authentication failed"),
            Self::SignatureInvalid => f.write_str("group envelope signature invalid"),
            Self::UntrustedSender => f.write_str("group envelope sender is not trusted"),
            Self::WrongChannel => f.write_str("group envelope channel mismatch"),
        }
    }
}

impl StdError for GroupEnvelopeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Name(err) => Some(err),
            Self::NoGroupKeys
            | Self::MsgpackFailed
            | Self::UnsupportedVersion
            | Self::MissingGroupKey
            | Self::AeadFailed
            | Self::SignatureInvalid
            | Self::UntrustedSender
            | Self::WrongChannel => None,
        }
    }
}

impl From<NameError> for GroupEnvelopeError {
    fn from(err: NameError) -> Self {
        Self::Name(err)
    }
}

/// Failure modes for public-key mailbox sends.
#[derive(Debug)]
pub enum PeerSendError {
    /// Pairwise envelope creation failed.
    PeerEnvelope(PeerEnvelopeError),
    /// Group envelope creation failed.
    GroupEnvelope(GroupEnvelopeError),
    /// Every configured transport rejected the send.
    AllTransportsFailed(Vec<(TransportKind, TransportError)>),
}

impl fmt::Display for PeerSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerEnvelope(err) => write!(f, "peer envelope failed: {err}"),
            Self::GroupEnvelope(err) => write!(f, "group envelope failed: {err}"),
            Self::AllTransportsFailed(failures) => {
                write!(f, "all {} transport(s) failed", failures.len())?;
                let mut sep = ": ";
                for (kind, err) in failures {
                    write!(f, "{sep}{kind}: {err}")?;
                    sep = ", ";
                }
                Ok(())
            }
        }
    }
}

impl StdError for PeerSendError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::PeerEnvelope(err) => Some(err),
            Self::GroupEnvelope(err) => Some(err),
            Self::AllTransportsFailed(_) => None,
        }
    }
}

impl From<PeerEnvelopeError> for PeerSendError {
    fn from(err: PeerEnvelopeError) -> Self {
        Self::PeerEnvelope(err)
    }
}

impl From<GroupEnvelopeError> for PeerSendError {
    fn from(err: GroupEnvelopeError) -> Self {
        Self::GroupEnvelope(err)
    }
}

/// Failure modes for public-key slot operations.
#[derive(Debug)]
pub enum PeerSlotError {
    /// Pairwise envelope creation failed.
    PeerEnvelope(PeerEnvelopeError),
    /// Group envelope creation failed.
    GroupEnvelope(GroupEnvelopeError),
    /// Slot payload failed to encode or decode.
    MsgpackFailed,
    /// State storage failed.
    State(StateError),
    /// Every configured transport rejected the operation.
    AllTransportsFailed(Vec<(TransportKind, TransportError)>),
}

impl fmt::Display for PeerSlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerEnvelope(err) => write!(f, "peer envelope failed: {err}"),
            Self::GroupEnvelope(err) => write!(f, "group envelope failed: {err}"),
            Self::MsgpackFailed => f.write_str("peer slot payload is malformed"),
            Self::State(err) => write!(f, "state store error: {err}"),
            Self::AllTransportsFailed(failures) => {
                write!(f, "all {} transport(s) failed", failures.len())?;
                let mut sep = ": ";
                for (kind, err) in failures {
                    write!(f, "{sep}{kind}: {err}")?;
                    sep = ", ";
                }
                Ok(())
            }
        }
    }
}

impl StdError for PeerSlotError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::PeerEnvelope(err) => Some(err),
            Self::GroupEnvelope(err) => Some(err),
            Self::State(err) => Some(err),
            Self::MsgpackFailed | Self::AllTransportsFailed(_) => None,
        }
    }
}

impl From<PeerEnvelopeError> for PeerSlotError {
    fn from(err: PeerEnvelopeError) -> Self {
        Self::PeerEnvelope(err)
    }
}

impl From<GroupEnvelopeError> for PeerSlotError {
    fn from(err: GroupEnvelopeError) -> Self {
        Self::GroupEnvelope(err)
    }
}

impl From<StateError> for PeerSlotError {
    fn from(err: StateError) -> Self {
        Self::State(err)
    }
}

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

/// Failure modes for live group-key mutations.
#[derive(Debug)]
pub enum GroupKeyError {
    /// Group-key storage failed.
    State(StateError),
}

impl fmt::Display for GroupKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(err) => write!(f, "state store error: {err}"),
        }
    }
}

impl StdError for GroupKeyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::State(err) => Some(err),
        }
    }
}

impl From<StateError> for GroupKeyError {
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

    pub fn seal_to_peers(
        &self,
        kind: ChannelKind,
        name: &str,
        payload: &[u8],
        recipients: &[PeerCard],
    ) -> Result<PeerEnvelope, PeerEnvelopeError> {
        PeerEnvelope::seal(self, kind, name, payload, recipients)
    }

    pub fn seal_to_groups(
        &self,
        kind: ChannelKind,
        name: &str,
        payload: &[u8],
        group_keys: &[(GroupId, GroupKey)],
    ) -> Result<GroupEnvelope, GroupEnvelopeError> {
        GroupEnvelope::seal(self, kind, name, payload, group_keys)
    }

    pub fn open_peer_envelope(
        &self,
        envelope: &PeerEnvelope,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Result<PeerEnvelopeMessage, PeerEnvelopeError> {
        envelope.open(self, kind, name, trusted)
    }

    #[must_use]
    pub fn open_peer_envelope_or_drop(
        &self,
        bytes: &[u8],
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Option<PeerEnvelopeMessage> {
        PeerEnvelope::open_bytes_or_drop(bytes, self, kind, name, trusted)
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

/// Runtime public-key namespace configuration.
#[derive(Default)]
pub struct PeerConfig {
    pub state: State,
    pub trusted_peers: Vec<TrustedPeer>,
    pub group_keys: Vec<(GroupId, GroupKey)>,
    #[cfg(feature = "http")]
    pub http: Option<HttpConfig>,
    #[cfg(feature = "pkarr")]
    pub pkarr: Option<PkarrConfig>,
    #[cfg(feature = "dht")]
    pub dht: Option<DhtConfig>,
    #[cfg(feature = "iroh")]
    pub iroh: Option<IrohConfig>,
    pub transports: Vec<ConfiguredTransport>,
}

/// Live public-key namespace state.
pub struct PeerNamespace {
    identity: Arc<PeerIdentity>,
    state: State,
    trusted_peers: Arc<RwLock<HashMap<PeerId, TrustedPeer>>>,
    group_keys: Arc<RwLock<HashMap<(GroupId, GroupKeyId), GroupKey>>>,
    transports: Vec<PeerTransportEndpoint>,
    #[cfg(feature = "iroh")]
    iroh: Option<Arc<IrohTransport>>,
}

#[derive(Clone)]
struct PeerTransportEndpoint {
    kind: TransportKind,
    transport: Arc<dyn Transport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerAddress {
    Pairwise(PeerId),
    Publisher(PeerId),
    Group(GroupId),
}

impl PeerNamespace {
    #[allow(clippy::unused_async)]
    pub async fn open(identity: PeerIdentity, config: PeerConfig) -> Result<Self, OpenError> {
        let state = config.state.clone();
        #[cfg(feature = "iroh")]
        let state_store = state.store();
        let mut transports = Vec::new();

        #[cfg(feature = "http")]
        if let Some(http_config) = config.http.clone() {
            let http = Arc::new(
                HttpTransport::new(http_config)
                    .map_err(|err| OpenError::TransportInit(TransportKind::Http, Box::new(err)))?,
            );
            let transport: Arc<dyn Transport> = http;
            transports.push(PeerTransportEndpoint {
                kind: TransportKind::Http,
                transport,
            });
        }

        #[cfg(any(feature = "dht", feature = "pkarr"))]
        let transport_seed = identity.peer_id().to_bytes();
        #[cfg(feature = "pkarr")]
        if let Some(pkarr_config) = &config.pkarr {
            let pkarr = Arc::new(
                PkarrTransport::new(&transport_seed, pkarr_config)
                    .map_err(|err| OpenError::TransportInit(TransportKind::Pkarr, Box::new(err)))?,
            );
            let transport: Arc<dyn Transport> = pkarr;
            transports.push(PeerTransportEndpoint {
                kind: TransportKind::Pkarr,
                transport,
            });
        }

        #[cfg(feature = "dht")]
        if let Some(dht_config) = &config.dht {
            let dht = Arc::new(
                DhtTransport::new(&transport_seed, dht_config)
                    .map_err(|err| OpenError::TransportInit(TransportKind::Dht, Box::new(err)))?,
            );
            let transport: Arc<dyn Transport> = dht;
            transports.push(PeerTransportEndpoint {
                kind: TransportKind::Dht,
                transport,
            });
        }

        #[cfg(feature = "iroh")]
        let iroh = open_peer_iroh_transport(&config, state_store.as_ref()).await?;
        #[cfg(feature = "iroh")]
        if let Some(iroh) = iroh.clone() {
            let transport: Arc<dyn Transport> = iroh;
            transports.push(PeerTransportEndpoint {
                kind: TransportKind::Iroh,
                transport,
            });
        }

        for configured in &config.transports {
            transports.push(PeerTransportEndpoint {
                kind: configured.kind,
                transport: Arc::clone(&configured.transport),
            });
        }

        let namespace = Self {
            identity: Arc::new(identity),
            state,
            trusted_peers: Arc::new(RwLock::new(HashMap::new())),
            group_keys: Arc::new(RwLock::new(HashMap::new())),
            transports,
            #[cfg(feature = "iroh")]
            iroh,
        };
        for trusted in config.trusted_peers {
            trusted
                .card
                .validate()
                .map_err(|err| OpenError::State(StateError::Corrupted(err.to_string())))?;
            write_trusted_peers(&namespace.trusted_peers).insert(trusted.peer_id(), trusted);
        }
        for (group, key) in config.group_keys {
            namespace
                .add_group_key(group, key)
                .map_err(|err| match err {
                    GroupKeyError::State(err) => OpenError::State(err),
                })?;
        }
        Ok(namespace)
    }

    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    #[must_use]
    pub fn card(&self) -> PeerCard {
        self.identity.card()
    }

    #[cfg(feature = "iroh")]
    #[must_use]
    pub fn iroh_endpoint_addr(&self) -> Option<IrohEndpointAddr> {
        self.iroh.as_ref().map(|iroh| iroh.endpoint_addr())
    }

    #[cfg(not(feature = "iroh"))]
    #[must_use]
    pub fn iroh_endpoint_addr(&self) -> Option<IrohEndpointAddr> {
        None
    }

    pub fn add_group_key(&self, group: GroupId, key: GroupKey) -> Result<(), GroupKeyError> {
        self.state.store_group_key(group, &key)?;
        let mut keys = write_group_keys(&self.group_keys);
        keys.insert((group, key.id), key);
        Ok(())
    }

    pub fn remove_group_key(
        &self,
        group: GroupId,
        key_id: GroupKeyId,
    ) -> Result<(), GroupKeyError> {
        self.state.remove_group_key(group, key_id)?;
        let mut keys = write_group_keys(&self.group_keys);
        keys.remove(&(group, key_id));
        Ok(())
    }

    #[must_use]
    pub fn list_group_keys(&self, group: GroupId) -> Vec<GroupKeyId> {
        let keys = read_group_keys(&self.group_keys);
        let mut ids: Vec<_> = keys
            .keys()
            .filter_map(|&(candidate, key_id)| (candidate == group).then_some(key_id))
            .collect();
        ids.sort_unstable();
        ids
    }

    pub fn trust_peer(&self, peer: TrustedPeer) -> Result<(), TrustError> {
        peer.card.validate()?;
        let peer_id = peer.peer_id();
        let endpoint = peer.card.iroh_endpoint.clone();
        self.state.store_trusted_peer(&peer)?;
        let mut trusted = write_trusted_peers(&self.trusted_peers);
        let replaced = trusted.insert(peer_id, peer);
        drop(trusted);
        let old_endpoint_id = replaced
            .and_then(|peer| peer.card.iroh_endpoint)
            .map(|endpoint| endpoint.endpoint_id);
        #[cfg(feature = "iroh")]
        update_iroh_trusted_endpoint(self.iroh.as_ref(), old_endpoint_id, endpoint);
        #[cfg(not(feature = "iroh"))]
        {
            let _ = old_endpoint_id;
            let _ = endpoint;
        }
        Ok(())
    }

    pub fn remove_trusted_peer(&self, peer: PeerId) -> Result<(), TrustError> {
        self.state.remove_trusted_peer(peer)?;
        let mut trusted = write_trusted_peers(&self.trusted_peers);
        let removed = trusted.remove(&peer);
        drop(trusted);
        let old_endpoint_id = removed
            .and_then(|peer| peer.card.iroh_endpoint)
            .map(|endpoint| endpoint.endpoint_id);
        #[cfg(feature = "iroh")]
        update_iroh_trusted_endpoint(self.iroh.as_ref(), old_endpoint_id, None);
        #[cfg(not(feature = "iroh"))]
        let _ = old_endpoint_id;
        Ok(())
    }

    #[must_use]
    pub fn trusted_peers(&self) -> Vec<PeerCard> {
        let trusted = read_trusted_peers(&self.trusted_peers);
        let mut peers: Vec<_> = trusted.values().map(|peer| peer.card.clone()).collect();
        peers.sort_unstable_by_key(|peer| peer.peer_id);
        peers
    }

    pub fn mailbox(&self, name: &str) -> Result<PeerMailbox<'_>, NameError> {
        validate_name(name)?;
        Ok(PeerMailbox {
            namespace: self,
            name: name.to_owned(),
            dedup: std::sync::Mutex::new(Dedup::new(crate::dedup::DEFAULT_CAPACITY)),
        })
    }

    pub fn slot(&self, name: &str) -> Result<PeerSlot<'_>, NameError> {
        validate_name(name)?;
        Ok(PeerSlot {
            namespace: self,
            name: name.to_owned(),
        })
    }

    pub fn seal_group_envelope(
        &self,
        kind: ChannelKind,
        name: &str,
        payload: &[u8],
        group_keys: &[(GroupId, GroupKeyId)],
    ) -> Result<GroupEnvelope, GroupEnvelopeError> {
        let keys = self.resolve_group_keys(group_keys)?;
        self.identity.seal_to_groups(kind, name, payload, &keys)
    }

    pub fn open_group_envelope(
        &self,
        envelope: &GroupEnvelope,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Result<GroupEnvelopeMessage, GroupEnvelopeError> {
        let keys = self.group_keys_for_envelope(envelope);
        envelope.open(kind, name, trusted, &keys)
    }

    #[must_use]
    pub fn open_group_envelope_or_drop(
        &self,
        bytes: &[u8],
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Option<GroupEnvelopeMessage> {
        let envelope = GroupEnvelope::from_bytes(bytes).ok()?;
        self.open_group_envelope(&envelope, kind, name, trusted)
            .ok()
    }

    fn resolve_group_keys(
        &self,
        requested: &[(GroupId, GroupKeyId)],
    ) -> Result<Vec<(GroupId, GroupKey)>, GroupEnvelopeError> {
        if requested.is_empty() {
            return Err(GroupEnvelopeError::NoGroupKeys);
        }
        let keys = read_group_keys(&self.group_keys);
        requested
            .iter()
            .map(|&(group, key_id)| {
                keys.get(&(group, key_id))
                    .cloned()
                    .map(|key| (group, key))
                    .ok_or(GroupEnvelopeError::MissingGroupKey)
            })
            .collect()
    }

    fn group_keys_for_envelope(&self, envelope: &GroupEnvelope) -> Vec<(GroupId, GroupKey)> {
        let keys = read_group_keys(&self.group_keys);
        envelope
            .entries
            .iter()
            .filter_map(|entry| {
                keys.get(&(entry.group, entry.key_id))
                    .cloned()
                    .map(|key| (entry.group, key))
            })
            .collect()
    }

    fn trusted_snapshot(&self) -> Vec<TrustedPeer> {
        read_trusted_peers(&self.trusted_peers)
            .values()
            .cloned()
            .collect()
    }

    fn group_ids(&self) -> Vec<GroupId> {
        let keys = read_group_keys(&self.group_keys);
        let mut ids: Vec<_> = keys.keys().map(|&(group, _)| group).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn clone_for_task(&self) -> PeerSlotTaskNamespace {
        PeerSlotTaskNamespace {
            identity: Arc::clone(&self.identity),
            state: self.state.clone(),
            trusted_peers: Arc::clone(&self.trusted_peers),
            group_keys: Arc::clone(&self.group_keys),
        }
    }

    fn open_slot_value(
        &self,
        name: &str,
        via: TransportKind,
        address: PeerAddress,
        scope: PeerSlotScope,
        bytes: &[u8],
    ) -> Option<PeerSlotValue> {
        self.clone_for_task()
            .open_slot_value(name, via, address, scope, bytes)
    }
}

#[derive(Clone)]
struct PeerSlotTaskNamespace {
    identity: Arc<PeerIdentity>,
    state: State,
    trusted_peers: Arc<RwLock<HashMap<PeerId, TrustedPeer>>>,
    group_keys: Arc<RwLock<HashMap<(GroupId, GroupKeyId), GroupKey>>>,
}

impl PeerSlotTaskNamespace {
    fn trusted_snapshot(&self) -> Vec<TrustedPeer> {
        read_trusted_peers(&self.trusted_peers)
            .values()
            .cloned()
            .collect()
    }

    fn group_keys_for_envelope(&self, envelope: &GroupEnvelope) -> Vec<(GroupId, GroupKey)> {
        let keys = read_group_keys(&self.group_keys);
        envelope
            .entries
            .iter()
            .filter_map(|entry| {
                keys.get(&(entry.group, entry.key_id))
                    .cloned()
                    .map(|key| (entry.group, key))
            })
            .collect()
    }

    fn open_slot_value(
        &self,
        name: &str,
        via: TransportKind,
        address: PeerAddress,
        scope: PeerSlotScope,
        bytes: &[u8],
    ) -> Option<PeerSlotValue> {
        let trusted = self.trusted_snapshot();
        match address {
            PeerAddress::Pairwise(_) | PeerAddress::Publisher(_) => {
                let message = PeerEnvelope::open_bytes_or_drop(
                    bytes,
                    &self.identity,
                    ChannelKind::Slot,
                    name,
                    &trusted,
                )?;
                let inner = decode_peer_slot_payload(&message.payload).ok()?;
                Some(PeerSlotValue {
                    version: inner.version,
                    sender: message.sender,
                    signed_by: message.signed_by,
                    payload: inner.payload,
                    via,
                    scope,
                    key_id: None,
                })
            }
            PeerAddress::Group(_) => {
                let envelope = GroupEnvelope::from_bytes(bytes).ok()?;
                let keys = self.group_keys_for_envelope(&envelope);
                let message = envelope
                    .open(ChannelKind::Slot, name, &trusted, &keys)
                    .ok()?;
                let inner = decode_peer_slot_payload(&message.payload).ok()?;
                Some(PeerSlotValue {
                    version: inner.version,
                    sender: message.sender,
                    signed_by: message.signed_by,
                    payload: inner.payload,
                    via,
                    scope,
                    key_id: Some(message.key_id),
                })
            }
        }
    }
}

/// Public-key mailbox bound to one channel name.
pub struct PeerMailbox<'a> {
    namespace: &'a PeerNamespace,
    name: String,
    dedup: std::sync::Mutex<Dedup>,
}

impl PeerMailbox<'_> {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn send_to_peers(
        &self,
        recipients: &[PeerCard],
        payload: &[u8],
    ) -> Result<PeerSendReport, PeerSendError> {
        let envelope = PeerEnvelope::seal(
            &self.namespace.identity,
            ChannelKind::Mailbox,
            &self.name,
            payload,
            recipients,
        )?;
        let bytes = envelope.to_bytes()?;
        let addresses = recipients
            .iter()
            .map(|card| PeerAddress::Pairwise(card.peer_id))
            .collect::<Vec<_>>();
        self.send_bytes(&addresses, bytes).await
    }

    pub async fn send_to_group(
        &self,
        group: GroupId,
        key_ids: &[GroupKeyId],
        payload: &[u8],
    ) -> Result<PeerSendReport, PeerSendError> {
        let requested = key_ids
            .iter()
            .copied()
            .map(|key_id| (group, key_id))
            .collect::<Vec<_>>();
        let envelope = self.namespace.seal_group_envelope(
            ChannelKind::Mailbox,
            &self.name,
            payload,
            &requested,
        )?;
        let bytes = envelope.to_bytes()?;
        self.send_bytes(&[PeerAddress::Group(group)], bytes).await
    }

    pub async fn recv(&self) -> Result<PeerMailboxMessage, RecvError> {
        self.recv_timeout(Duration::from_secs(DEFAULT_LONG_POLL_SECS.into()))
            .await
    }

    pub async fn recv_timeout(&self, wait: Duration) -> Result<PeerMailboxMessage, RecvError> {
        loop {
            let mut tasks: FuturesUnordered<PeerRecvTask> = FuturesUnordered::new();
            let addresses = self.recv_addresses();
            for endpoint in &self.namespace.transports {
                for address in &addresses {
                    let transport = Arc::clone(&endpoint.transport);
                    let id = peer_transport_id(
                        endpoint.kind,
                        *address,
                        ChannelKind::Mailbox,
                        &self.name,
                    );
                    let kind = endpoint.kind;
                    let address = *address;
                    tasks.push(Box::pin(async move {
                        (kind, address, transport.recv(&id, wait).await)
                    }));
                }
            }

            let mut received_transport_response = false;
            while let Some((kind, address, recv_result)) = tasks.next().await {
                match recv_result {
                    Ok(Some(bytes)) => {
                        received_transport_response = true;
                        if self
                            .dedup
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .observe(&bytes)
                        {
                            continue;
                        }
                        if let Some(message) = self.open_message(kind, address, &bytes) {
                            return Ok(message);
                        }
                    }
                    Ok(None) => {
                        received_transport_response = true;
                    }
                    Err(_) => {}
                }
            }

            if wait.is_zero() {
                return Err(RecvError::Closed);
            }
            if !received_transport_response {
                crate::runtime::sleep(wait).await;
            }
        }
    }

    async fn send_bytes(
        &self,
        addresses: &[PeerAddress],
        bytes: Vec<u8>,
    ) -> Result<PeerSendReport, PeerSendError> {
        let mut tasks: FuturesUnordered<PeerSendTask> = FuturesUnordered::new();
        for endpoint in &self.namespace.transports {
            for address in addresses {
                let transport = Arc::clone(&endpoint.transport);
                let id =
                    peer_transport_id(endpoint.kind, *address, ChannelKind::Mailbox, &self.name);
                let bytes = bytes.clone();
                let kind = endpoint.kind;
                tasks.push(Box::pin(async move {
                    (kind, transport.send(&id, &bytes).await)
                }));
            }
        }

        let mut delivered = Vec::new();
        let mut failed = Vec::new();
        while let Some((kind, send_result)) = tasks.next().await {
            match send_result {
                Ok(()) => delivered.push(kind),
                Err(err) => failed.push((kind, err)),
            }
        }

        if delivered.is_empty() {
            return Err(PeerSendError::AllTransportsFailed(failed));
        }
        Ok(PeerSendReport { delivered, failed })
    }

    fn recv_addresses(&self) -> Vec<PeerAddress> {
        let mut addresses = Vec::with_capacity(1 + self.namespace.group_ids().len());
        addresses.push(PeerAddress::Pairwise(self.namespace.peer_id()));
        addresses.extend(
            self.namespace
                .group_ids()
                .into_iter()
                .map(PeerAddress::Group),
        );
        addresses
    }

    fn open_message(
        &self,
        via: TransportKind,
        address: PeerAddress,
        bytes: &[u8],
    ) -> Option<PeerMailboxMessage> {
        let trusted = self.namespace.trusted_snapshot();
        match address {
            PeerAddress::Pairwise(_) | PeerAddress::Publisher(_) => {
                PeerEnvelope::open_bytes_or_drop(
                    bytes,
                    &self.namespace.identity,
                    ChannelKind::Mailbox,
                    &self.name,
                    &trusted,
                )
                .map(|message| PeerMailboxMessage {
                    sender: message.sender,
                    signed_by: message.signed_by,
                    payload: message.payload,
                    via,
                    group: None,
                    key_id: None,
                })
            }
            PeerAddress::Group(_) => self
                .namespace
                .open_group_envelope_or_drop(bytes, ChannelKind::Mailbox, &self.name, &trusted)
                .map(|message| PeerMailboxMessage {
                    sender: message.sender,
                    signed_by: message.signed_by,
                    payload: message.payload,
                    via,
                    group: Some(message.group),
                    key_id: Some(message.key_id),
                }),
        }
    }
}

/// Public-key slot bound to one channel name.
pub struct PeerSlot<'a> {
    namespace: &'a PeerNamespace,
    name: String,
}

impl PeerSlot<'_> {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn put_for_peers(
        &self,
        recipients: &[PeerCard],
        payload: &[u8],
    ) -> Result<PeerSlotPutReport, PeerSlotError> {
        let version = self.next_version(PeerSlotScopeKey::Pairwise)?;
        let payload = encode_peer_slot_payload(version, payload)?;
        let envelope = PeerEnvelope::seal(
            &self.namespace.identity,
            ChannelKind::Slot,
            &self.name,
            &payload,
            recipients,
        )?;
        let bytes = envelope.to_bytes()?;
        let addresses = recipients
            .iter()
            .map(|card| PeerAddress::Pairwise(card.peer_id))
            .collect::<Vec<_>>();
        self.put_bytes(&addresses, version, bytes).await
    }

    pub async fn put_publisher_for_peers(
        &self,
        recipients: &[PeerCard],
        payload: &[u8],
    ) -> Result<PeerSlotPutReport, PeerSlotError> {
        let publisher = self.namespace.peer_id();
        let version = self.next_version(PeerSlotScopeKey::Publisher(publisher))?;
        let payload = encode_peer_slot_payload(version, payload)?;
        let envelope = PeerEnvelope::seal(
            &self.namespace.identity,
            ChannelKind::Slot,
            &self.name,
            &payload,
            recipients,
        )?;
        let bytes = envelope.to_bytes()?;
        self.put_bytes(&[PeerAddress::Publisher(publisher)], version, bytes)
            .await
    }

    pub async fn put_group(
        &self,
        group: GroupId,
        key_ids: &[GroupKeyId],
        payload: &[u8],
    ) -> Result<PeerSlotPutReport, PeerSlotError> {
        let version = self.next_version(PeerSlotScopeKey::Group(group))?;
        let payload = encode_peer_slot_payload(version, payload)?;
        let requested = key_ids
            .iter()
            .copied()
            .map(|key_id| (group, key_id))
            .collect::<Vec<_>>();
        let envelope = self.namespace.seal_group_envelope(
            ChannelKind::Slot,
            &self.name,
            &payload,
            &requested,
        )?;
        let bytes = envelope.to_bytes()?;
        self.put_bytes(&[PeerAddress::Group(group)], version, bytes)
            .await
    }

    pub async fn get_pairwise(&self) -> Result<Option<PeerSlotValue>, PeerSlotError> {
        self.get_address(
            PeerAddress::Pairwise(self.namespace.peer_id()),
            PeerSlotScope::Pairwise,
        )
        .await
    }

    pub async fn get_publisher(
        &self,
        publisher: PeerId,
    ) -> Result<Option<PeerSlotValue>, PeerSlotError> {
        self.get_address(
            PeerAddress::Publisher(publisher),
            PeerSlotScope::Publisher { publisher },
        )
        .await
    }

    pub async fn get_group(&self, group: GroupId) -> Result<Option<PeerSlotValue>, PeerSlotError> {
        self.get_address(PeerAddress::Group(group), PeerSlotScope::Group { group })
            .await
    }

    pub fn watch_pairwise(&self) -> Result<PeerSlotWatch, PeerSlotError> {
        self.watch_address(
            PeerAddress::Pairwise(self.namespace.peer_id()),
            PeerSlotScope::Pairwise,
            PeerSlotScopeKey::Pairwise,
        )
    }

    pub fn watch_publisher(&self, publisher: PeerId) -> Result<PeerSlotWatch, PeerSlotError> {
        self.watch_address(
            PeerAddress::Publisher(publisher),
            PeerSlotScope::Publisher { publisher },
            PeerSlotScopeKey::Publisher(publisher),
        )
    }

    pub fn watch_group(&self, group: GroupId) -> Result<PeerSlotWatch, PeerSlotError> {
        self.watch_address(
            PeerAddress::Group(group),
            PeerSlotScope::Group { group },
            PeerSlotScopeKey::Group(group),
        )
    }

    async fn put_bytes(
        &self,
        addresses: &[PeerAddress],
        version: u64,
        bytes: Vec<u8>,
    ) -> Result<PeerSlotPutReport, PeerSlotError> {
        let mut tasks: FuturesUnordered<PeerSendTask> = FuturesUnordered::new();
        for endpoint in &self.namespace.transports {
            for address in addresses {
                let transport = Arc::clone(&endpoint.transport);
                let id = peer_transport_id(endpoint.kind, *address, ChannelKind::Slot, &self.name);
                let bytes = bytes.clone();
                let kind = endpoint.kind;
                tasks.push(Box::pin(async move {
                    (kind, transport.put(&id, version, &bytes).await)
                }));
            }
        }

        let mut stored = Vec::new();
        let mut failed = Vec::new();
        while let Some((kind, put_result)) = tasks.next().await {
            match put_result {
                Ok(()) => stored.push(kind),
                Err(err) => failed.push((kind, err)),
            }
        }

        if stored.is_empty() {
            return Err(PeerSlotError::AllTransportsFailed(failed));
        }
        Ok(PeerSlotPutReport {
            version,
            stored,
            failed,
        })
    }

    async fn get_address(
        &self,
        address: PeerAddress,
        scope: PeerSlotScope,
    ) -> Result<Option<PeerSlotValue>, PeerSlotError> {
        let mut tasks: FuturesUnordered<PeerSlotGetTask> = FuturesUnordered::new();
        for endpoint in &self.namespace.transports {
            let transport = Arc::clone(&endpoint.transport);
            let id = peer_transport_id(endpoint.kind, address, ChannelKind::Slot, &self.name);
            let kind = endpoint.kind;
            tasks.push(Box::pin(async move { (kind, transport.get(&id).await) }));
        }

        let mut ok_count = 0usize;
        let mut failures = Vec::new();
        let mut best: Option<(u64, Vec<u8>, PeerSlotValue)> = None;
        while let Some((kind, get_result)) = tasks.next().await {
            match get_result {
                Ok(None) => ok_count += 1,
                Ok(Some((_server_version, bytes))) => {
                    ok_count += 1;
                    let Some(value) = self.open_value(kind, address, scope, &bytes) else {
                        continue;
                    };
                    if best.as_ref().is_none_or(|(best_version, best_bytes, _)| {
                        peer_slot_pair_is_newer(value.version, &bytes, *best_version, best_bytes)
                    }) {
                        best = Some((value.version, bytes, value));
                    }
                }
                Err(err) => failures.push((kind, err)),
            }
        }

        if ok_count == 0 && !failures.is_empty() {
            return Err(PeerSlotError::AllTransportsFailed(failures));
        }
        Ok(best.map(|(_, _, value)| value))
    }

    fn watch_address(
        &self,
        address: PeerAddress,
        scope: PeerSlotScope,
        state_key: PeerSlotScopeKey,
    ) -> Result<PeerSlotWatch, PeerSlotError> {
        let (tx, rx) = mpsc::channel(PEER_SLOT_WATCH_BUFFER);
        let best = Arc::new(Mutex::new(None::<(u64, Vec<u8>)>));
        let dedup = Arc::new(Mutex::new(Dedup::new(crate::dedup::DEFAULT_CAPACITY)));
        let since = self
            .namespace
            .state
            .store()
            .last_seen_slot_version(&peer_slot_state_key(&self.name, state_key))?
            .unwrap_or(0);

        for endpoint in &self.namespace.transports {
            let id = peer_transport_id(endpoint.kind, address, ChannelKind::Slot, &self.name);
            let mut stream = endpoint.transport.watch(&id, since);
            let tx = tx.clone();
            let best = Arc::clone(&best);
            let dedup = Arc::clone(&dedup);
            let name = self.name.clone();
            let namespace = self.namespace.clone_for_task();
            let kind = endpoint.kind;

            crate::runtime::spawn(async move {
                while let Some(item) = stream.next().await {
                    let Ok((_server_version, bytes)) = item else {
                        continue;
                    };
                    if dedup.lock().await.observe(&bytes) {
                        continue;
                    }
                    let Some(value) =
                        namespace.open_slot_value(&name, kind, address, scope, &bytes)
                    else {
                        continue;
                    };

                    let mut best = best.lock().await;
                    if best.as_ref().is_some_and(|(best_version, best_bytes)| {
                        !peer_slot_pair_is_newer(value.version, &bytes, *best_version, best_bytes)
                    }) {
                        continue;
                    }
                    *best = Some((value.version, bytes.clone()));
                    drop(best);

                    let _ = namespace.state.store().record_seen_slot_version(
                        &peer_slot_state_key(&name, state_key),
                        value.version,
                    );
                    if tx.send(value).await.is_err() {
                        break;
                    }
                }
            });
        }

        Ok(PeerSlotWatch {
            name: self.name.clone(),
            rx,
        })
    }

    fn next_version(&self, scope: PeerSlotScopeKey) -> Result<u64, PeerSlotError> {
        self.namespace
            .state
            .store()
            .next_local_slot_version(&peer_slot_state_key(&self.name, scope))
            .map_err(PeerSlotError::State)
    }

    fn open_value(
        &self,
        via: TransportKind,
        address: PeerAddress,
        scope: PeerSlotScope,
        bytes: &[u8],
    ) -> Option<PeerSlotValue> {
        self.namespace
            .open_slot_value(&self.name, via, address, scope, bytes)
    }
}

#[derive(Debug)]
pub struct PeerSendReport {
    pub delivered: Vec<TransportKind>,
    pub failed: Vec<(TransportKind, TransportError)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerMailboxMessage {
    pub sender: PeerId,
    pub signed_by: VerifyingKey,
    pub payload: Vec<u8>,
    pub via: TransportKind,
    pub group: Option<GroupId>,
    pub key_id: Option<GroupKeyId>,
}

#[derive(Debug)]
pub struct PeerSlotPutReport {
    pub version: u64,
    pub stored: Vec<TransportKind>,
    pub failed: Vec<(TransportKind, TransportError)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSlotScope {
    Pairwise,
    Publisher { publisher: PeerId },
    Group { group: GroupId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSlotValue {
    pub version: u64,
    pub sender: PeerId,
    pub signed_by: VerifyingKey,
    pub payload: Vec<u8>,
    pub via: TransportKind,
    pub scope: PeerSlotScope,
    pub key_id: Option<GroupKeyId>,
}

#[derive(Debug)]
pub struct PeerSlotWatch {
    name: String,
    rx: mpsc::Receiver<PeerSlotValue>,
}

impl PeerSlotWatch {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn recv(&mut self) -> Result<PeerSlotValue, RecvError> {
        self.rx.recv().await.ok_or(RecvError::Closed)
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

/// One encrypted recipient entry inside a public-key envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecipientEnvelope {
    pub recipient: PeerId,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Decrypted public-key envelope payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEnvelopeMessage {
    pub sender: PeerId,
    pub signed_by: VerifyingKey,
    pub payload: Vec<u8>,
}

/// One encrypted group-key entry inside a public-key group envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEnvelopeEntry {
    pub group: GroupId,
    pub key_id: GroupKeyId,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Decrypted public-key group envelope payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEnvelopeMessage {
    pub sender: PeerId,
    pub signed_by: VerifyingKey,
    pub group: GroupId,
    pub key_id: GroupKeyId,
    pub payload: Vec<u8>,
}

/// Signed group broadcast envelope with one ciphertext per group key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEnvelope {
    pub sender: PeerId,
    pub kind: ChannelKind,
    pub name: String,
    pub entries: Vec<GroupEnvelopeEntry>,
    pub signature: [u8; SIG_LEN],
}

impl GroupEnvelope {
    pub fn seal(
        sender: &PeerIdentity,
        kind: ChannelKind,
        name: &str,
        payload: &[u8],
        group_keys: &[(GroupId, GroupKey)],
    ) -> Result<Self, GroupEnvelopeError> {
        validate_name(name)?;
        if group_keys.is_empty() {
            return Err(GroupEnvelopeError::NoGroupKeys);
        }

        let sender_id = sender.peer_id();
        let mut entries = Vec::with_capacity(group_keys.len());
        for &(group, ref key) in group_keys {
            let mut nonce = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce);
            let message_key = group_message_key(group, key, kind, name, &nonce);
            let aad = group_envelope_aad(sender_id, group, key.id, kind, name, &nonce);
            let ciphertext = group_encrypt(&message_key, &nonce, &aad, payload)?;
            entries.push(GroupEnvelopeEntry {
                group,
                key_id: key.id,
                nonce,
                ciphertext,
            });
        }

        let mut envelope = Self {
            sender: sender_id,
            kind,
            name: name.to_owned(),
            entries,
            signature: [0u8; SIG_LEN],
        };
        envelope.signature = crypto::sign(&sender.signing, &envelope.signature_preimage());
        Ok(envelope)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GroupEnvelopeError> {
        rmp_serde::to_vec_named(&self.to_wire()).map_err(|_| GroupEnvelopeError::MsgpackFailed)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupEnvelopeError> {
        let wire: GroupEnvelopeWire =
            rmp_serde::from_slice(bytes).map_err(|_| GroupEnvelopeError::MsgpackFailed)?;
        Self::try_from_wire(wire)
    }

    pub fn open(
        &self,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
        group_keys: &[(GroupId, GroupKey)],
    ) -> Result<GroupEnvelopeMessage, GroupEnvelopeError> {
        validate_name(name)?;
        if self.kind != kind || self.name != name {
            return Err(GroupEnvelopeError::WrongChannel);
        }
        let sender = trusted
            .iter()
            .find(|peer| peer.peer_id() == self.sender)
            .ok_or(GroupEnvelopeError::UntrustedSender)?;
        sender
            .card
            .validate()
            .map_err(|_| GroupEnvelopeError::UntrustedSender)?;

        let mut had_matching_key = false;
        let mut had_aead_failure = false;
        for entry in &self.entries {
            for &(group, ref key) in group_keys {
                if group != entry.group || key.id != entry.key_id {
                    continue;
                }
                had_matching_key = true;
                let message_key = group_message_key(group, key, kind, name, &entry.nonce);
                let aad = group_envelope_aad(self.sender, group, key.id, kind, name, &entry.nonce);
                match group_decrypt(&message_key, &entry.nonce, &aad, &entry.ciphertext) {
                    Ok(payload) => {
                        if !crypto::verify(
                            &sender.card.signing_key,
                            &self.signature_preimage(),
                            &self.signature,
                        ) {
                            return Err(GroupEnvelopeError::SignatureInvalid);
                        }
                        return Ok(GroupEnvelopeMessage {
                            sender: self.sender,
                            signed_by: sender.card.signing_key,
                            group,
                            key_id: key.id,
                            payload,
                        });
                    }
                    Err(GroupEnvelopeError::AeadFailed) => {
                        had_aead_failure = true;
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        if had_aead_failure && had_matching_key {
            Err(GroupEnvelopeError::AeadFailed)
        } else {
            Err(GroupEnvelopeError::MissingGroupKey)
        }
    }

    #[must_use]
    pub fn open_or_drop(
        &self,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
        group_keys: &[(GroupId, GroupKey)],
    ) -> Option<GroupEnvelopeMessage> {
        self.open(kind, name, trusted, group_keys).ok()
    }

    pub fn open_bytes(
        bytes: &[u8],
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
        group_keys: &[(GroupId, GroupKey)],
    ) -> Result<GroupEnvelopeMessage, GroupEnvelopeError> {
        Self::from_bytes(bytes)?.open(kind, name, trusted, group_keys)
    }

    #[must_use]
    pub fn open_bytes_or_drop(
        bytes: &[u8],
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
        group_keys: &[(GroupId, GroupKey)],
    ) -> Option<GroupEnvelopeMessage> {
        Self::open_bytes(bytes, kind, name, trusted, group_keys).ok()
    }

    fn to_wire(&self) -> GroupEnvelopeWire {
        GroupEnvelopeWire {
            version: GROUP_ENVELOPE_RECORD_VERSION,
            sender_peer_id: self.sender.to_bytes(),
            channel_kind: channel_kind_code(self.kind),
            channel_name: self.name.clone(),
            entries: self
                .entries
                .iter()
                .map(|entry| GroupEnvelopeEntryWire {
                    group_id: entry.group.to_bytes(),
                    key_id: entry.key_id.to_bytes(),
                    nonce: entry.nonce,
                    ciphertext: entry.ciphertext.clone(),
                })
                .collect(),
            signature: self.signature.to_vec(),
        }
    }

    fn try_from_wire(wire: GroupEnvelopeWire) -> Result<Self, GroupEnvelopeError> {
        if wire.version != GROUP_ENVELOPE_RECORD_VERSION {
            return Err(GroupEnvelopeError::UnsupportedVersion);
        }
        let kind = group_channel_kind_from_code(wire.channel_kind)?;
        validate_name(&wire.channel_name)?;
        if wire.entries.is_empty() {
            return Err(GroupEnvelopeError::NoGroupKeys);
        }
        let signature = wire
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| GroupEnvelopeError::SignatureInvalid)?;
        let entries = wire
            .entries
            .into_iter()
            .map(|entry| GroupEnvelopeEntry {
                group: GroupId::from_bytes(entry.group_id),
                key_id: GroupKeyId::from_bytes(entry.key_id),
                nonce: entry.nonce,
                ciphertext: entry.ciphertext,
            })
            .collect();
        Ok(Self {
            sender: PeerId::from_bytes(wire.sender_peer_id),
            kind,
            name: wire.channel_name,
            entries,
            signature,
        })
    }

    fn signature_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"enlace/v1/pkey/group/sig/");
        out.push(GROUP_ENVELOPE_RECORD_VERSION);
        out.extend_from_slice(&self.sender.to_bytes());
        out.push(channel_kind_code(self.kind));
        write_len_prefixed(&mut out, self.name.as_bytes());
        let count =
            u32::try_from(self.entries.len()).expect("group envelope entry count overflowed u32");
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.group.to_bytes());
            out.extend_from_slice(&entry.key_id.to_bytes());
            out.extend_from_slice(&entry.nonce);
            write_len_prefixed(&mut out, &entry.ciphertext);
        }
        out
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct GroupEnvelopeWire {
    version: u8,
    sender_peer_id: [u8; PEER_ID_LEN],
    channel_kind: u8,
    channel_name: String,
    entries: Vec<GroupEnvelopeEntryWire>,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct GroupEnvelopeEntryWire {
    group_id: [u8; GROUP_ID_LEN],
    key_id: [u8; GROUP_KEY_ID_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

/// Signed fan-out envelope with one ciphertext per pairwise recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEnvelope {
    pub sender: PeerId,
    pub kind: ChannelKind,
    pub name: String,
    pub recipients: Vec<PeerRecipientEnvelope>,
    pub signature: [u8; SIG_LEN],
}

impl PeerEnvelope {
    pub fn seal(
        sender: &PeerIdentity,
        kind: ChannelKind,
        name: &str,
        payload: &[u8],
        recipients: &[PeerCard],
    ) -> Result<Self, PeerEnvelopeError> {
        validate_name(name)?;
        if recipients.is_empty() {
            return Err(PeerEnvelopeError::NoRecipients);
        }

        let sender_id = sender.peer_id();
        let mut encrypted = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            recipient
                .validate()
                .map_err(PeerEnvelopeError::InvalidRecipient)?;
            let mut nonce = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce);
            let key = pairwise_message_key(
                &sender.exchange,
                &X25519PublicKey::from(recipient.exchange_key),
                kind,
                name,
                &nonce,
            );
            let aad = peer_envelope_aad(sender_id, recipient.peer_id, kind, name, &nonce);
            let ciphertext = peer_encrypt(&key, &nonce, &aad, payload)?;
            encrypted.push(PeerRecipientEnvelope {
                recipient: recipient.peer_id,
                nonce,
                ciphertext,
            });
        }

        let mut envelope = Self {
            sender: sender_id,
            kind,
            name: name.to_owned(),
            recipients: encrypted,
            signature: [0u8; SIG_LEN],
        };
        envelope.signature = crypto::sign(&sender.signing, &envelope.signature_preimage());
        Ok(envelope)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PeerEnvelopeError> {
        rmp_serde::to_vec_named(&self.to_wire()).map_err(|_| PeerEnvelopeError::MsgpackFailed)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerEnvelopeError> {
        let wire: PeerEnvelopeWire =
            rmp_serde::from_slice(bytes).map_err(|_| PeerEnvelopeError::MsgpackFailed)?;
        Self::try_from_wire(wire)
    }

    pub fn open(
        &self,
        recipient: &PeerIdentity,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Result<PeerEnvelopeMessage, PeerEnvelopeError> {
        validate_name(name)?;
        if self.kind != kind || self.name != name {
            return Err(PeerEnvelopeError::WrongChannel);
        }
        let recipient_id = recipient.peer_id();
        let recipient_entry = self
            .recipients
            .iter()
            .find(|entry| entry.recipient == recipient_id)
            .ok_or(PeerEnvelopeError::NotAddressed)?;
        let sender = trusted
            .iter()
            .find(|peer| peer.peer_id() == self.sender)
            .ok_or(PeerEnvelopeError::UntrustedSender)?;
        sender
            .card
            .validate()
            .map_err(|_| PeerEnvelopeError::UntrustedSender)?;

        let key = pairwise_message_key(
            &recipient.exchange,
            &X25519PublicKey::from(sender.card.exchange_key),
            kind,
            name,
            &recipient_entry.nonce,
        );
        let aad = peer_envelope_aad(
            self.sender,
            recipient_entry.recipient,
            kind,
            name,
            &recipient_entry.nonce,
        );
        let payload = peer_decrypt(
            &key,
            &recipient_entry.nonce,
            &aad,
            &recipient_entry.ciphertext,
        )?;
        if !crypto::verify(
            &sender.card.signing_key,
            &self.signature_preimage(),
            &self.signature,
        ) {
            return Err(PeerEnvelopeError::SignatureInvalid);
        }

        Ok(PeerEnvelopeMessage {
            sender: self.sender,
            signed_by: sender.card.signing_key,
            payload,
        })
    }

    #[must_use]
    pub fn open_or_drop(
        &self,
        recipient: &PeerIdentity,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Option<PeerEnvelopeMessage> {
        self.open(recipient, kind, name, trusted).ok()
    }

    pub fn open_bytes(
        bytes: &[u8],
        recipient: &PeerIdentity,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Result<PeerEnvelopeMessage, PeerEnvelopeError> {
        Self::from_bytes(bytes)?.open(recipient, kind, name, trusted)
    }

    #[must_use]
    pub fn open_bytes_or_drop(
        bytes: &[u8],
        recipient: &PeerIdentity,
        kind: ChannelKind,
        name: &str,
        trusted: &[TrustedPeer],
    ) -> Option<PeerEnvelopeMessage> {
        Self::open_bytes(bytes, recipient, kind, name, trusted).ok()
    }

    fn to_wire(&self) -> PeerEnvelopeWire {
        PeerEnvelopeWire {
            version: PEER_ENVELOPE_RECORD_VERSION,
            sender_peer_id: self.sender.to_bytes(),
            channel_kind: channel_kind_code(self.kind),
            channel_name: self.name.clone(),
            recipients: self
                .recipients
                .iter()
                .map(|entry| PeerRecipientEnvelopeWire {
                    recipient_peer_id: entry.recipient.to_bytes(),
                    nonce: entry.nonce,
                    ciphertext: entry.ciphertext.clone(),
                })
                .collect(),
            signature: self.signature.to_vec(),
        }
    }

    fn try_from_wire(wire: PeerEnvelopeWire) -> Result<Self, PeerEnvelopeError> {
        if wire.version != PEER_ENVELOPE_RECORD_VERSION {
            return Err(PeerEnvelopeError::UnsupportedVersion);
        }
        let kind = channel_kind_from_code(wire.channel_kind)?;
        validate_name(&wire.channel_name)?;
        if wire.recipients.is_empty() {
            return Err(PeerEnvelopeError::NoRecipients);
        }
        let signature = wire
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| PeerEnvelopeError::SignatureInvalid)?;
        let recipients = wire
            .recipients
            .into_iter()
            .map(|entry| PeerRecipientEnvelope {
                recipient: PeerId::from_bytes(entry.recipient_peer_id),
                nonce: entry.nonce,
                ciphertext: entry.ciphertext,
            })
            .collect();
        Ok(Self {
            sender: PeerId::from_bytes(wire.sender_peer_id),
            kind,
            name: wire.channel_name,
            recipients,
            signature,
        })
    }

    fn signature_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"enlace/v1/pkey/sig/");
        out.push(PEER_ENVELOPE_RECORD_VERSION);
        out.extend_from_slice(&self.sender.to_bytes());
        out.push(channel_kind_code(self.kind));
        write_len_prefixed(&mut out, self.name.as_bytes());
        let count = u32::try_from(self.recipients.len())
            .expect("peer envelope recipient count overflowed u32");
        out.extend_from_slice(&count.to_be_bytes());
        for recipient in &self.recipients {
            out.extend_from_slice(&recipient.recipient.to_bytes());
            out.extend_from_slice(&recipient.nonce);
            write_len_prefixed(&mut out, &recipient.ciphertext);
        }
        out
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct PeerEnvelopeWire {
    version: u8,
    sender_peer_id: [u8; PEER_ID_LEN],
    channel_kind: u8,
    channel_name: String,
    recipients: Vec<PeerRecipientEnvelopeWire>,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct PeerRecipientEnvelopeWire {
    recipient_peer_id: [u8; PEER_ID_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

fn pairwise_message_key(
    secret: &StaticSecret,
    public: &X25519PublicKey,
    kind: ChannelKind,
    name: &str,
    nonce: &[u8; NONCE_LEN],
) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
    let shared = secret.diffie_hellman(public);
    let mut info = Vec::with_capacity(
        b"enlace/v1/pkey/message".len() + kind.as_bytes().len() + name.len() + nonce.len(),
    );
    info.extend_from_slice(b"enlace/v1/pkey/message");
    info.extend_from_slice(kind.as_bytes());
    info.extend_from_slice(name.as_bytes());
    info.extend_from_slice(nonce);
    let mut out = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    crypto::hkdf_sha256(shared.as_bytes(), b"", &info, out.as_mut_slice());
    out
}

fn peer_encrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, PeerEnvelopeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PeerEnvelopeError::AeadFailed)
}

fn peer_decrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PeerEnvelopeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| PeerEnvelopeError::AeadFailed)
}

fn group_message_key(
    group: GroupId,
    key: &GroupKey,
    kind: ChannelKind,
    name: &str,
    nonce: &[u8; NONCE_LEN],
) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
    let mut info = Vec::with_capacity(
        b"enlace/v1/pkey/group".len()
            + GROUP_ID_LEN
            + GROUP_KEY_ID_LEN
            + kind.as_bytes().len()
            + name.len()
            + nonce.len(),
    );
    info.extend_from_slice(b"enlace/v1/pkey/group");
    info.extend_from_slice(&group.to_bytes());
    info.extend_from_slice(&key.id.to_bytes());
    info.extend_from_slice(kind.as_bytes());
    info.extend_from_slice(name.as_bytes());
    info.extend_from_slice(nonce);
    let mut out = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    crypto::hkdf_sha256(&key.secret[..], b"", &info, out.as_mut_slice());
    out
}

fn group_encrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, GroupEnvelopeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| GroupEnvelopeError::AeadFailed)
}

fn group_decrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, GroupEnvelopeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| GroupEnvelopeError::AeadFailed)
}

fn peer_envelope_aad(
    sender: PeerId,
    recipient: PeerId,
    kind: ChannelKind,
    name: &str,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        b"enlace/v1/pkey/aead/".len()
            + PEER_ID_LEN
            + PEER_ID_LEN
            + kind.as_bytes().len()
            + name.len()
            + nonce.len(),
    );
    out.extend_from_slice(b"enlace/v1/pkey/aead/");
    out.extend_from_slice(&sender.to_bytes());
    out.extend_from_slice(&recipient.to_bytes());
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(nonce);
    out
}

fn group_envelope_aad(
    sender: PeerId,
    group: GroupId,
    key_id: GroupKeyId,
    kind: ChannelKind,
    name: &str,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        b"enlace/v1/pkey/group/aead/".len()
            + PEER_ID_LEN
            + GROUP_ID_LEN
            + GROUP_KEY_ID_LEN
            + kind.as_bytes().len()
            + name.len()
            + nonce.len(),
    );
    out.extend_from_slice(b"enlace/v1/pkey/group/aead/");
    out.extend_from_slice(&sender.to_bytes());
    out.extend_from_slice(&group.to_bytes());
    out.extend_from_slice(&key_id.to_bytes());
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(nonce);
    out
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("envelope field length overflowed u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

const fn channel_kind_code(kind: ChannelKind) -> u8 {
    match kind {
        ChannelKind::Mailbox => 0,
        ChannelKind::Slot => 1,
    }
}

fn channel_kind_from_code(code: u8) -> Result<ChannelKind, PeerEnvelopeError> {
    match code {
        0 => Ok(ChannelKind::Mailbox),
        1 => Ok(ChannelKind::Slot),
        _ => Err(PeerEnvelopeError::MsgpackFailed),
    }
}

fn group_channel_kind_from_code(code: u8) -> Result<ChannelKind, GroupEnvelopeError> {
    match code {
        0 => Ok(ChannelKind::Mailbox),
        1 => Ok(ChannelKind::Slot),
        _ => Err(GroupEnvelopeError::MsgpackFailed),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct PeerSlotInner {
    version: u8,
    slot_version: u64,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct OpenPeerSlotInner {
    version: u64,
    payload: Vec<u8>,
}

fn encode_peer_slot_payload(version: u64, payload: &[u8]) -> Result<Vec<u8>, PeerSlotError> {
    rmp_serde::to_vec_named(&PeerSlotInner {
        version: PEER_SLOT_INNER_VERSION,
        slot_version: version,
        payload: payload.to_vec(),
    })
    .map_err(|_| PeerSlotError::MsgpackFailed)
}

fn decode_peer_slot_payload(bytes: &[u8]) -> Result<OpenPeerSlotInner, PeerSlotError> {
    let inner: PeerSlotInner =
        rmp_serde::from_slice(bytes).map_err(|_| PeerSlotError::MsgpackFailed)?;
    if inner.version != PEER_SLOT_INNER_VERSION {
        return Err(PeerSlotError::MsgpackFailed);
    }
    Ok(OpenPeerSlotInner {
        version: inner.slot_version,
        payload: inner.payload,
    })
}

#[derive(Debug, Clone, Copy)]
enum PeerSlotScopeKey {
    Pairwise,
    Publisher(PeerId),
    Group(GroupId),
}

fn peer_slot_state_key(name: &str, scope: PeerSlotScopeKey) -> String {
    match scope {
        PeerSlotScopeKey::Pairwise => format!("peer-slot\0pairwise\0{name}"),
        PeerSlotScopeKey::Publisher(peer) => format!("peer-slot\0publisher\0{peer}\0{name}"),
        PeerSlotScopeKey::Group(group) => format!("peer-slot\0group\0{group}\0{name}"),
    }
}

fn peer_slot_pair_is_newer(
    version: u64,
    bytes: &[u8],
    best_version: u64,
    best_bytes: &[u8],
) -> bool {
    (version, bytes) > (best_version, best_bytes)
}

fn peer_transport_id(
    transport: TransportKind,
    address: PeerAddress,
    kind: ChannelKind,
    name: &str,
) -> Vec<u8> {
    let full = peer_address_id(address, kind, name);
    if matches!(
        transport,
        TransportKind::Iroh | TransportKind::Dht | TransportKind::Pkarr
    ) {
        full.to_vec()
    } else {
        full[..crate::kdf::CHANNEL_ID_LEN].to_vec()
    }
}

fn peer_address_id(address: PeerAddress, kind: ChannelKind, name: &str) -> [u8; 32] {
    let (domain, id): (&[u8], [u8; 32]) = match address {
        PeerAddress::Pairwise(peer) => (b"enlace/v1/pkey/addr/pairwise", peer.to_bytes()),
        PeerAddress::Publisher(peer) => (b"enlace/v1/pkey/addr/publisher", peer.to_bytes()),
        PeerAddress::Group(group) => (b"enlace/v1/pkey/addr/group", group.to_bytes()),
    };
    let mut info = Vec::with_capacity(domain.len() + kind.as_bytes().len() + name.len());
    info.extend_from_slice(domain);
    info.extend_from_slice(kind.as_bytes());
    info.extend_from_slice(name.as_bytes());
    let mut out = [0u8; 32];
    crypto::hkdf_sha256(&id, b"", &info, &mut out);
    out
}

#[cfg(feature = "iroh")]
async fn open_peer_iroh_transport(
    config: &PeerConfig,
    state: &dyn crate::state::StateStore,
) -> Result<Option<Arc<IrohTransport>>, OpenError> {
    if let Some(iroh_config) = &config.iroh {
        let mut iroh_config = iroh_config.clone();
        let trusted_endpoints = trusted_iroh_endpoints(&config.trusted_peers);
        for endpoint in &trusted_endpoints {
            upsert_iroh_peer(&mut iroh_config.peers, endpoint.clone());
        }
        let allowed = (!trusted_endpoints.is_empty()).then(|| {
            trusted_endpoints
                .iter()
                .map(|endpoint| endpoint.endpoint_id)
                .collect::<Vec<_>>()
        });
        let iroh = Arc::new(
            IrohTransport::new_with_allowed_endpoints(&iroh_config, state, allowed)
                .await
                .map_err(|err| match err {
                    crate::transports::IrohInitError::State(err) => OpenError::State(err),
                    crate::transports::IrohInitError::Transport(err) => {
                        OpenError::TransportInit(TransportKind::Iroh, Box::new(err))
                    }
                })?,
        );
        Ok(Some(iroh))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "iroh")]
fn trusted_iroh_endpoints(trusted: &[TrustedPeer]) -> Vec<IrohEndpointAddr> {
    trusted
        .iter()
        .filter_map(|peer| peer.card.iroh_endpoint.clone())
        .collect()
}

#[cfg(feature = "iroh")]
fn upsert_iroh_peer(peers: &mut Vec<IrohEndpointAddr>, peer: IrohEndpointAddr) {
    if let Some(existing) = peers
        .iter_mut()
        .find(|existing| existing.endpoint_id == peer.endpoint_id)
    {
        *existing = peer;
    } else {
        peers.push(peer);
    }
}

fn write_trusted_peers<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_trusted_peers<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_group_keys<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_group_keys<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "iroh")]
fn update_iroh_trusted_endpoint(
    iroh: Option<&Arc<IrohTransport>>,
    old_endpoint_id: Option<[u8; 32]>,
    endpoint: Option<IrohEndpointAddr>,
) {
    let Some(iroh) = iroh else {
        return;
    };
    if old_endpoint_id.is_some_and(|old| endpoint.as_ref().is_none_or(|new| new.endpoint_id != old))
        && let Some(old) = old_endpoint_id
    {
        iroh.revoke_peer(old);
    }
    if let Some(endpoint) = endpoint {
        iroh.allow_peer(endpoint);
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
    fn peer_envelope_round_trips_for_trusted_recipient() {
        let sender = identity(21, 22);
        let recipient = identity(23, 24);
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];

        let envelope = sender
            .seal_to_peers(
                ChannelKind::Mailbox,
                "ops/events",
                b"hello peer",
                &[recipient.card()],
            )
            .unwrap();
        let bytes = envelope.to_bytes().unwrap();
        let decoded = PeerEnvelope::from_bytes(&bytes).unwrap();
        let message = recipient
            .open_peer_envelope(&decoded, ChannelKind::Mailbox, "ops/events", &trusted)
            .unwrap();

        assert_eq!(message.sender, sender.peer_id());
        assert_eq!(message.signed_by, sender.signing.verifying_key());
        assert_eq!(message.payload, b"hello peer");
    }

    #[test]
    fn peer_envelope_fans_out_with_distinct_recipient_ciphertexts() {
        let sender = identity(31, 32);
        let first = identity(33, 34);
        let second = identity(35, 36);
        let outsider = identity(37, 38);
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];

        let envelope = PeerEnvelope::seal(
            &sender,
            ChannelKind::Mailbox,
            "ops/events",
            b"group-ish",
            &[first.card(), second.card()],
        )
        .unwrap();

        assert_eq!(envelope.recipients.len(), 2);
        assert_ne!(envelope.recipients[0].nonce, envelope.recipients[1].nonce);
        assert_ne!(
            envelope.recipients[0].ciphertext,
            envelope.recipients[1].ciphertext
        );
        assert_eq!(
            envelope
                .open(&first, ChannelKind::Mailbox, "ops/events", &trusted)
                .unwrap()
                .payload,
            b"group-ish"
        );
        assert_eq!(
            envelope
                .open(&second, ChannelKind::Mailbox, "ops/events", &trusted)
                .unwrap()
                .payload,
            b"group-ish"
        );
        assert_eq!(
            envelope
                .open(&outsider, ChannelKind::Mailbox, "ops/events", &trusted)
                .unwrap_err(),
            PeerEnvelopeError::NotAddressed
        );
    }

    #[test]
    fn peer_envelope_enforces_trusted_sender() {
        let sender = identity(41, 42);
        let recipient = identity(43, 44);
        let stranger = identity(45, 46);
        let trusted = [TrustedPeer::try_from_card(stranger.card()).unwrap()];
        let envelope = sender
            .seal_to_peers(
                ChannelKind::Mailbox,
                "ops/events",
                b"untrusted",
                &[recipient.card()],
            )
            .unwrap();

        assert_eq!(
            envelope
                .open(&recipient, ChannelKind::Mailbox, "ops/events", &trusted)
                .unwrap_err(),
            PeerEnvelopeError::UntrustedSender
        );
        assert_eq!(
            envelope.open_or_drop(&recipient, ChannelKind::Mailbox, "ops/events", &trusted),
            None
        );
    }

    #[test]
    fn peer_envelope_rejects_wrong_channel_and_bad_signature() {
        let sender = identity(51, 52);
        let recipient = identity(53, 54);
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];
        let mut envelope = sender
            .seal_to_peers(
                ChannelKind::Mailbox,
                "ops/events",
                b"payload",
                &[recipient.card()],
            )
            .unwrap();

        assert_eq!(
            envelope
                .open(&recipient, ChannelKind::Slot, "ops/events", &trusted)
                .unwrap_err(),
            PeerEnvelopeError::WrongChannel
        );
        envelope.signature[0] ^= 0x01;
        assert_eq!(
            envelope
                .open(&recipient, ChannelKind::Mailbox, "ops/events", &trusted)
                .unwrap_err(),
            PeerEnvelopeError::SignatureInvalid
        );
    }

    #[test]
    fn peer_envelope_drops_malformed_and_tampered_bytes() {
        let sender = identity(61, 62);
        let recipient = identity(63, 64);
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];
        let envelope = sender
            .seal_to_peers(
                ChannelKind::Mailbox,
                "ops/events",
                b"payload",
                &[recipient.card()],
            )
            .unwrap();

        let mut bytes = envelope.to_bytes().unwrap();
        assert_eq!(
            PeerEnvelope::open_bytes_or_drop(
                b"bad msgpack",
                &recipient,
                ChannelKind::Mailbox,
                "ops/events",
                &trusted,
            ),
            None
        );

        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            PeerEnvelope::open_bytes_or_drop(
                &bytes,
                &recipient,
                ChannelKind::Mailbox,
                "ops/events",
                &trusted,
            ),
            None
        );
    }

    #[test]
    fn peer_envelope_rejects_invalid_inputs() {
        let sender = identity(71, 72);
        let recipient = identity(73, 74);
        let mut bad_card = recipient.card();
        bad_card.exchange_key = [0; 32];

        assert_eq!(
            PeerEnvelope::seal(&sender, ChannelKind::Mailbox, "ops/events", b"x", &[]).unwrap_err(),
            PeerEnvelopeError::NoRecipients
        );
        assert_eq!(
            PeerEnvelope::seal(
                &sender,
                ChannelKind::Mailbox,
                "Bad",
                b"x",
                &[recipient.card()]
            )
            .unwrap_err(),
            PeerEnvelopeError::Name(NameError::InvalidChar)
        );
        assert_eq!(
            PeerEnvelope::seal(
                &sender,
                ChannelKind::Mailbox,
                "ops/events",
                b"x",
                &[bad_card]
            )
            .unwrap_err(),
            PeerEnvelopeError::InvalidRecipient(PeerCardError::EmptyExchangeKey)
        );
    }

    #[tokio::test]
    async fn group_envelope_round_trips_for_trusted_sender() {
        let sender = identity(91, 92);
        let receiver = PeerNamespace::open(identity(93, 94), PeerConfig::default())
            .await
            .unwrap();
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];
        let group = GroupId::from_bytes([1; GROUP_ID_LEN]);
        let key = GroupKey::new(GroupKeyId::from_bytes([2; GROUP_KEY_ID_LEN]), [3; 32]);
        receiver.add_group_key(group, key.clone()).unwrap();

        let envelope = sender
            .seal_to_groups(
                ChannelKind::Mailbox,
                "ops/events",
                b"hello group",
                &[(group, key.clone())],
            )
            .unwrap();
        let bytes = envelope.to_bytes().unwrap();
        let decoded = GroupEnvelope::from_bytes(&bytes).unwrap();
        let message = receiver
            .open_group_envelope(&decoded, ChannelKind::Mailbox, "ops/events", &trusted)
            .unwrap();

        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].group, group);
        assert_eq!(decoded.entries[0].key_id, key.id);
        assert_eq!(message.sender, sender.peer_id());
        assert_eq!(message.signed_by, sender.signing.verifying_key());
        assert_eq!(message.group, group);
        assert_eq!(message.key_id, key.id);
        assert_eq!(message.payload, b"hello group");
    }

    #[test]
    fn group_envelope_uses_one_ciphertext_per_group_key() {
        let sender = identity(95, 96);
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];
        let first_group = GroupId::from_bytes([4; GROUP_ID_LEN]);
        let second_group = GroupId::from_bytes([5; GROUP_ID_LEN]);
        let first_key = GroupKey::new(GroupKeyId::from_bytes([6; GROUP_KEY_ID_LEN]), [7; 32]);
        let second_key = GroupKey::new(GroupKeyId::from_bytes([8; GROUP_KEY_ID_LEN]), [9; 32]);

        let envelope = GroupEnvelope::seal(
            &sender,
            ChannelKind::Mailbox,
            "ops/events",
            b"broadcast",
            &[
                (first_group, first_key.clone()),
                (second_group, second_key.clone()),
            ],
        )
        .unwrap();

        assert_eq!(envelope.entries.len(), 2);
        assert_ne!(envelope.entries[0].nonce, envelope.entries[1].nonce);
        assert_ne!(
            envelope.entries[0].ciphertext,
            envelope.entries[1].ciphertext
        );
        assert_eq!(
            envelope
                .open(
                    ChannelKind::Mailbox,
                    "ops/events",
                    &trusted,
                    &[(second_group, second_key.clone())],
                )
                .unwrap()
                .payload,
            b"broadcast"
        );
    }

    #[tokio::test]
    async fn group_envelope_ignores_missing_or_removed_keys() {
        let sender = identity(97, 98);
        let receiver = PeerNamespace::open(identity(99, 100), PeerConfig::default())
            .await
            .unwrap();
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];
        let group = GroupId::from_bytes([10; GROUP_ID_LEN]);
        let key = GroupKey::new(GroupKeyId::from_bytes([11; GROUP_KEY_ID_LEN]), [12; 32]);
        receiver.add_group_key(group, key.clone()).unwrap();
        let envelope = sender
            .seal_to_groups(
                ChannelKind::Mailbox,
                "ops/events",
                b"rotated",
                &[(group, key.clone())],
            )
            .unwrap();
        let bytes = envelope.to_bytes().unwrap();

        receiver.remove_group_key(group, key.id).unwrap();

        assert_eq!(
            envelope
                .open(ChannelKind::Mailbox, "ops/events", &trusted, &[])
                .unwrap_err(),
            GroupEnvelopeError::MissingGroupKey
        );
        assert_eq!(
            receiver.open_group_envelope_or_drop(
                &bytes,
                ChannelKind::Mailbox,
                "ops/events",
                &trusted,
            ),
            None
        );
    }

    #[test]
    fn group_envelope_enforces_trusted_sender_and_channel() {
        let sender = identity(101, 102);
        let stranger = identity(103, 104);
        let trusted = [TrustedPeer::try_from_card(stranger.card()).unwrap()];
        let group = GroupId::from_bytes([13; GROUP_ID_LEN]);
        let key = GroupKey::new(GroupKeyId::from_bytes([14; GROUP_KEY_ID_LEN]), [15; 32]);
        let envelope = sender
            .seal_to_groups(
                ChannelKind::Mailbox,
                "ops/events",
                b"private",
                &[(group, key.clone())],
            )
            .unwrap();

        assert_eq!(
            envelope
                .open(
                    ChannelKind::Mailbox,
                    "ops/events",
                    &trusted,
                    &[(group, key.clone())],
                )
                .unwrap_err(),
            GroupEnvelopeError::UntrustedSender
        );
        assert_eq!(
            envelope
                .open(
                    ChannelKind::Slot,
                    "ops/events",
                    &[TrustedPeer::try_from_card(sender.card()).unwrap()],
                    &[(group, key.clone())],
                )
                .unwrap_err(),
            GroupEnvelopeError::WrongChannel
        );
    }

    #[test]
    fn group_envelope_drops_malformed_and_tampered_bytes() {
        let sender = identity(105, 106);
        let trusted = [TrustedPeer::try_from_card(sender.card()).unwrap()];
        let group = GroupId::from_bytes([16; GROUP_ID_LEN]);
        let key = GroupKey::new(GroupKeyId::from_bytes([17; GROUP_KEY_ID_LEN]), [18; 32]);
        let envelope = sender
            .seal_to_groups(
                ChannelKind::Mailbox,
                "ops/events",
                b"payload",
                &[(group, key.clone())],
            )
            .unwrap();
        let mut bytes = envelope.to_bytes().unwrap();

        assert_eq!(
            GroupEnvelope::open_bytes_or_drop(
                b"bad msgpack",
                ChannelKind::Mailbox,
                "ops/events",
                &trusted,
                &[(group, key.clone())],
            ),
            None
        );

        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            GroupEnvelope::open_bytes_or_drop(
                &bytes,
                ChannelKind::Mailbox,
                "ops/events",
                &trusted,
                &[(group, key.clone())],
            ),
            None
        );
    }

    #[test]
    fn group_envelope_rejects_invalid_inputs() {
        let sender = identity(107, 108);
        let group = GroupId::from_bytes([19; GROUP_ID_LEN]);
        let key = GroupKey::new(GroupKeyId::from_bytes([20; GROUP_KEY_ID_LEN]), [21; 32]);

        assert_eq!(
            GroupEnvelope::seal(&sender, ChannelKind::Mailbox, "ops/events", b"x", &[])
                .unwrap_err(),
            GroupEnvelopeError::NoGroupKeys
        );
        assert_eq!(
            GroupEnvelope::seal(&sender, ChannelKind::Mailbox, "Bad", b"x", &[(group, key)])
                .unwrap_err(),
            GroupEnvelopeError::Name(NameError::InvalidChar)
        );
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

    #[tokio::test]
    async fn peer_namespace_seeds_and_lists_group_keys() {
        let group = GroupId::from_bytes([1; GROUP_ID_LEN]);
        let other_group = GroupId::from_bytes([2; GROUP_ID_LEN]);
        let first = GroupKey::new(GroupKeyId::from_bytes([3; GROUP_KEY_ID_LEN]), [4; 32]);
        let second = GroupKey::new(GroupKeyId::from_bytes([5; GROUP_KEY_ID_LEN]), [6; 32]);
        let other = GroupKey::new(GroupKeyId::from_bytes([7; GROUP_KEY_ID_LEN]), [8; 32]);

        let namespace = PeerNamespace::open(
            identity(80, 81),
            PeerConfig {
                group_keys: vec![
                    (group, second.clone()),
                    (other_group, other.clone()),
                    (group, first.clone()),
                ],
                ..PeerConfig::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(namespace.peer_id(), identity(80, 81).peer_id());
        assert_eq!(namespace.card(), identity(80, 81).card());
        assert_eq!(namespace.list_group_keys(group), vec![first.id, second.id]);
        assert_eq!(namespace.list_group_keys(other_group), vec![other.id]);
    }

    #[tokio::test]
    async fn peer_namespace_adds_replaces_and_removes_group_keys() {
        let group = GroupId::from_bytes([9; GROUP_ID_LEN]);
        let key_id = GroupKeyId::from_bytes([10; GROUP_KEY_ID_LEN]);
        let first = GroupKey::new(key_id, [11; 32]);
        let replacement = GroupKey::new(key_id, [12; 32]);
        let namespace = PeerNamespace::open(identity(82, 83), PeerConfig::default())
            .await
            .unwrap();

        namespace.add_group_key(group, first).unwrap();
        namespace.add_group_key(group, replacement).unwrap();
        assert_eq!(namespace.list_group_keys(group), vec![key_id]);

        namespace.remove_group_key(group, key_id).unwrap();
        assert!(namespace.list_group_keys(group).is_empty());
    }

    #[tokio::test]
    async fn peer_namespace_group_key_mutations_update_state() {
        let state = State::memory();
        let group = GroupId::from_bytes([13; GROUP_ID_LEN]);
        let key = GroupKey::new(GroupKeyId::from_bytes([14; GROUP_KEY_ID_LEN]), [15; 32]);
        let namespace = PeerNamespace::open(
            identity(84, 85),
            PeerConfig {
                state: state.clone(),
                group_keys: Vec::new(),
                ..PeerConfig::default()
            },
        )
        .await
        .unwrap();

        namespace.add_group_key(group, key.clone()).unwrap();
        assert_eq!(state.group_keys(group).unwrap(), vec![key.clone()]);

        namespace.remove_group_key(group, key.id).unwrap();
        assert!(state.group_keys(group).unwrap().is_empty());
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
