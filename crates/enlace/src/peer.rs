//! Public-key peer identity types.

use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;
use std::sync::RwLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, Payload, rand_core::RngCore},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::config::IrohEndpointAddr;
use crate::crypto::{self, AEAD_KEY_LEN, NONCE_LEN, SIG_LEN};
use crate::kdf::{ChannelKind, NameError, validate_name};
use crate::state::{State, StateError};

pub const PEER_ID_LEN: usize = 32;
pub const GROUP_ID_LEN: usize = 32;
pub const GROUP_KEY_ID_LEN: usize = 32;
pub const GROUP_KEY_SECRET_LEN: usize = 32;
const PEER_CARD_EXPORT_PREFIX: &str = "enlace-peer-card-v1:";
const PEER_CARD_RECORD_VERSION: u8 = 1;
const PEER_ENVELOPE_RECORD_VERSION: u8 = 1;

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
    pub group_keys: Vec<(GroupId, GroupKey)>,
}

/// Live public-key namespace state.
pub struct PeerNamespace {
    identity: PeerIdentity,
    state: State,
    group_keys: RwLock<HashMap<(GroupId, GroupKeyId), GroupKey>>,
}

impl PeerNamespace {
    pub fn open(identity: PeerIdentity, config: PeerConfig) -> Result<Self, GroupKeyError> {
        let namespace = Self {
            identity,
            state: config.state,
            group_keys: RwLock::new(HashMap::new()),
        };
        for (group, key) in config.group_keys {
            namespace.add_group_key(group, key)?;
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

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("peer envelope field length overflowed u32");
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

fn write_group_keys<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_group_keys<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    fn peer_namespace_seeds_and_lists_group_keys() {
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
        .unwrap();

        assert_eq!(namespace.peer_id(), identity(80, 81).peer_id());
        assert_eq!(namespace.card(), identity(80, 81).card());
        assert_eq!(namespace.list_group_keys(group), vec![first.id, second.id]);
        assert_eq!(namespace.list_group_keys(other_group), vec![other.id]);
    }

    #[test]
    fn peer_namespace_adds_replaces_and_removes_group_keys() {
        let group = GroupId::from_bytes([9; GROUP_ID_LEN]);
        let key_id = GroupKeyId::from_bytes([10; GROUP_KEY_ID_LEN]);
        let first = GroupKey::new(key_id, [11; 32]);
        let replacement = GroupKey::new(key_id, [12; 32]);
        let namespace = PeerNamespace::open(identity(82, 83), PeerConfig::default()).unwrap();

        namespace.add_group_key(group, first).unwrap();
        namespace.add_group_key(group, replacement).unwrap();
        assert_eq!(namespace.list_group_keys(group), vec![key_id]);

        namespace.remove_group_key(group, key_id).unwrap();
        assert!(namespace.list_group_keys(group).is_empty());
    }

    #[test]
    fn peer_namespace_group_key_mutations_update_state() {
        let state = State::memory();
        let group = GroupId::from_bytes([13; GROUP_ID_LEN]);
        let key = GroupKey::new(GroupKeyId::from_bytes([14; GROUP_KEY_ID_LEN]), [15; 32]);
        let namespace = PeerNamespace::open(
            identity(84, 85),
            PeerConfig {
                state: state.clone(),
                group_keys: Vec::new(),
            },
        )
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
