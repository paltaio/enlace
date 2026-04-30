#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

//! Encrypted mailbox and latest-value slot transport fan-out.
//!
//! `enlace` exposes two namespace modes over the same transport set:
//!
//! - [`Namespace`] is shared-seed mode. Use it when every participant can safely
//!   share one 32-byte secret and should have equal read/write access to the same
//!   mailbox and slot names. This fits small trusted clusters, local recovery
//!   slots, and deployments where membership is already controlled outside the
//!   library. Optional signing keys can authenticate incoming records, but the
//!   shared seed still grants access to all peers that know it.
//! - [`PeerNamespace`] is public-key mode. Use it when peers have separate
//!   long-term identities, pair by exchanging [`PeerCard`] values, and need
//!   per-peer trust, revocation, pairwise envelopes, caller-managed group keys,
//!   or iroh endpoint allowlists. Caller code owns identity persistence, card
//!   exchange, authorization policy, group membership, and group-key rotation.
//!
//! HTTP and iroh transports can carry mailbox messages in both modes. HTTP,
//! DHT, pkarr, and iroh can carry slots; DHT and pkarr are latest-record slot
//! transports and do not provide mailbox delivery.

pub mod config;
pub mod coordinator;
pub mod crypto;
pub mod dedup;
pub mod error;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
pub mod guard;
pub mod kdf;
pub mod mailbox;
pub mod namespace;
pub mod peer;
pub mod slot;
pub mod state;
pub mod transports;

pub use config::{
    BasicAuth, Config, ConfiguredTransport, DhtBootstrapCacheConfig, DhtConfig, HttpConfig,
    IrohConfig, IrohEndpointAddr, IrohRelayMode, PkarrConfig,
};
pub use error::{OpenError, RecvError, SealError, SendError, SlotError, TransportError};
pub use kdf::{ChannelKind, NameError, TransportKind};
pub use mailbox::{Mailbox, RecvMessage, SendReport};
pub use namespace::Namespace;
pub use peer::{
    GROUP_ID_LEN, GROUP_KEY_ID_LEN, GROUP_KEY_SECRET_LEN, GroupEnvelope, GroupEnvelopeEntry,
    GroupEnvelopeError, GroupEnvelopeMessage, GroupId, GroupKey, GroupKeyError, GroupKeyId,
    PEER_ID_LEN, PeerCard, PeerCardError, PeerConfig, PeerEnvelope, PeerEnvelopeError,
    PeerEnvelopeMessage, PeerId, PeerIdentity, PeerMailbox, PeerMailboxMessage, PeerNamespace,
    PeerRecipientEnvelope, PeerSendError, PeerSendReport, PeerSlot, PeerSlotError,
    PeerSlotPutReport, PeerSlotScope, PeerSlotValue, PeerSlotWatch, TrustError, TrustedPeer,
};
pub use slot::{PutReport, Slot, SlotValue, SlotWatch};
pub use state::{InMemoryStateStore, State, StateError, StateStore};
pub use transports::{
    DhtTransport, EndpointHealth, HealthReport, HealthState, HealthTransition,
    HealthTransitionKind, HttpTransport, IrohTransport, MailboxTransport, PkarrTransport,
    SlotTransport, SlotWatchStream, Transport, TransportHealth,
};
