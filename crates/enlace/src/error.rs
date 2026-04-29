//! Error enums for the public API.
//!
//! `recv` is forgiving: bad ciphertext, bad msgpack, bad signature, or an
//! untrusted signer all cause the offending message to be logged and dropped,
//! and `recv()` only fails when the namespace is being shut down.
//!
//! `send` and `put` are strict: when every enabled transport fails the error
//! enumerates each per-transport failure for diagnostics.

use std::error::Error as StdError;
use std::fmt;

use crate::crypto::CryptoError;
use crate::kdf::TransportKind;
use crate::state::StateError;

// -- SealError --------------------------------------------------------------

/// Failure modes when sealing or unsealing a wire frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Sealed payload shorter than the nonce + tag overhead.
    TooShort,
    /// AEAD authentication failed: wrong key, wrong AAD, or tampered ciphertext.
    AeadFailed,
    /// Inner msgpack envelope failed to decode.
    MsgpackFailed,
    /// Trusted-keys are configured but the frame carried no signature.
    SignatureMissing,
    /// Signature verification failed.
    SignatureInvalid,
    /// Signature verified, but the signing key is not in the trusted set.
    UntrustedSigner,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("sealed payload too short"),
            Self::AeadFailed => f.write_str("AEAD authentication failed"),
            Self::MsgpackFailed => f.write_str("malformed msgpack envelope"),
            Self::SignatureMissing => f.write_str("signature required but absent"),
            Self::SignatureInvalid => f.write_str("signature verification failed"),
            Self::UntrustedSigner => f.write_str("signer is not in the trusted set"),
        }
    }
}

impl StdError for SealError {}

impl From<CryptoError> for SealError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::TooShort => SealError::TooShort,
            CryptoError::AeadFailed => SealError::AeadFailed,
        }
    }
}

// -- TransportError ---------------------------------------------------------

/// Failure of a single transport adapter.
#[derive(Debug)]
pub enum TransportError {
    /// Network-layer failure with a human-readable description.
    Network(String),
    /// Server rejected the request with an authentication error.
    Auth,
    /// Slot put rejected because the version was not strictly newer.
    Stale,
    /// Server rejected the body for exceeding the configured size cap.
    BodyTooLarge,
    /// Operation timed out before completion.
    Timeout,
    /// Transport does not support this operation shape.
    Unsupported,
    /// Adapter-specific failure carrying the underlying error.
    Other(Box<dyn StdError + Send + Sync>),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "network error: {msg}"),
            Self::Auth => f.write_str("authentication failed"),
            Self::Stale => f.write_str("slot put rejected: version is not newer"),
            Self::BodyTooLarge => f.write_str("body exceeded configured size cap"),
            Self::Timeout => f.write_str("request timed out"),
            Self::Unsupported => f.write_str("operation is not supported by this transport"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl StdError for TransportError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Other(e) => Some(&**e),
            _ => None,
        }
    }
}

// -- OpenError --------------------------------------------------------------

/// Failure modes for [`Namespace::open`](crate).
#[derive(Debug)]
pub enum OpenError {
    /// Config did not enable any transport.
    NoTransport,
    /// Seed bytes failed validation (e.g. all-zero seed).
    InvalidSeed,
    /// Trusted keys configured without a signing key — every outgoing frame
    /// would be dropped on the receiver side, so the configuration is rejected.
    TrustedWithoutSigning,
    /// A transport adapter failed to initialize.
    TransportInit(TransportKind, Box<dyn StdError + Send + Sync>),
    /// State store access failed during open.
    State(StateError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTransport => f.write_str("no transport configured"),
            Self::InvalidSeed => f.write_str("seed failed validation"),
            Self::TrustedWithoutSigning => {
                f.write_str("trusted keys configured without a signing key")
            }
            Self::TransportInit(kind, e) => {
                write!(f, "{kind} transport failed to initialize: {e}")
            }
            Self::State(e) => write!(f, "state store error: {e}"),
        }
    }
}

impl StdError for OpenError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::TransportInit(_, e) => Some(&**e),
            Self::State(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StateError> for OpenError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

// -- SendError --------------------------------------------------------------

/// Failure modes for [`Mailbox::send`](crate).
#[derive(Debug)]
pub enum SendError {
    /// Every enabled transport rejected or failed the send.
    AllTransportsFailed(Vec<(TransportKind, TransportError)>),
    /// Sealing the outgoing payload failed before any transport was tried.
    Sealing(SealError),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllTransportsFailed(failures) => format_all_failed(f, failures),
            Self::Sealing(e) => write!(f, "sealing failed: {e}"),
        }
    }
}

impl StdError for SendError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Sealing(e) => Some(e),
            Self::AllTransportsFailed(_) => None,
        }
    }
}

impl From<SealError> for SendError {
    fn from(e: SealError) -> Self {
        Self::Sealing(e)
    }
}

// -- RecvError --------------------------------------------------------------

/// Failure modes for [`Mailbox::recv`](crate).
///
/// The receive path discards malformed or untrusted frames silently;
/// `Closed` is the only path through which `recv` ever returns an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// The owning namespace has been dropped.
    Closed,
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("namespace closed"),
        }
    }
}

impl StdError for RecvError {}

// -- SlotError --------------------------------------------------------------

/// Failure modes for [`Slot::put`](crate) and [`Slot::get`](crate).
#[derive(Debug)]
pub enum SlotError {
    /// Every enabled transport rejected or failed the operation.
    AllTransportsFailed(Vec<(TransportKind, TransportError)>),
    /// Sealing the outgoing payload failed before any transport was tried.
    Sealing(SealError),
    /// State store access failed.
    State(StateError),
}

impl fmt::Display for SlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllTransportsFailed(failures) => format_all_failed(f, failures),
            Self::Sealing(e) => write!(f, "sealing failed: {e}"),
            Self::State(e) => write!(f, "state store error: {e}"),
        }
    }
}

impl StdError for SlotError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Sealing(e) => Some(e),
            Self::State(e) => Some(e),
            Self::AllTransportsFailed(_) => None,
        }
    }
}

impl From<SealError> for SlotError {
    fn from(e: SealError) -> Self {
        Self::Sealing(e)
    }
}

impl From<StateError> for SlotError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

// -- helpers ----------------------------------------------------------------

fn format_all_failed(
    f: &mut fmt::Formatter<'_>,
    failures: &[(TransportKind, TransportError)],
) -> fmt::Result {
    write!(f, "all {} transport(s) failed", failures.len())?;
    let mut sep = ": ";
    for (kind, err) in failures {
        write!(f, "{sep}{kind}: {err}")?;
        sep = ", ";
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- SealError ----------------------------------------------------------

    #[test]
    fn seal_error_display_strings() {
        assert_eq!(SealError::TooShort.to_string(), "sealed payload too short");
        assert_eq!(
            SealError::AeadFailed.to_string(),
            "AEAD authentication failed"
        );
        assert_eq!(
            SealError::MsgpackFailed.to_string(),
            "malformed msgpack envelope"
        );
        assert_eq!(
            SealError::SignatureMissing.to_string(),
            "signature required but absent"
        );
        assert_eq!(
            SealError::SignatureInvalid.to_string(),
            "signature verification failed"
        );
        assert_eq!(
            SealError::UntrustedSigner.to_string(),
            "signer is not in the trusted set"
        );
    }

    #[test]
    fn seal_error_no_source() {
        assert!(StdError::source(&SealError::TooShort).is_none());
    }

    #[test]
    fn seal_error_from_crypto_error() {
        assert_eq!(SealError::from(CryptoError::TooShort), SealError::TooShort);
        assert_eq!(
            SealError::from(CryptoError::AeadFailed),
            SealError::AeadFailed
        );
    }

    // -- TransportError -----------------------------------------------------

    #[test]
    fn transport_error_display_unit_variants() {
        assert_eq!(TransportError::Auth.to_string(), "authentication failed");
        assert_eq!(
            TransportError::Stale.to_string(),
            "slot put rejected: version is not newer"
        );
        assert_eq!(
            TransportError::BodyTooLarge.to_string(),
            "body exceeded configured size cap"
        );
        assert_eq!(TransportError::Timeout.to_string(), "request timed out");
        assert_eq!(
            TransportError::Unsupported.to_string(),
            "operation is not supported by this transport"
        );
    }

    #[test]
    fn transport_error_network_includes_message() {
        let e = TransportError::Network("connection refused".into());
        assert_eq!(e.to_string(), "network error: connection refused");
    }

    #[test]
    fn transport_error_other_carries_source() {
        let inner = std::io::Error::other("disk full");
        let e = TransportError::Other(Box::new(inner));
        assert_eq!(e.to_string(), "disk full");
        assert!(StdError::source(&e).is_some());
    }

    #[test]
    fn transport_error_unit_variants_have_no_source() {
        assert!(StdError::source(&TransportError::Auth).is_none());
        assert!(StdError::source(&TransportError::Stale).is_none());
        assert!(StdError::source(&TransportError::Timeout).is_none());
        assert!(StdError::source(&TransportError::Unsupported).is_none());
        assert!(StdError::source(&TransportError::Network("x".into())).is_none());
    }

    // -- OpenError ----------------------------------------------------------

    #[test]
    fn open_error_display_strings() {
        assert_eq!(
            OpenError::NoTransport.to_string(),
            "no transport configured"
        );
        assert_eq!(OpenError::InvalidSeed.to_string(), "seed failed validation");
        assert_eq!(
            OpenError::TrustedWithoutSigning.to_string(),
            "trusted keys configured without a signing key",
        );
    }

    #[test]
    fn open_error_transport_init_includes_kind() {
        let inner = std::io::Error::other("bind failed");
        let e = OpenError::TransportInit(TransportKind::Iroh, Box::new(inner));
        assert_eq!(
            e.to_string(),
            "iroh transport failed to initialize: bind failed",
        );
        assert!(StdError::source(&e).is_some());
    }

    #[test]
    fn open_error_state_chains_to_state_error() {
        let inner = StateError::Corrupted("bad keypair length".into());
        let e: OpenError = inner.into();
        assert_eq!(
            e.to_string(),
            "state store error: state corrupted: bad keypair length"
        );
        let chain = StdError::source(&e).expect("State variant has a source");
        assert_eq!(chain.to_string(), "state corrupted: bad keypair length");
    }

    // -- SendError ----------------------------------------------------------

    #[test]
    fn send_error_sealing_chains() {
        let e: SendError = SealError::SignatureInvalid.into();
        assert_eq!(
            e.to_string(),
            "sealing failed: signature verification failed"
        );
        let chain = StdError::source(&e).expect("Sealing variant has a source");
        assert_eq!(chain.to_string(), "signature verification failed");
    }

    #[test]
    fn send_error_all_failed_lists_each_transport() {
        let failures = vec![
            (TransportKind::Http, TransportError::Auth),
            (
                TransportKind::Pkarr,
                TransportError::Network("dns refused".into()),
            ),
        ];
        let e = SendError::AllTransportsFailed(failures);
        assert_eq!(
            e.to_string(),
            "all 2 transport(s) failed: http: authentication failed, pkarr: network error: dns refused",
        );
        assert!(StdError::source(&e).is_none());
    }

    // -- RecvError ----------------------------------------------------------

    #[test]
    fn recv_error_display_and_no_source() {
        assert_eq!(RecvError::Closed.to_string(), "namespace closed");
        assert!(StdError::source(&RecvError::Closed).is_none());
    }

    // -- SlotError ----------------------------------------------------------

    #[test]
    fn slot_error_sealing_chains() {
        let e: SlotError = SealError::AeadFailed.into();
        assert_eq!(e.to_string(), "sealing failed: AEAD authentication failed");
        assert!(StdError::source(&e).is_some());
    }

    #[test]
    fn slot_error_state_chains() {
        let e: SlotError = StateError::Corrupted("oops".into()).into();
        assert_eq!(e.to_string(), "state store error: state corrupted: oops");
        let chain = StdError::source(&e).expect("State variant has a source");
        assert_eq!(chain.to_string(), "state corrupted: oops");
    }

    #[test]
    fn slot_error_all_failed_lists_single_transport() {
        let failures = vec![(TransportKind::Dht, TransportError::Stale)];
        let e = SlotError::AllTransportsFailed(failures);
        assert_eq!(
            e.to_string(),
            "all 1 transport(s) failed: dht: slot put rejected: version is not newer",
        );
    }

    // -- TransportKind Display passthrough ----------------------------------

    #[test]
    fn transport_kind_display_lowercase_token() {
        assert_eq!(TransportKind::Http.to_string(), "http");
        assert_eq!(TransportKind::Pkarr.to_string(), "pkarr");
        assert_eq!(TransportKind::Dht.to_string(), "dht");
        assert_eq!(TransportKind::Iroh.to_string(), "iroh");
    }
}
