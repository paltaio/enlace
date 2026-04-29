//! Channel addressing.
//!
//! From a 32-byte seed plus a channel kind (mailbox or slot) and a channel name,
//! derives:
//!
//! - a 32-byte AEAD subkey (per kind, per name) — used by `crypto::seal/unseal`
//! - a 16-byte transport-level channel id (per transport, per kind, per name)
//!
//! The HKDF info-string prefixes used for these two derivations
//! (`enlace/v1/key/aead/...` and `enlace/v1/id/...`) are deliberately disjoint
//! so the AEAD subkey for a channel can never collide with the transport-level
//! id of any channel: domain separation is enforced at the HKDF info layer,
//! not by trimming output bits.
//!
//! Names are restricted to a narrow ASCII subset so that two endpoints that
//! pass byte-equal names derive byte-equal keys/ids without any Unicode
//! normalization step.

use crate::crypto::{AeadKeyBytes, derive_key32, hkdf_sha256};

/// Channel id length in bytes.
pub const CHANNEL_ID_LEN: usize = 16;

/// Channel name length cap in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// Distinguishes mailbox channels from slot channels in the HKDF context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    Mailbox,
    Slot,
}

impl ChannelKind {
    #[inline]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            ChannelKind::Mailbox => b"mailbox",
            ChannelKind::Slot => b"slot",
        }
    }
}

/// One of the four transport adapters.
///
/// Used both as the discriminator in the channel-id HKDF context (so the same
/// channel name on the same seed yields a distinct 16-byte id per transport)
/// and as the runtime identifier surfaced on received messages and errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Http,
    Pkarr,
    Dht,
    Iroh,
}

impl TransportKind {
    #[inline]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            TransportKind::Http => b"http",
            TransportKind::Pkarr => b"pkarr",
            TransportKind::Dht => b"dht",
            TransportKind::Iroh => b"iroh",
        }
    }

    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            TransportKind::Http => "http",
            TransportKind::Pkarr => "pkarr",
            TransportKind::Dht => "dht",
            TransportKind::Iroh => "iroh",
        }
    }
}

impl core::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong,
    InvalidChar,
}

impl core::fmt::Display for NameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NameError::Empty => f.write_str("channel name is empty"),
            NameError::TooLong => f.write_str("channel name exceeds 64 bytes"),
            NameError::InvalidChar => {
                f.write_str("channel name contains a byte outside [0-9 a-z - _ / .]")
            }
        }
    }
}

impl std::error::Error for NameError {}

/// Validate a channel name against the allowed charset and length rules.
///
/// Allowed bytes: `0-9`, `a-z`, `-`, `_`, `/`, `.`. Length must be 1..=64.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    for &b in name.as_bytes() {
        let ok = matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'-' | b'_' | b'/' | b'.');
        if !ok {
            return Err(NameError::InvalidChar);
        }
    }
    Ok(())
}

/// Derive the per-channel AEAD key.
///
/// `info = b"enlace/v1/key/aead/" || kind || b"/" || name`
///
/// Returned buffer is wrapped in `Zeroizing` and wiped on drop.
pub fn channel_aead_key(
    seed: &[u8; 32],
    kind: ChannelKind,
    name: &str,
) -> Result<AeadKeyBytes, NameError> {
    validate_name(name)?;
    let kind_bytes = kind.as_bytes();
    let name_bytes = name.as_bytes();
    let mut info =
        Vec::with_capacity(b"enlace/v1/key/aead/".len() + kind_bytes.len() + 1 + name_bytes.len());
    info.extend_from_slice(b"enlace/v1/key/aead/");
    info.extend_from_slice(kind_bytes);
    info.push(b'/');
    info.extend_from_slice(name_bytes);
    Ok(derive_key32(seed, &info))
}

/// Derive the per-transport channel id.
///
/// `info = b"enlace/v1/id/" || transport || b"/" || kind || b"/" || name`
///
/// HKDF output is truncated to `CHANNEL_ID_LEN` (16 bytes).
pub fn channel_id(
    seed: &[u8; 32],
    transport: TransportKind,
    kind: ChannelKind,
    name: &str,
) -> Result<[u8; CHANNEL_ID_LEN], NameError> {
    validate_name(name)?;
    let transport_bytes = transport.as_bytes();
    let kind_bytes = kind.as_bytes();
    let name_bytes = name.as_bytes();
    let mut info = Vec::with_capacity(
        b"enlace/v1/id/".len()
            + transport_bytes.len()
            + 1
            + kind_bytes.len()
            + 1
            + name_bytes.len(),
    );
    info.extend_from_slice(b"enlace/v1/id/");
    info.extend_from_slice(transport_bytes);
    info.push(b'/');
    info.extend_from_slice(kind_bytes);
    info.push(b'/');
    info.extend_from_slice(name_bytes);
    let mut out = [0u8; CHANNEL_ID_LEN];
    hkdf_sha256(seed, b"", &info, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; 32] = [0xA1u8; 32];
    const SEED_B: [u8; 32] = [0xB2u8; 32];

    // -- name validation -----------------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_name(""), Err(NameError::Empty));
    }

    #[test]
    fn name_max_length_accepted() {
        let n = "a".repeat(MAX_NAME_LEN);
        assert!(validate_name(&n).is_ok());
    }

    #[test]
    fn name_over_max_rejected() {
        let n = "a".repeat(MAX_NAME_LEN + 1);
        assert_eq!(validate_name(&n), Err(NameError::TooLong));
    }

    #[test]
    fn name_full_charset_accepted() {
        let all_ok = "abcdefghijklmnopqrstuvwxyz0123456789-_./";
        assert!(validate_name(all_ok).is_ok());
    }

    #[test]
    fn name_uppercase_rejected() {
        assert_eq!(validate_name("Foo"), Err(NameError::InvalidChar));
        assert_eq!(validate_name("FOO"), Err(NameError::InvalidChar));
    }

    #[test]
    fn name_space_rejected() {
        assert_eq!(validate_name("a b"), Err(NameError::InvalidChar));
    }

    #[test]
    fn name_special_ascii_bytes_rejected() {
        // Bytes inside printable ASCII that are NOT in the allowed set.
        for bad in [b':', b'+', b'=', b'@', b'#', b'%', b'*', b'~', b' ', b'\t'] {
            let raw = [b'a', bad, b'b'];
            let s = std::str::from_utf8(&raw).expect("ASCII test bytes are valid UTF-8");
            assert_eq!(
                validate_name(s),
                Err(NameError::InvalidChar),
                "byte 0x{bad:02X} should be rejected"
            );
        }
    }

    #[test]
    fn name_uppercase_full_alphabet_rejected() {
        for c in b'A'..=b'Z' {
            let raw = [c];
            let s = std::str::from_utf8(&raw).unwrap();
            assert_eq!(
                validate_name(s),
                Err(NameError::InvalidChar),
                "uppercase {s} should be rejected"
            );
        }
    }

    #[test]
    fn name_single_byte_accepted() {
        assert!(validate_name("a").is_ok());
        assert!(validate_name("0").is_ok());
        assert!(validate_name("-").is_ok());
        assert!(validate_name("/").is_ok());
        assert!(validate_name(".").is_ok());
        assert!(validate_name("_").is_ok());
    }

    // -- channel AEAD key ----------------------------------------------------

    #[test]
    fn aead_key_deterministic() {
        let k1 = channel_aead_key(&SEED_A, ChannelKind::Mailbox, "alpha").unwrap();
        let k2 = channel_aead_key(&SEED_A, ChannelKind::Mailbox, "alpha").unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());
        assert_eq!(k1.as_ref().len(), crate::crypto::AEAD_KEY_LEN);
    }

    #[test]
    fn aead_key_diverges_by_kind() {
        let mailbox = channel_aead_key(&SEED_A, ChannelKind::Mailbox, "alpha").unwrap();
        let slot = channel_aead_key(&SEED_A, ChannelKind::Slot, "alpha").unwrap();
        assert_ne!(mailbox.as_ref(), slot.as_ref());
    }

    #[test]
    fn aead_key_diverges_by_name() {
        let a = channel_aead_key(&SEED_A, ChannelKind::Mailbox, "alpha").unwrap();
        let b = channel_aead_key(&SEED_A, ChannelKind::Mailbox, "beta").unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn aead_key_diverges_by_seed() {
        let a = channel_aead_key(&SEED_A, ChannelKind::Mailbox, "alpha").unwrap();
        let b = channel_aead_key(&SEED_B, ChannelKind::Mailbox, "alpha").unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn aead_key_rejects_invalid_name() {
        assert_eq!(
            channel_aead_key(&SEED_A, ChannelKind::Mailbox, "").err(),
            Some(NameError::Empty)
        );
        assert_eq!(
            channel_aead_key(&SEED_A, ChannelKind::Slot, "Bad").err(),
            Some(NameError::InvalidChar)
        );
    }

    // -- channel id ----------------------------------------------------------

    #[test]
    fn channel_id_deterministic_and_sized() {
        let id1 = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        let id2 = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), CHANNEL_ID_LEN);
    }

    #[test]
    fn channel_id_diverges_by_transport() {
        let http = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        let pkarr =
            channel_id(&SEED_A, TransportKind::Pkarr, ChannelKind::Mailbox, "alpha").unwrap();
        let dht = channel_id(&SEED_A, TransportKind::Dht, ChannelKind::Mailbox, "alpha").unwrap();
        let iroh = channel_id(&SEED_A, TransportKind::Iroh, ChannelKind::Mailbox, "alpha").unwrap();
        // All four must be pairwise distinct.
        let all = [http, pkarr, dht, iroh];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "transports {i} and {j} produced equal ids");
            }
        }
    }

    #[test]
    fn channel_id_diverges_by_kind() {
        let mailbox =
            channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        let slot = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Slot, "alpha").unwrap();
        assert_ne!(mailbox, slot);
    }

    #[test]
    fn channel_id_diverges_by_name() {
        let a = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        let b = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "beta").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn channel_id_diverges_by_seed() {
        let a = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        let b = channel_id(&SEED_B, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn channel_id_rejects_invalid_name() {
        assert_eq!(
            channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "").err(),
            Some(NameError::Empty)
        );
        let too_long = "a".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            channel_id(
                &SEED_A,
                TransportKind::Http,
                ChannelKind::Mailbox,
                &too_long
            )
            .err(),
            Some(NameError::TooLong)
        );
    }

    // -- cross-domain separation -------------------------------------------

    #[test]
    fn aead_key_and_channel_id_share_no_prefix() {
        // The AEAD key context (`enlace/v1/key/aead/...`) and the id context
        // (`enlace/v1/id/...`) are disjoint by construction; a sanity check
        // that they don't collide on their first 16 bytes either.
        let key = channel_aead_key(&SEED_A, ChannelKind::Mailbox, "alpha").unwrap();
        let id = channel_id(&SEED_A, TransportKind::Http, ChannelKind::Mailbox, "alpha").unwrap();
        assert_ne!(&key.as_ref()[..CHANNEL_ID_LEN], &id[..]);
    }
}
