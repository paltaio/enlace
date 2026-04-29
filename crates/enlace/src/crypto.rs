//! AEAD seal/unseal, ed25519 sign/verify, HKDF subkey expansion,
//! and constant-time slice comparison.
//!
//! Channel-id and per-channel-key derivation that uses these primitives
//! lives in `kdf.rs`.

use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, OsRng, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const AEAD_KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

/// 32-byte AEAD key wrapped so it's wiped on drop.
pub type AeadKeyBytes = Zeroizing<[u8; AEAD_KEY_LEN]>;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Sealed payload shorter than nonce + tag.
    TooShort,
    /// Authentication failed: wrong key, wrong AAD, or tampered ciphertext.
    AeadFailed,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::TooShort => f.write_str("sealed payload too short"),
            CryptoError::AeadFailed => f.write_str("AEAD authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// HKDF-SHA256 expand. Empty `salt` is normalized to "no salt".
///
/// Panics only if `out.len() > 255 * 32` (HKDF-SHA256 hard cap); all callers
/// in this crate request ≤ 32 bytes.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, out)
        .expect("HKDF output length within SHA-256 limits");
}

/// Derive a 32-byte key from `ikm` + `info` (empty salt). Returned buffer is zeroized on drop.
pub fn derive_key32(ikm: &[u8], info: &[u8]) -> AeadKeyBytes {
    let mut out = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hkdf_sha256(ikm, b"", info, out.as_mut_slice());
    out
}

/// XChaCha20-Poly1305 seal. Output: `[24-byte nonce || ciphertext || 16-byte tag]`.
pub fn seal(key: &[u8; AEAD_KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encrypt is infallible for inputs we feed it");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    out
}

/// XChaCha20-Poly1305 open. Input: `[24-byte nonce || ciphertext || 16-byte tag]`.
pub fn unseal(key: &[u8; AEAD_KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::TooShort);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailed)
}

/// ed25519 sign.
pub fn sign(sk: &SigningKey, message: &[u8]) -> [u8; SIG_LEN] {
    sk.sign(message).to_bytes()
}

/// ed25519 verify. `false` on any failure (bad signature, wrong key, malformed bytes).
pub fn verify(vk: &VerifyingKey, message: &[u8], signature: &[u8; SIG_LEN]) -> bool {
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

/// Constant-time byte-slice equality. `false` on length mismatch (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn aead_round_trip() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let aad = b"enlace/v1/aead/mailbox/test";
        let plaintext = b"hello world";
        let sealed = seal(&key, aad, plaintext);
        assert!(sealed.len() >= NONCE_LEN + TAG_LEN);
        let opened = unseal(&key, aad, &sealed).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aead_round_trip_empty_plaintext() {
        let key = [0u8; AEAD_KEY_LEN];
        let sealed = seal(&key, b"", b"");
        let opened = unseal(&key, b"", &sealed).unwrap();
        assert_eq!(opened, b"");
    }

    #[test]
    fn aead_wrong_key_fails() {
        let k1 = [1u8; AEAD_KEY_LEN];
        let k2 = [2u8; AEAD_KEY_LEN];
        let sealed = seal(&k1, b"aad", b"msg");
        assert_eq!(unseal(&k2, b"aad", &sealed), Err(CryptoError::AeadFailed));
    }

    #[test]
    fn aead_wrong_aad_fails() {
        let k = [3u8; AEAD_KEY_LEN];
        let sealed = seal(&k, b"a", b"msg");
        assert_eq!(unseal(&k, b"b", &sealed), Err(CryptoError::AeadFailed));
    }

    #[test]
    fn aead_tampered_ciphertext_fails() {
        let k = [4u8; AEAD_KEY_LEN];
        let mut sealed = seal(&k, b"", b"hello");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(unseal(&k, b"", &sealed), Err(CryptoError::AeadFailed));
    }

    #[test]
    fn aead_too_short_input() {
        let k = [5u8; AEAD_KEY_LEN];
        for len in 0..NONCE_LEN + TAG_LEN {
            let buf = vec![0u8; len];
            assert_eq!(
                unseal(&k, b"", &buf),
                Err(CryptoError::TooShort),
                "len={len} should error TooShort"
            );
        }
    }

    #[test]
    fn aead_nonce_unique_across_calls() {
        let k = [6u8; AEAD_KEY_LEN];
        let s1 = seal(&k, b"", b"x");
        let s2 = seal(&k, b"", b"x");
        assert_ne!(&s1[..NONCE_LEN], &s2[..NONCE_LEN]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn hkdf_deterministic() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha256(b"ikm", b"salt", b"info", &mut a);
        hkdf_sha256(b"ikm", b"salt", b"info", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_different_info_diverges() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha256(b"ikm", b"", b"info-a", &mut a);
        hkdf_sha256(b"ikm", b"", b"info-b", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_different_ikm_diverges() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha256(b"ikm-a", b"", b"info", &mut a);
        hkdf_sha256(b"ikm-b", b"", b"info", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_short_and_long_outputs() {
        let mut short = [0u8; 8];
        let mut long = [0u8; 64];
        hkdf_sha256(b"ikm", b"", b"info", &mut short);
        hkdf_sha256(b"ikm", b"", b"info", &mut long);
        // First 8 bytes of `long` must equal `short` (HKDF-Expand is a stream).
        assert_eq!(&long[..8], &short);
    }

    #[test]
    fn derive_key32_returns_zeroizing_buffer() {
        let k = derive_key32(b"seed-material", b"enlace/v1/key/aead/mailbox/foo");
        assert_eq!(k.as_ref().len(), AEAD_KEY_LEN);
        // Same input ⇒ same output.
        let k2 = derive_key32(b"seed-material", b"enlace/v1/key/aead/mailbox/foo");
        assert_eq!(k.as_ref(), k2.as_ref());
        // Different info ⇒ different output.
        let k3 = derive_key32(b"seed-material", b"enlace/v1/key/aead/mailbox/bar");
        assert_ne!(k.as_ref(), k3.as_ref());
    }

    #[test]
    fn ed25519_round_trip() {
        let sk = SigningKey::from_bytes(&[0xAAu8; 32]);
        let vk = sk.verifying_key();
        let msg = b"message under test";
        let sig = sign(&sk, msg);
        assert!(verify(&vk, msg, &sig));
    }

    #[test]
    fn ed25519_signature_bit_flip_rejected() {
        let sk = SigningKey::from_bytes(&[0xBBu8; 32]);
        let vk = sk.verifying_key();
        let mut sig = sign(&sk, b"data");
        sig[0] ^= 0x01;
        assert!(!verify(&vk, b"data", &sig));
    }

    #[test]
    fn ed25519_message_tamper_rejected() {
        let sk = SigningKey::from_bytes(&[0xCCu8; 32]);
        let vk = sk.verifying_key();
        let sig = sign(&sk, b"original");
        assert!(!verify(&vk, b"tampered", &sig));
    }

    #[test]
    fn ed25519_wrong_key_rejected() {
        let sk1 = SigningKey::from_bytes(&[0xDDu8; 32]);
        let sk2 = SigningKey::from_bytes(&[0xEEu8; 32]);
        let sig = sign(&sk1, b"msg");
        assert!(!verify(&sk2.verifying_key(), b"msg", &sig));
    }

    #[test]
    fn ct_eq_equal_lengths() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
    }

    #[test]
    fn ct_eq_unequal_lengths() {
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn ct_eq_empty() {
        assert!(ct_eq(b"", b""));
    }

    proptest! {
        #[test]
        fn aead_round_trip_for_arbitrary_payloads(
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
            aad in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let key = [0x42u8; AEAD_KEY_LEN];
            let sealed = seal(&key, &aad, &payload);
            let opened = unseal(&key, &aad, &sealed).expect("sealed payload should reopen");
            prop_assert_eq!(opened, payload);
        }

        #[test]
        fn ed25519_round_trip_for_arbitrary_messages(
            message in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let sk = SigningKey::from_bytes(&[0xABu8; 32]);
            let vk = sk.verifying_key();
            let sig = sign(&sk, &message);
            prop_assert!(verify(&vk, &message, &sig));
        }
    }
}
