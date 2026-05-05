//! Crypto provider bootstrap for the rustls global default.
//!
//! reqwest 0.13's `rustls-no-provider` feature builds a TLS-capable client
//! without baking aws-lc-rs into the binary, but at the cost of requiring the
//! application to install a [`rustls::crypto::CryptoProvider`] before the
//! first HTTPS handshake — otherwise reqwest panics with `No provider set`.
//! We install `ring` here so the rest of the crate can construct reqwest
//! clients without each call site re-doing the dance.

use std::sync::Once;

/// Install `ring` as the process-wide rustls default if no provider has been
/// installed yet. Idempotent: safe to call from every transport constructor.
/// A no-op on wasm, where TLS is the browser's job and rustls isn't compiled
/// in.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn ensure_default_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Ignore the error: install_default fails only if a different
        // provider was already installed — embedders are free to pick their
        // own (e.g. aws-lc-rs) before constructing an enlace transport, and
        // we shouldn't override that.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn ensure_default_crypto_provider() {}
