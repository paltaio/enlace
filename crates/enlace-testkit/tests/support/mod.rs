use std::sync::Once;

pub fn reqwest_client() -> reqwest::Client {
    ensure_default_crypto_provider();
    reqwest::Client::new()
}

fn ensure_default_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
