use std::sync::Arc;

use crate::coordinator::Coordinator;
use crate::crypto;
use crate::kdf::{ChannelKind, channel_aead_key};
use crate::state::InMemoryStateStore;

const SEED: [u8; 32] = [0xA5; 32];
const NAME: &str = "fuzz";
const MAX_PLAINTEXT_BYTES: usize = 65_536;

pub fn open_mailbox(data: &[u8]) {
    let coordinator = Coordinator::new(
        &SEED,
        Vec::new(),
        None,
        Vec::new(),
        0,
        MAX_PLAINTEXT_BYTES,
        Arc::new(InMemoryStateStore::default()),
    );
    let Some((&mode, bytes)) = data.split_first() else {
        coordinator.open_for_fuzz(ChannelKind::Mailbox, NAME, data);
        return;
    };

    if mode & 1 == 0 {
        coordinator.open_for_fuzz(ChannelKind::Mailbox, NAME, bytes);
        return;
    }

    let Ok(key) = channel_aead_key(&SEED, ChannelKind::Mailbox, NAME) else {
        return;
    };
    let sealed = crypto::seal(&key, &mailbox_aad(), bytes);
    coordinator.open_for_fuzz(ChannelKind::Mailbox, NAME, &sealed);
}

fn mailbox_aad() -> Vec<u8> {
    let mut aad = Vec::with_capacity(b"enlace/v1/aead/mailbox/".len() + NAME.len());
    aad.extend_from_slice(b"enlace/v1/aead/mailbox/");
    aad.extend_from_slice(NAME.as_bytes());
    aad
}
