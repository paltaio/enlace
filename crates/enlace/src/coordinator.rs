use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio_stream::StreamExt;
use zeroize::Zeroizing;

use crate::crypto::{self, SIG_LEN};
use crate::dedup::Dedup;
use crate::error::{RecvError, SealError, SendError, SlotError};
use crate::kdf::{
    ChannelKind, NameError, TransportKind, channel_aead_key, channel_id, iroh_topic_id,
};
use crate::mailbox::{RecvMessage, SendReport};
use crate::slot::{PutReport, SlotValue, SlotWatch};
use crate::state::StateStore;
use crate::transports::Transport;

const WATCH_BUFFER: usize = 64;

#[derive(Clone)]
pub(crate) struct TransportEndpoint {
    pub(crate) kind: TransportKind,
    pub(crate) transport: Arc<dyn Transport>,
}

pub(crate) struct Coordinator {
    seed: Zeroizing<[u8; 32]>,
    transports: Vec<TransportEndpoint>,
    signing: Option<SigningKey>,
    trusted: Vec<VerifyingKey>,
    dedup_buffer: usize,
    max_plaintext_bytes: usize,
    state: Arc<dyn StateStore>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedInner {
    payload: Vec<u8>,
    version: Option<u64>,
    signer: Option<[u8; 32]>,
    signature: Option<Vec<u8>>,
}

struct OpenedEnvelope {
    payload: Vec<u8>,
    version: Option<u64>,
    signed_by: Option<VerifyingKey>,
}

impl Coordinator {
    pub(crate) fn new(
        seed: &[u8; 32],
        transports: Vec<TransportEndpoint>,
        signing: Option<SigningKey>,
        trusted: Vec<VerifyingKey>,
        dedup_buffer: usize,
        max_plaintext_bytes: usize,
        state: Arc<dyn StateStore>,
    ) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
            transports,
            signing,
            trusted,
            dedup_buffer,
            max_plaintext_bytes,
            state,
        }
    }

    pub(crate) fn dedup_buffer(&self) -> usize {
        self.dedup_buffer
    }

    pub(crate) async fn mailbox_send(
        &self,
        name: &str,
        payload: &[u8],
    ) -> Result<SendReport, SendError> {
        let sealed = self.seal(ChannelKind::Mailbox, name, payload, None)?;
        let mut tasks = JoinSet::new();

        for endpoint in &self.transports {
            let transport = Arc::clone(&endpoint.transport);
            let id = transport_channel_id(&self.seed, endpoint.kind, ChannelKind::Mailbox, name)
                .map_err(|_| SealError::MsgpackFailed)?;
            let sealed = sealed.clone();
            let kind = endpoint.kind;
            tasks.spawn(async move { (kind, transport.send(&id, &sealed).await) });
        }

        let mut delivered = Vec::new();
        let mut failed = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok((kind, send_result)) = result {
                match send_result {
                    Ok(()) => delivered.push(kind),
                    Err(err) => failed.push((kind, err)),
                }
            }
        }

        if delivered.is_empty() {
            return Err(SendError::AllTransportsFailed(failed));
        }
        Ok(SendReport { delivered, failed })
    }

    pub(crate) async fn mailbox_recv(
        &self,
        name: &str,
        wait: Duration,
        dedup: &std::sync::Mutex<Dedup>,
    ) -> Result<RecvMessage, RecvError> {
        loop {
            let mut tasks = JoinSet::new();
            for endpoint in &self.transports {
                let transport = Arc::clone(&endpoint.transport);
                let id =
                    transport_channel_id(&self.seed, endpoint.kind, ChannelKind::Mailbox, name)
                        .map_err(|_| RecvError::Closed)?;
                let kind = endpoint.kind;
                tasks.spawn(async move { (kind, transport.recv(&id, wait).await) });
            }

            let mut received_transport_response = false;
            while let Some(result) = tasks.join_next().await {
                let Ok(recv_result) = result else {
                    continue;
                };
                match recv_result {
                    (kind, Ok(Some(sealed))) => {
                        received_transport_response = true;
                        if dedup
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .observe(&sealed)
                        {
                            continue;
                        }
                        let Ok(opened) = self.open(ChannelKind::Mailbox, name, &sealed) else {
                            continue;
                        };
                        if opened.version.is_some() {
                            continue;
                        }
                        return Ok(RecvMessage {
                            payload: opened.payload,
                            via: kind,
                            signed_by: opened.signed_by,
                        });
                    }
                    (_, Ok(None)) => {
                        received_transport_response = true;
                    }
                    (_, Err(_)) => {}
                }
            }

            if wait.is_zero() {
                return Err(RecvError::Closed);
            }
            if !received_transport_response {
                tokio::time::sleep(wait).await;
            }
        }
    }

    pub(crate) async fn slot_put(
        &self,
        name: &str,
        payload: &[u8],
    ) -> Result<PutReport, SlotError> {
        let version = self.state.next_local_slot_version(name)?;
        let sealed = self.seal(ChannelKind::Slot, name, payload, Some(version))?;
        let mut tasks = JoinSet::new();

        for endpoint in &self.transports {
            let transport = Arc::clone(&endpoint.transport);
            let id = transport_channel_id(&self.seed, endpoint.kind, ChannelKind::Slot, name)
                .map_err(|_| SealError::MsgpackFailed)?;
            let sealed = sealed.clone();
            let kind = endpoint.kind;
            tasks.spawn(async move { (kind, transport.put(&id, version, &sealed).await) });
        }

        let mut stored = Vec::new();
        let mut failed = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok((kind, put_result)) = result {
                match put_result {
                    Ok(()) => stored.push(kind),
                    Err(err) => failed.push((kind, err)),
                }
            }
        }

        if stored.is_empty() {
            return Err(SlotError::AllTransportsFailed(failed));
        }
        Ok(PutReport {
            version,
            stored,
            failed,
        })
    }

    pub(crate) async fn slot_get(&self, name: &str) -> Result<Option<SlotValue>, SlotError> {
        let mut tasks = JoinSet::new();
        for endpoint in &self.transports {
            let transport = Arc::clone(&endpoint.transport);
            let id = transport_channel_id(&self.seed, endpoint.kind, ChannelKind::Slot, name)
                .map_err(|_| SealError::MsgpackFailed)?;
            let kind = endpoint.kind;
            tasks.spawn(async move { (kind, transport.get(&id).await) });
        }

        let mut ok_count = 0usize;
        let mut failures = Vec::new();
        let mut best: Option<(u64, Vec<u8>, SlotValue)> = None;

        while let Some(result) = tasks.join_next().await {
            let Ok(get_result) = result else {
                continue;
            };
            match get_result {
                (_, Ok(None)) => ok_count += 1,
                (kind, Ok(Some((_server_version, sealed)))) => {
                    ok_count += 1;
                    let Ok(opened) = self.open(ChannelKind::Slot, name, &sealed) else {
                        continue;
                    };
                    let Some(version) = opened.version else {
                        continue;
                    };
                    let value = SlotValue {
                        version,
                        payload: opened.payload,
                        via: kind,
                        signed_by: opened.signed_by,
                    };
                    if best.as_ref().is_none_or(|(best_version, best_sealed, _)| {
                        slot_pair_is_newer(version, &sealed, *best_version, best_sealed)
                    }) {
                        best = Some((version, sealed, value));
                    }
                }
                (kind, Err(err)) => failures.push((kind, err)),
            }
        }

        if ok_count == 0 && !failures.is_empty() {
            return Err(SlotError::AllTransportsFailed(failures));
        }
        Ok(best.map(|(_, _, value)| value))
    }

    pub(crate) fn slot_watch(self: &Arc<Self>, name: String) -> SlotWatch {
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);
        let best = Arc::new(Mutex::new(None::<(u64, Vec<u8>)>));
        let dedup = Arc::new(Mutex::new(Dedup::new(self.dedup_buffer)));

        for endpoint in &self.transports {
            let Ok(id) = transport_channel_id(&self.seed, endpoint.kind, ChannelKind::Slot, &name)
            else {
                continue;
            };
            let mut stream = endpoint.transport.watch(&id, 0);
            let coordinator = Arc::clone(self);
            let best = Arc::clone(&best);
            let dedup = Arc::clone(&dedup);
            let tx = tx.clone();
            let name = name.clone();
            let kind = endpoint.kind;

            tokio::spawn(async move {
                while let Some(item) = stream.next().await {
                    let Ok((_server_version, sealed)) = item else {
                        continue;
                    };
                    if dedup.lock().await.observe(&sealed) {
                        continue;
                    }
                    let Ok(opened) = coordinator.open(ChannelKind::Slot, &name, &sealed) else {
                        continue;
                    };
                    let Some(version) = opened.version else {
                        continue;
                    };

                    let mut best = best.lock().await;
                    if best.as_ref().is_some_and(|(best_version, best_sealed)| {
                        !slot_pair_is_newer(version, &sealed, *best_version, best_sealed)
                    }) {
                        continue;
                    }
                    *best = Some((version, sealed.clone()));
                    drop(best);

                    let _ = coordinator.state.record_seen_slot_version(&name, version);
                    if tx
                        .send(SlotValue {
                            version,
                            payload: opened.payload,
                            via: kind,
                            signed_by: opened.signed_by,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }

        SlotWatch::new(name, rx)
    }

    fn seal(
        &self,
        kind: ChannelKind,
        name: &str,
        payload: &[u8],
        version: Option<u64>,
    ) -> Result<Vec<u8>, SealError> {
        let preimage = signature_preimage(kind, name, payload, version);
        let (signer, signature) = self.signing.as_ref().map_or((None, None), |sk| {
            (
                Some(sk.verifying_key().to_bytes()),
                Some(crypto::sign(sk, &preimage).to_vec()),
            )
        });
        let inner = SignedInner {
            payload: payload.to_vec(),
            version,
            signer,
            signature,
        };
        let plaintext = rmp_serde::to_vec_named(&inner).map_err(|_| SealError::MsgpackFailed)?;
        let key = channel_aead_key(&self.seed, kind, name).map_err(|_| SealError::MsgpackFailed)?;
        let aad = aead_aad(kind, name);
        Ok(crypto::seal(&key, &aad, &plaintext))
    }

    fn open(
        &self,
        kind: ChannelKind,
        name: &str,
        sealed: &[u8],
    ) -> Result<OpenedEnvelope, SealError> {
        let key = channel_aead_key(&self.seed, kind, name).map_err(|_| SealError::MsgpackFailed)?;
        let aad = aead_aad(kind, name);
        let plaintext = crypto::unseal(&key, &aad, sealed)?;
        if plaintext.len() > self.max_plaintext_bytes {
            return Err(SealError::MsgpackFailed);
        }

        let inner: SignedInner =
            rmp_serde::from_slice(&plaintext).map_err(|_| SealError::MsgpackFailed)?;
        let signed_by = verify_inner(kind, name, &inner, &self.trusted)?;

        Ok(OpenedEnvelope {
            payload: inner.payload,
            version: inner.version,
            signed_by,
        })
    }

    #[cfg(feature = "fuzzing")]
    pub(crate) fn open_for_fuzz(&self, kind: ChannelKind, name: &str, sealed: &[u8]) {
        let _ = self.open(kind, name, sealed);
    }
}

fn verify_inner(
    kind: ChannelKind,
    name: &str,
    inner: &SignedInner,
    trusted: &[VerifyingKey],
) -> Result<Option<VerifyingKey>, SealError> {
    match (&inner.signer, &inner.signature) {
        (None, None) if trusted.is_empty() => Ok(None),
        (None, None) => Err(SealError::SignatureMissing),
        (Some(_), None) | (None, Some(_)) => Err(SealError::MsgpackFailed),
        (Some(signer), Some(signature)) => {
            let signer =
                VerifyingKey::from_bytes(signer).map_err(|_| SealError::SignatureInvalid)?;
            let signature: [u8; SIG_LEN] = signature
                .as_slice()
                .try_into()
                .map_err(|_| SealError::SignatureInvalid)?;
            let preimage = signature_preimage(kind, name, &inner.payload, inner.version);
            if !crypto::verify(&signer, &preimage, &signature) {
                return Err(SealError::SignatureInvalid);
            }
            if !trusted.is_empty()
                && !trusted
                    .iter()
                    .any(|trusted_key| trusted_key.to_bytes() == signer.to_bytes())
            {
                return Err(SealError::UntrustedSigner);
            }
            Ok(Some(signer))
        }
    }
}

fn aead_aad(kind: ChannelKind, name: &str) -> Vec<u8> {
    let kind = kind.as_bytes();
    let name = name.as_bytes();
    let mut aad = Vec::with_capacity(b"enlace/v1/aead/".len() + kind.len() + 1 + name.len());
    aad.extend_from_slice(b"enlace/v1/aead/");
    aad.extend_from_slice(kind);
    aad.push(b'/');
    aad.extend_from_slice(name);
    aad
}

fn signature_preimage(
    kind: ChannelKind,
    name: &str,
    payload: &[u8],
    version: Option<u64>,
) -> Vec<u8> {
    let kind = kind.as_bytes();
    let name = name.as_bytes();
    let extra = version.map_or(0, |_| 8);
    let mut preimage = Vec::with_capacity(
        b"enlace/v1/sig/".len() + kind.len() + 1 + name.len() + 1 + extra + payload.len(),
    );
    preimage.extend_from_slice(b"enlace/v1/sig/");
    preimage.extend_from_slice(kind);
    preimage.push(b'/');
    preimage.extend_from_slice(name);
    preimage.push(b'/');
    if let Some(version) = version {
        preimage.extend_from_slice(&version.to_be_bytes());
    }
    preimage.extend_from_slice(payload);
    preimage
}

fn slot_pair_is_newer(version: u64, sealed: &[u8], best_version: u64, best_sealed: &[u8]) -> bool {
    (version, sealed) > (best_version, best_sealed)
}

fn transport_channel_id(
    seed: &[u8; 32],
    transport: TransportKind,
    kind: ChannelKind,
    name: &str,
) -> Result<Vec<u8>, NameError> {
    if transport == TransportKind::Iroh {
        iroh_topic_id(seed, kind, name).map(Vec::from)
    } else {
        channel_id(seed, transport, kind, name).map(Vec::from)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn slot_ordering_matches_version_then_sealed_lexicographic(
            version in any::<u64>(),
            best_version in any::<u64>(),
            sealed in proptest::collection::vec(any::<u8>(), 0..128),
            best_sealed in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            prop_assert_eq!(
                slot_pair_is_newer(version, &sealed, best_version, &best_sealed),
                (version, sealed.as_slice()) > (best_version, best_sealed.as_slice()),
            );
        }

        #[test]
        fn signature_preimage_is_deterministic(
            name in "[a-z0-9_./-]{1,64}",
            payload in proptest::collection::vec(any::<u8>(), 0..512),
            version in proptest::option::of(any::<u64>()),
        ) {
            let a = signature_preimage(ChannelKind::Slot, &name, &payload, version);
            let b = signature_preimage(ChannelKind::Slot, &name, &payload, version);
            prop_assert_eq!(a, b);
        }
    }
}
