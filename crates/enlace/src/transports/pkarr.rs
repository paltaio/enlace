use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pkarr::dns::ResourceRecord;
use pkarr::dns::rdata::{RData, TXT};
use pkarr::{Client, Keypair, PublicKey, SignedPacket, SignedPacketBuilder};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::config::PkarrConfig;
use crate::crypto::derive_key32;
use crate::error::TransportError;
use crate::transports::{MailboxTransport, SlotTransport, SlotWatchStream};

const DEFAULT_RECORD_TTL: u32 = 300;
const MAX_PUBLISH_ATTEMPTS: usize = 3;
const RECORD_PREFIX: &str = "enlace-slot-v1";
const WATCH_BUFFER: usize = 64;

#[derive(Clone)]
pub struct PkarrTransport {
    client: Client,
    keypair: Keypair,
    public_key: PublicKey,
    record_ttl: u32,
    poll_interval: Duration,
}

impl PkarrTransport {
    pub fn new(seed: &[u8; 32], config: &PkarrConfig) -> Result<Self, TransportError> {
        let mut builder = Client::builder();
        let relays = config.effective_resolvers();
        builder.no_default_network();
        builder.relays(&relays).map_err(map_other_error)?;
        let client = builder.build().map_err(map_other_error)?;
        let keypair = pkarr_keypair(seed);
        let public_key = keypair.public_key();
        let record_ttl = record_ttl(config.republish_interval);
        let poll_interval = poll_interval(config.republish_interval);
        Ok(Self {
            client,
            keypair,
            public_key,
            record_ttl,
            poll_interval,
        })
    }

    async fn resolve_packet_for(&self, public_key: &PublicKey) -> Option<SignedPacket> {
        self.client.resolve_most_recent(public_key).await
    }

    async fn slot_get_since(
        &self,
        id: PkarrSlotId,
        since: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let Some(packet) = self.resolve_packet_for(&id.public_key).await else {
            return Ok(None);
        };
        let Some((version, sealed)) = slot_record(&packet, &id.record)? else {
            return Ok(None);
        };
        if version <= since {
            return Ok(None);
        }
        Ok(Some((version, sealed)))
    }
}

impl fmt::Debug for PkarrTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkarrTransport")
            .field("public_key", &self.public_key)
            .field("record_ttl", &self.record_ttl)
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MailboxTransport for PkarrTransport {
    async fn send(&self, _id: &[u8], _sealed: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::Unsupported)
    }

    async fn recv(&self, _id: &[u8], _wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        Err(TransportError::Unsupported)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SlotTransport for PkarrTransport {
    async fn put(&self, id: &[u8], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        let id = self.pkarr_slot_id(id)?;
        // pkarr's client cache and individual relays can diverge: a stale
        // CAS timestamp on one relay surfaces as Concurrency even though our
        // version isn't really stale. Re-resolve and retry a few times before
        // giving up; a true stale version still fails after the loop.
        let mut last_err: Option<TransportError> = None;
        for _ in 0..MAX_PUBLISH_ATTEMPTS {
            let current = self.resolve_packet_for(&id.public_key).await;
            if current
                .as_ref()
                .and_then(|packet| slot_record(packet, &id.record).transpose())
                .transpose()?
                .is_some_and(|(current_version, _)| current_version >= version)
            {
                return Err(TransportError::Stale);
            }

            let packet = build_packet(
                &id.keypair,
                &id.public_key,
                current.as_ref(),
                &id.record,
                version,
                sealed,
                self.record_ttl,
            )?;
            let cas = current.as_ref().map(SignedPacket::timestamp);
            match self.client.publish(&packet, cas).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    let mapped = map_publish_error(err);
                    if !matches!(mapped, TransportError::Stale) {
                        return Err(mapped);
                    }
                    last_err = Some(mapped);
                }
            }
        }
        Err(last_err.unwrap_or(TransportError::Stale))
    }

    async fn get(&self, id: &[u8]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let id = self.pkarr_slot_id(id)?;
        self.slot_get_since(id, 0).await
    }

    fn watch(&self, id: &[u8], since: u64) -> SlotWatchStream {
        let Ok(id) = self.pkarr_slot_id(id) else {
            return Box::pin(tokio_stream::iter([Err(TransportError::Network(
                "pkarr channel id must be 16 or 32 bytes".to_owned(),
            ))]));
        };
        let transport = self.clone();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);

        crate::runtime::spawn(async move {
            let mut since = since;
            loop {
                match transport.slot_get_since(id.clone(), since).await {
                    Ok(Some((version, value))) => {
                        since = version;
                        if tx.send(Ok((version, value))).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if tx.send(Err(err)).await.is_err() {
                            break;
                        }
                    }
                }
                crate::runtime::sleep(transport.poll_interval).await;
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}

#[derive(Clone)]
struct PkarrSlotId {
    keypair: Keypair,
    public_key: PublicKey,
    record: [u8; 16],
}

impl PkarrTransport {
    fn pkarr_slot_id(&self, id: &[u8]) -> Result<PkarrSlotId, TransportError> {
        match id.len() {
            16 => {
                let record: [u8; 16] = id.try_into().map_err(|_| {
                    TransportError::Network("pkarr channel id must be 16 bytes".to_owned())
                })?;
                Ok(PkarrSlotId {
                    keypair: self.keypair.clone(),
                    public_key: self.public_key.clone(),
                    record,
                })
            }
            32 => {
                let seed: [u8; 32] = id.try_into().map_err(|_| {
                    TransportError::Network("pkarr address id must be 32 bytes".to_owned())
                })?;
                let keypair = pkarr_keypair(&seed);
                Ok(PkarrSlotId {
                    public_key: keypair.public_key(),
                    keypair,
                    record: [0; 16],
                })
            }
            _ => Err(TransportError::Network(
                "pkarr channel id must be 16 or 32 bytes".to_owned(),
            )),
        }
    }
}

fn build_packet(
    keypair: &Keypair,
    public_key: &PublicKey,
    current: Option<&SignedPacket>,
    id: &[u8; 16],
    version: u64,
    sealed: &[u8],
    ttl: u32,
) -> Result<SignedPacket, TransportError> {
    let name = record_name(id);
    let target = normalized_record_name(public_key, &name);
    let value = encode_slot_record(version, sealed);
    let mut preserved: Vec<_> = current
        .into_iter()
        .flat_map(SignedPacket::all_resource_records)
        .filter(|record| record.name.to_string() != target)
        .cloned()
        .collect();

    loop {
        match sign_packet(keypair, &preserved, &name, &value, ttl) {
            Ok(packet) => return Ok(packet),
            Err(TransportError::BodyTooLarge) if !preserved.is_empty() => {
                preserved.pop();
            }
            Err(err) => return Err(err),
        }
    }
}

fn sign_packet(
    keypair: &Keypair,
    preserved: &[ResourceRecord<'_>],
    name: &str,
    value: &str,
    ttl: u32,
) -> Result<SignedPacket, TransportError> {
    let mut builder = SignedPacketBuilder::default();
    for record in preserved {
        builder = builder.record(record.clone());
    }
    let name = name.try_into().map_err(map_other_error)?;
    let txt: TXT<'_> = value.try_into().map_err(map_other_error)?;
    builder
        .txt(name, txt, ttl)
        .sign(keypair)
        .map_err(map_build_error)
}

fn slot_record(
    packet: &SignedPacket,
    id: &[u8; 16],
) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
    let name = record_name(id);
    packet
        .resource_records(&name)
        .find_map(|record| match &record.rdata {
            RData::TXT(txt) => Some(decode_slot_record(txt)),
            _ => None,
        })
        .transpose()
}

fn decode_slot_record(txt_record: &TXT<'_>) -> Result<(u64, Vec<u8>), TransportError> {
    let encoded = String::try_from(txt_record.clone()).map_err(map_other_error)?;
    let mut parts = encoded.splitn(3, ':');
    let prefix = parts.next();
    let version = parts.next();
    let sealed = parts.next();
    let (Some(RECORD_PREFIX), Some(version), Some(sealed)) = (prefix, version, sealed) else {
        return Err(TransportError::Network(
            "malformed pkarr slot record".to_owned(),
        ));
    };
    let version = u64::from_str_radix(version, 16).map_err(map_other_error)?;
    let sealed = URL_SAFE_NO_PAD.decode(sealed).map_err(map_other_error)?;
    Ok((version, sealed))
}

fn encode_slot_record(version: u64, sealed: &[u8]) -> String {
    let mut value = String::with_capacity(RECORD_PREFIX.len() + 1 + 16 + 1 + sealed.len() * 4 / 3);
    value.push_str(RECORD_PREFIX);
    write!(&mut value, ":{version:016x}:").expect("writing to String cannot fail");
    value.push_str(&URL_SAFE_NO_PAD.encode(sealed));
    value
}

fn record_name(id: &[u8; 16]) -> String {
    let mut name = String::with_capacity(32);
    for byte in id {
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    name
}

fn normalized_record_name(public_key: &PublicKey, name: &str) -> String {
    let mut normalized = String::with_capacity(name.len() + 1 + public_key.to_z32().len());
    normalized.push_str(name);
    normalized.push('.');
    normalized.push_str(&public_key.to_z32());
    normalized
}

fn record_ttl(interval: Duration) -> u32 {
    match u32::try_from(interval.as_secs()) {
        Ok(0) => DEFAULT_RECORD_TTL,
        Ok(ttl) => ttl,
        Err(_) => u32::MAX,
    }
}

fn poll_interval(interval: Duration) -> Duration {
    if interval.is_zero() {
        Duration::from_secs(u64::from(DEFAULT_RECORD_TTL))
    } else {
        interval
    }
}

fn pkarr_keypair(seed: &[u8; 32]) -> Keypair {
    let key = derive_key32(seed, b"enlace/v1/key/pkarr-id");
    Keypair::from_secret_key(&key)
}

fn map_build_error(err: pkarr::errors::SignedPacketBuildError) -> TransportError {
    match err {
        pkarr::errors::SignedPacketBuildError::PacketTooLarge(_) => TransportError::BodyTooLarge,
        pkarr::errors::SignedPacketBuildError::FailedToWrite(err) => map_other_error(err),
    }
}

fn map_publish_error(err: pkarr::errors::PublishError) -> TransportError {
    match err {
        pkarr::errors::PublishError::Concurrency(_) => TransportError::Stale,
        pkarr::errors::PublishError::Query(pkarr::errors::QueryError::Timeout) => {
            TransportError::Timeout
        }
        err => map_other_error(err),
    }
}

fn map_other_error<E>(err: E) -> TransportError
where
    E: std::error::Error + Send + Sync + 'static,
{
    TransportError::Other(Box::new(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_name_is_lower_hex_channel_id() {
        assert_eq!(
            record_name(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]),
            "000102030405060708090a0b0c0d0e0f"
        );
    }

    #[test]
    fn slot_record_round_trips_version_and_value() {
        let encoded = encode_slot_record(42, b"sealed bytes");
        let txt: TXT<'_> = encoded.as_str().try_into().unwrap();
        let decoded = decode_slot_record(&txt).unwrap();
        assert_eq!(decoded, (42, b"sealed bytes".to_vec()));
    }

    #[test]
    fn packet_stores_slot_by_channel_id() {
        let keypair = pkarr_keypair(&[1; 32]);
        let public_key = keypair.public_key();
        let packet = build_packet(
            &keypair,
            &public_key,
            None,
            &[2; 16],
            7,
            b"sealed",
            DEFAULT_RECORD_TTL,
        )
        .unwrap();

        assert_eq!(
            slot_record(&packet, &[2; 16]).unwrap(),
            Some((7, b"sealed".to_vec()))
        );
        assert_eq!(slot_record(&packet, &[3; 16]).unwrap(), None);
    }

    #[test]
    fn slot_id_accepts_shared_seed_and_public_key_addresses() {
        let transport = PkarrTransport::new(&[1; 32], &PkarrConfig::default()).unwrap();

        let shared = transport.pkarr_slot_id(&[2; 16]).unwrap();
        let public = transport.pkarr_slot_id(&[3; 32]).unwrap();

        assert_eq!(shared.record, [2; 16]);
        assert_eq!(public.record, [0; 16]);
        assert_ne!(shared.public_key, public.public_key);
    }

    #[tokio::test]
    async fn mailbox_send_is_unsupported() {
        let transport = PkarrTransport::new(&[1; 32], &PkarrConfig::default()).unwrap();
        let err = transport.send(&[2; 16], b"sealed").await.unwrap_err();
        assert!(matches!(err, TransportError::Unsupported));
    }

    #[tokio::test]
    async fn mailbox_recv_is_unsupported() {
        let transport = PkarrTransport::new(&[1; 32], &PkarrConfig::default()).unwrap();
        let err = transport.recv(&[2; 16], Duration::ZERO).await.unwrap_err();
        assert!(matches!(err, TransportError::Unsupported));
    }

    #[test]
    fn publish_concurrency_errors_map_to_stale() {
        use pkarr::errors::{ConcurrencyError, PublishError};

        for variant in [
            ConcurrencyError::ConflictRisk,
            ConcurrencyError::NotMostRecent,
            ConcurrencyError::CasFailed,
        ] {
            assert!(matches!(
                map_publish_error(PublishError::Concurrency(variant)),
                TransportError::Stale,
            ));
        }
    }

    #[test]
    fn publish_query_timeout_maps_to_timeout_not_stale() {
        use pkarr::errors::{PublishError, QueryError};

        assert!(matches!(
            map_publish_error(PublishError::Query(QueryError::Timeout)),
            TransportError::Timeout,
        ));
    }

    #[test]
    fn publish_other_errors_do_not_map_to_stale() {
        use pkarr::errors::PublishError;

        let mapped = map_publish_error(PublishError::UnexpectedResponses);
        assert!(
            !matches!(mapped, TransportError::Stale),
            "unexpected-response errors must abort the retry loop, not retry: got {mapped:?}",
        );
    }
}
