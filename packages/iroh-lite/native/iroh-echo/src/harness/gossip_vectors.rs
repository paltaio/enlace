use anyhow::{Result, bail};
use bytes::Bytes;
use iroh::{PublicKey, SecretKey};
use iroh_gossip::proto::{self, Command, InEvent, OutEvent, PeerData, Scope, TopicId};
use n0_future::time::Instant;
use rand::{SeedableRng, rngs::StdRng};

const TOPIC_ID: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
pub(crate) const ALPN: &[u8] = b"/iroh-gossip/1";
const PAYLOAD: &[u8] = b"hello gossip";

pub(crate) struct BroadcastFrames {
    pub(crate) topic_id: TopicId,
    pub(crate) stream_header_frame: Vec<u8>,
    pub(crate) broadcast_message_frame: Vec<u8>,
    pub(crate) payload: &'static [u8],
}

pub fn run() -> Result<()> {
    let frames = broadcast_frames()?;
    let peer_a = peer_from_seed(1);
    let peer_b = peer_from_seed(2);
    let topic = frames.topic_id;
    let join = join_message(peer_b, peer_a, topic)?;

    println!("IROH_GOSSIP_VECTOR alpn_hex={}", hex(ALPN));
    println!("IROH_GOSSIP_VECTOR topic_id_hex={}", hex(topic.as_bytes()));
    println!("IROH_GOSSIP_VECTOR peer_a_hex={}", hex(peer_a.as_bytes()));
    println!("IROH_GOSSIP_VECTOR peer_b_hex={}", hex(peer_b.as_bytes()));
    println!(
        "IROH_GOSSIP_VECTOR stream_header_frame_hex={}",
        hex(&frames.stream_header_frame)
    );
    println!(
        "IROH_GOSSIP_VECTOR join_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(&join, topic)?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR broadcast_message_frame_hex={}",
        hex(&frames.broadcast_message_frame)
    );
    println!(
        "IROH_GOSSIP_VECTOR broadcast_payload_hex={}",
        hex(frames.payload)
    );
    Ok(())
}

pub(crate) fn broadcast_frames() -> Result<BroadcastFrames> {
    let peer_a = peer_from_seed(1);
    let peer_b = peer_from_seed(2);
    let topic = TopicId::from_bytes(TOPIC_ID);
    let broadcast = broadcast_message(peer_a, peer_b, topic)?;
    let stream_header = postcard::to_stdvec(&topic)?;
    Ok(BroadcastFrames {
        topic_id: topic,
        stream_header_frame: length_prefixed(&stream_header)?,
        broadcast_message_frame: length_prefixed(&topic_message_payload(&broadcast, topic)?)?,
        payload: PAYLOAD,
    })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn join_message(
    joiner: PublicKey,
    bootstrap: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let mut state = state(joiner, 1);
    let out = state.handle(
        InEvent::Command(topic, Command::Join(vec![bootstrap])),
        Instant::now(),
        None,
    );
    require_send_message(out, bootstrap, "join")
}

fn broadcast_message(
    peer_a: PublicKey,
    peer_b: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let mut state_a = state(peer_a, 10);
    let mut state_b = state(peer_b, 20);

    let _ = state_a
        .handle(
            InEvent::Command(topic, Command::Join(Vec::new())),
            Instant::now(),
            None,
        )
        .count();
    let join = require_send_message(
        state_b.handle(
            InEvent::Command(topic, Command::Join(vec![peer_a])),
            Instant::now(),
            None,
        ),
        peer_a,
        "join",
    )?;
    let neighbor = receive(&mut state_a, peer_b, join, "neighbor")?;
    let _ = receive(&mut state_b, peer_a, neighbor, "neighbor reply")?;

    let out = state_b.handle(
        InEvent::Command(
            topic,
            Command::Broadcast(Bytes::copy_from_slice(PAYLOAD), Scope::Swarm),
        ),
        Instant::now(),
        None,
    );
    require_send_message(out, peer_a, "broadcast")
}

fn receive(
    state: &mut proto::State<PublicKey, StdRng>,
    from: PublicKey,
    message: proto::Message<PublicKey>,
    label: &str,
) -> Result<proto::Message<PublicKey>> {
    let out = state.handle(InEvent::RecvMessage(from, message), Instant::now(), None);
    require_first_send_message(out, label)
}

fn state(peer: PublicKey, seed: u64) -> proto::State<PublicKey, StdRng> {
    proto::State::new(
        peer,
        PeerData::default(),
        proto::Config::default(),
        StdRng::seed_from_u64(seed),
    )
}

fn require_send_message(
    out: impl Iterator<Item = OutEvent<PublicKey>>,
    peer: PublicKey,
    label: &str,
) -> Result<proto::Message<PublicKey>> {
    for event in out {
        if let OutEvent::SendMessage(to, message) = event
            && to == peer
        {
            return Ok(message);
        }
    }
    bail!("missing {label} message")
}

fn require_first_send_message(
    out: impl Iterator<Item = OutEvent<PublicKey>>,
    label: &str,
) -> Result<proto::Message<PublicKey>> {
    for event in out {
        if let OutEvent::SendMessage(_, message) = event {
            return Ok(message);
        }
    }
    bail!("missing {label} message")
}

fn topic_message_payload(message: &proto::Message<PublicKey>, topic: TopicId) -> Result<Vec<u8>> {
    let full = postcard::to_stdvec(message)?;
    let topic_bytes = topic.as_bytes();
    if !full.starts_with(topic_bytes) {
        bail!("gossip message did not encode topic prefix")
    }
    Ok(full[topic_bytes.len()..].to_vec())
}

fn length_prefixed(payload: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(payload.len())?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn peer_from_seed(seed: u8) -> PublicKey {
    SecretKey::from_bytes(&[seed; 32]).public()
}
