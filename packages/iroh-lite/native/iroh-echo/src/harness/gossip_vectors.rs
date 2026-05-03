use std::{collections::BTreeSet, net::SocketAddr};

use anyhow::{Result, bail};
use bytes::Bytes;
use iroh::{PublicKey, RelayUrl, SecretKey};
use iroh_gossip::proto::{self, Command, InEvent, OutEvent, PeerData, Scope, TopicId};
use n0_future::time::Instant;
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

const TOPIC_ID: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
pub(crate) const ALPN: &[u8] = b"/iroh-gossip/1";
const PAYLOAD: &[u8] = b"hello gossip";
const REPAIR_PAYLOAD: &[u8] = b"repair gossip";
const RELAY_URL: &str = "https://relay.example.com/";

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct AddrInfo {
    relay_url: Option<RelayUrl>,
    direct_addresses: BTreeSet<SocketAddr>,
}

pub(crate) struct BroadcastFrames {
    pub(crate) topic_id: TopicId,
    pub(crate) stream_header_frame: Vec<u8>,
    pub(crate) broadcast_message_frame: Vec<u8>,
    pub(crate) payload: &'static [u8],
}

#[allow(clippy::too_many_lines)]
pub fn run() -> Result<()> {
    let frames = broadcast_frames()?;
    let peer_a = peer_from_seed(1);
    let peer_b = peer_from_seed(2);
    let peer_c = peer_from_seed(3);
    let peer_d = peer_from_seed(4);
    let topic = frames.topic_id;
    let join = join_message(peer_b, peer_a, topic)?;
    let neighbor = neighbor_message(peer_a, peer_b, topic)?;
    let forward_join = forward_join_message(peer_a, peer_b, peer_c, topic)?;
    let shuffle = shuffle_message(peer_a, peer_b, topic)?;
    let shuffle_reply = shuffle_reply_message(peer_a, peer_b, topic)?;
    let disconnect = disconnect_message(peer_a, peer_d, topic)?;
    let prune = prune_message(peer_a, peer_b, peer_c, topic)?;
    let ihave = ihave_message(peer_a, peer_b, peer_c, topic)?;
    let graft = graft_message(peer_a, peer_b, peer_c, topic)?;
    let empty_addr_info = postcard::to_stdvec(&AddrInfo::default())?;
    let relay_peer_data = relay_peer_data()?;
    let direct_peer_data = direct_peer_data()?;
    let relay_join = join_message_with_peer_data(peer_b, peer_a, topic, relay_peer_data.clone())?;

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
        "IROH_GOSSIP_VECTOR relay_join_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(
            &relay_join,
            topic
        )?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR neighbor_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(&neighbor, topic)?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR forward_join_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(
            &forward_join,
            topic
        )?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR shuffle_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(&shuffle, topic)?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR shuffle_reply_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(
            &shuffle_reply,
            topic
        )?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR disconnect_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(
            &disconnect,
            topic
        )?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR broadcast_message_frame_hex={}",
        hex(&frames.broadcast_message_frame)
    );
    println!(
        "IROH_GOSSIP_VECTOR prune_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(&prune, topic)?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR ihave_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(&ihave, topic)?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR graft_message_frame_hex={}",
        hex(&length_prefixed(&topic_message_payload(&graft, topic)?)?)
    );
    println!(
        "IROH_GOSSIP_VECTOR broadcast_payload_hex={}",
        hex(frames.payload)
    );
    println!(
        "IROH_GOSSIP_VECTOR repair_payload_hex={}",
        hex(REPAIR_PAYLOAD)
    );
    println!(
        "IROH_GOSSIP_VECTOR peer_data_empty_hex={}",
        hex(PeerData::default().as_bytes())
    );
    println!(
        "IROH_GOSSIP_VECTOR addr_info_empty_hex={}",
        hex(&empty_addr_info)
    );
    println!("IROH_GOSSIP_VECTOR relay_url={RELAY_URL}");
    println!(
        "IROH_GOSSIP_VECTOR relay_peer_data_hex={}",
        hex(relay_peer_data.as_bytes())
    );
    println!("IROH_GOSSIP_VECTOR direct_addr=127.0.0.1:12345");
    println!(
        "IROH_GOSSIP_VECTOR direct_peer_data_hex={}",
        hex(direct_peer_data.as_bytes())
    );
    Ok(())
}

pub(crate) fn broadcast_frames() -> Result<BroadcastFrames> {
    let peer_a = peer_from_seed(1);
    let peer_b = peer_from_seed(2);
    let topic = TopicId::from_bytes(TOPIC_ID);
    let broadcast = broadcast_message(peer_a, peer_b, topic, PAYLOAD)?;
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

fn join_message_with_peer_data(
    joiner: PublicKey,
    bootstrap: PublicKey,
    topic: TopicId,
    peer_data: PeerData,
) -> Result<proto::Message<PublicKey>> {
    let mut state = state_with_peer_data(joiner, peer_data, 1);
    let out = state.handle(
        InEvent::Command(topic, Command::Join(vec![bootstrap])),
        Instant::now(),
        None,
    );
    require_send_message(out, bootstrap, "join")
}

fn neighbor_message(
    receiver: PublicKey,
    joiner: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let mut state = initialized_state(receiver, 60, topic);
    let join = join_message(joiner, receiver, topic)?;
    receive(&mut state, joiner, join, "neighbor")
}

fn forward_join_message(
    receiver: PublicKey,
    active_peer: PublicKey,
    joiner: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let mut state = initialized_state(receiver, 70, topic);
    let active_join = join_message(active_peer, receiver, topic)?;
    let _ = receive(&mut state, active_peer, active_join, "active neighbor")?;
    let join = join_message(joiner, receiver, topic)?;
    let out = state.handle(InEvent::RecvMessage(joiner, join), Instant::now(), None);
    require_send_message_named(out, active_peer, "forward join", "ForwardJoin")
}

fn shuffle_message(
    sender: PublicKey,
    receiver: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let mut state = state(sender, 80);
    let _ = state
        .handle(
            InEvent::Command(topic, Command::Join(Vec::new())),
            Instant::now(),
            None,
        )
        .count();
    let timer = require_schedule_timer_named(
        state.handle(
            InEvent::UpdatePeerData(PeerData::default()),
            Instant::now(),
            None,
        ),
        "shuffle timer",
        "DoShuffle",
    )?;
    let join = join_message(receiver, sender, topic)?;
    let _ = receive(&mut state, receiver, join, "shuffle neighbor")?;
    let out = state.handle(InEvent::TimerExpired(timer), Instant::now(), None);
    require_send_message_named(out, receiver, "shuffle", "Shuffle")
}

fn shuffle_reply_message(
    sender: PublicKey,
    receiver: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let shuffle = shuffle_message(sender, receiver, topic)?;
    let mut state = initialized_state(receiver, 90, topic);
    let out = state.handle(InEvent::RecvMessage(sender, shuffle), Instant::now(), None);
    require_send_message_named(out, sender, "shuffle reply", "ShuffleReply")
}

fn disconnect_message(
    sender: PublicKey,
    receiver: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let mut state = initialized_state(sender, 100, topic);
    let join = join_message(receiver, sender, topic)?;
    let _ = receive(&mut state, receiver, join, "disconnect neighbor")?;
    let out = state.handle(InEvent::Command(topic, Command::Quit), Instant::now(), None);
    require_send_message_named(out, receiver, "disconnect", "Disconnect")
}

fn prune_message(
    sender: PublicKey,
    receiver: PublicKey,
    other: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let gossip = broadcast_message(sender, receiver, topic, PAYLOAD)?;
    let mut state = initialized_state(other, 30, topic);
    let _ = state
        .handle(
            InEvent::RecvMessage(sender, gossip.clone()),
            Instant::now(),
            None,
        )
        .count();
    let out = state.handle(InEvent::RecvMessage(sender, gossip), Instant::now(), None);
    require_send_message(out, sender, "prune")
}

fn ihave_message(
    lazy_peer: PublicKey,
    receiver: PublicKey,
    other: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let mut state = initialized_state(receiver, 40, topic);
    make_lazy_peer(&mut state, lazy_peer, other, topic)?;
    let events = state
        .handle(
            InEvent::Command(
                topic,
                Command::Broadcast(Bytes::copy_from_slice(REPAIR_PAYLOAD), Scope::Swarm),
            ),
            Instant::now(),
            None,
        )
        .collect::<Vec<_>>();
    let timer =
        require_schedule_timer_named(events.into_iter(), "ihave dispatch", "DispatchLazyPush")?;
    let out = state.handle(InEvent::TimerExpired(timer), Instant::now(), None);
    require_send_message(out, lazy_peer, "ihave")
}

fn graft_message(
    ihave_sender: PublicKey,
    receiver: PublicKey,
    other: PublicKey,
    topic: TopicId,
) -> Result<proto::Message<PublicKey>> {
    let ihave = ihave_message(ihave_sender, receiver, other, topic)?;
    let mut state = initialized_state(other, 50, topic);
    let out = state.handle(
        InEvent::RecvMessage(ihave_sender, ihave),
        Instant::now(),
        None,
    );
    let timer = require_schedule_timer_named(out, "graft send", "SendGraft")?;
    let events = state
        .handle(InEvent::TimerExpired(timer), Instant::now(), None)
        .collect::<Vec<_>>();
    require_send_message(events.into_iter(), ihave_sender, "graft")
}

fn broadcast_message(
    peer_a: PublicKey,
    peer_b: PublicKey,
    topic: TopicId,
    payload: &'static [u8],
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
            Command::Broadcast(Bytes::copy_from_slice(payload), Scope::Swarm),
        ),
        Instant::now(),
        None,
    );
    require_send_message(out, peer_a, "broadcast")
}

fn make_lazy_peer(
    state: &mut proto::State<PublicKey, StdRng>,
    lazy_peer: PublicKey,
    other: PublicKey,
    topic: TopicId,
) -> Result<()> {
    let prune = prune_message(lazy_peer, other, state.me().to_owned(), topic)?;
    let _ = state
        .handle(InEvent::RecvMessage(lazy_peer, prune), Instant::now(), None)
        .count();
    Ok(())
}

fn initialized_state(
    peer: PublicKey,
    seed: u64,
    topic: TopicId,
) -> proto::State<PublicKey, StdRng> {
    let mut out = state(peer, seed);
    let _ = out
        .handle(
            InEvent::Command(topic, Command::Join(Vec::new())),
            Instant::now(),
            None,
        )
        .count();
    out
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
    state_with_peer_data(peer, PeerData::default(), seed)
}

fn state_with_peer_data(
    peer: PublicKey,
    peer_data: PeerData,
    seed: u64,
) -> proto::State<PublicKey, StdRng> {
    proto::State::new(
        peer,
        peer_data,
        proto::Config::default(),
        StdRng::seed_from_u64(seed),
    )
}

fn require_send_message(
    out: impl Iterator<Item = OutEvent<PublicKey>>,
    peer: PublicKey,
    label: &str,
) -> Result<proto::Message<PublicKey>> {
    let mut events = Vec::new();
    for event in out {
        match event {
            OutEvent::SendMessage(to, message) if to == peer => return Ok(message),
            event => events.push(event),
        }
    }
    bail!("missing {label} message in events: {events:?}")
}

fn require_send_message_named(
    out: impl Iterator<Item = OutEvent<PublicKey>>,
    peer: PublicKey,
    label: &str,
    name: &str,
) -> Result<proto::Message<PublicKey>> {
    let mut events = Vec::new();
    for event in out {
        match event {
            OutEvent::SendMessage(to, message)
                if to == peer && format!("{message:?}").contains(name) =>
            {
                return Ok(message);
            }
            event => events.push(event),
        }
    }
    bail!("missing {label} message in events: {events:?}")
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

fn require_schedule_timer_named(
    out: impl Iterator<Item = OutEvent<PublicKey>>,
    label: &str,
    name: &str,
) -> Result<proto::Timer<PublicKey>> {
    let mut events = Vec::new();
    for event in out {
        if let OutEvent::ScheduleTimer(_, timer) = &event
            && format!("{timer:?}").contains(name)
        {
            let timer = timer.clone();
            return Ok(timer);
        }
        events.push(event);
    }
    bail!("missing {label} timer in events: {events:?}")
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

fn relay_peer_data() -> Result<PeerData> {
    let relay_url: RelayUrl = RELAY_URL.parse()?;
    let info = AddrInfo {
        relay_url: Some(relay_url),
        direct_addresses: BTreeSet::new(),
    };
    Ok(PeerData::new(postcard::to_stdvec(&info)?))
}

fn direct_peer_data() -> Result<PeerData> {
    let info = AddrInfo {
        relay_url: None,
        direct_addresses: BTreeSet::from(["127.0.0.1:12345".parse()?]),
    };
    Ok(PeerData::new(postcard::to_stdvec(&info)?))
}

fn peer_from_seed(seed: u8) -> PublicKey {
    SecretKey::from_bytes(&[seed; 32]).public()
}
