use anyhow::Result;
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl,
    address_lookup::{AddrFilter, memory::MemoryLookup},
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_gossip::{ALPN as GOSSIP_ALPN, api::Event as GossipEvent, net::Gossip, proto::TopicId};
use n0_future::StreamExt;
use tokio::io::{self, AsyncReadExt};
use tokio::time::{Duration, timeout};

mod gossip_vectors;

const ECHO_ALPN: &[u8] = b"/iroh/echo/1";
const DEFAULT_GOSSIP_PAYLOAD: &[u8] = b"hello gossip";
const DEFAULT_GOSSIP_TOPIC_ID: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

pub async fn run_from_args(mut args: impl Iterator<Item = String>) -> Result<()> {
    let _program = args.next();
    match args.next().as_deref() {
        Some("client") => run_client().await,
        Some("gossip-send") => run_gossip_sender().await,
        Some("gossip-server") => run_gossip_server().await,
        Some("gossip-client-send") => run_gossip_client_send().await,
        Some("gossip-client-recv") => run_gossip_client_recv().await,
        Some("gossip-vectors") => gossip_vectors::run(),
        _ => run_server().await,
    }
}

async fn run_server() -> Result<()> {
    let relay_url: RelayUrl = std::env::var("IROH_RELAY_URL")?.parse()?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::custom([relay_url]))
        .addr_filter(AddrFilter::relay_only())
        .clear_ip_transports()
        .alpns(vec![ECHO_ALPN.to_vec()])
        .bind()
        .await?;

    endpoint.online().await;
    let router = Router::builder(endpoint).accept(ECHO_ALPN, Echo).spawn();
    println!(
        "IROH_NATIVE_ECHO_READY endpoint_id_hex={}",
        hex(router.endpoint().id().as_bytes())
    );

    std::future::pending::<()>().await;
    Ok(())
}

async fn run_client() -> Result<()> {
    let relay_url: RelayUrl = std::env::var("IROH_RELAY_URL")?.parse()?;
    let server_endpoint_id = parse_endpoint_id_hex(&std::env::var("IROH_SERVER_ENDPOINT_ID_HEX")?)?;
    let payload = parse_hex(&std::env::var("IROH_ECHO_PAYLOAD_HEX")?)?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::custom([relay_url.clone()]))
        .addr_filter(AddrFilter::relay_only())
        .clear_ip_transports()
        .bind()
        .await?;

    endpoint.online().await;
    let server_addr = EndpointAddr::new(server_endpoint_id).with_relay_url(relay_url);
    let connection = endpoint.connect(server_addr, ECHO_ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&payload).await?;
    send.finish()?;

    let received = recv.read_to_end(payload.len()).await?;
    anyhow::ensure!(received == payload, "echo response did not match request");
    connection.close(0u32.into(), b"done");
    endpoint.close().await;
    println!("IROH_NATIVE_ECHO_CLIENT_OK payload_hex={}", hex(&received));
    Ok(())
}

async fn run_gossip_server() -> Result<()> {
    let relay_url: RelayUrl = std::env::var("IROH_RELAY_URL")?.parse()?;
    let topic_id = gossip_topic_id()?;
    let endpoint = gossip_endpoint(relay_url).await?;
    endpoint.online().await;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint)
        .accept(GOSSIP_ALPN, gossip.clone())
        .spawn();
    let topic = gossip.subscribe(topic_id, Vec::new()).await?;
    let (_sender, receiver) = topic.split();
    tokio::spawn(print_gossip_events(receiver));

    println!(
        "IROH_NATIVE_GOSSIP_SERVER_READY endpoint_id_hex={} topic_id_hex={}",
        hex(router.endpoint().id().as_bytes()),
        hex(topic_id.as_bytes())
    );

    std::future::pending::<()>().await;
    Ok(())
}

async fn run_gossip_client_send() -> Result<()> {
    let relay_url: RelayUrl = std::env::var("IROH_RELAY_URL")?.parse()?;
    let bootstrap = parse_endpoint_id_hex(&std::env::var("IROH_SERVER_ENDPOINT_ID_HEX")?)?;
    let topic_id = gossip_topic_id()?;
    let payload = gossip_payload()?;
    let endpoint = gossip_endpoint(relay_url.clone()).await?;
    let (router, gossip) =
        spawn_gossip_router(endpoint, Some(bootstrap_addr(bootstrap, relay_url)))?;
    let mut topic = gossip.subscribe_and_join(topic_id, vec![bootstrap]).await?;

    topic.broadcast(Bytes::from(payload.clone())).await?;
    verify_optional_gossip_payload(&mut topic).await?;
    println!(
        "IROH_NATIVE_GOSSIP_CLIENT_SEND_OK endpoint_id_hex={} topic_id_hex={} payload_hex={}",
        hex(router.endpoint().id().as_bytes()),
        hex(topic_id.as_bytes()),
        hex(&payload)
    );
    if std::env::var("IROH_GOSSIP_STAY_OPEN").as_deref() == Ok("1") {
        let mut stdin = io::stdin();
        let mut buffer = [0u8; 1];
        let _ = stdin.read(&mut buffer).await;
    }
    router.shutdown().await?;
    Ok(())
}

async fn run_gossip_client_recv() -> Result<()> {
    let relay_url: RelayUrl = std::env::var("IROH_RELAY_URL")?.parse()?;
    let bootstrap = parse_endpoint_id_hex(&std::env::var("IROH_SERVER_ENDPOINT_ID_HEX")?)?;
    let topic_id = gossip_topic_id()?;
    let endpoint = gossip_endpoint(relay_url.clone()).await?;
    let (router, gossip) =
        spawn_gossip_router(endpoint, Some(bootstrap_addr(bootstrap, relay_url)))?;
    let mut topic = gossip.subscribe_and_join(topic_id, vec![bootstrap]).await?;
    let message = wait_for_gossip_payload(&mut topic, expected_gossip_payload()?).await?;

    println!(
        "IROH_NATIVE_GOSSIP_CLIENT_RECV_OK endpoint_id_hex={} topic_id_hex={} from_endpoint_id_hex={} payload_hex={}",
        hex(router.endpoint().id().as_bytes()),
        hex(topic_id.as_bytes()),
        hex(message.delivered_from.as_bytes()),
        hex(&message.content)
    );
    router.shutdown().await?;
    Ok(())
}

async fn run_gossip_sender() -> Result<()> {
    let relay_url: RelayUrl = std::env::var("IROH_RELAY_URL")?.parse()?;
    let server_endpoint_id = parse_endpoint_id_hex(&std::env::var("IROH_SERVER_ENDPOINT_ID_HEX")?)?;
    let frames = gossip_vectors::broadcast_frames()?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::custom([relay_url.clone()]))
        .addr_filter(AddrFilter::relay_only())
        .clear_ip_transports()
        .bind()
        .await?;

    endpoint.online().await;
    let server_addr = EndpointAddr::new(server_endpoint_id).with_relay_url(relay_url);
    let connection = endpoint.connect(server_addr, gossip_vectors::ALPN).await?;
    let mut send = connection.open_uni().await?;
    send.write_all(&frames.stream_header_frame).await?;
    send.write_all(&frames.broadcast_message_frame).await?;
    send.finish()?;
    send.stopped().await?;
    connection.close(0u32.into(), b"done");
    endpoint.close().await;
    println!(
        "IROH_NATIVE_GOSSIP_SEND_OK topic_id_hex={} payload_hex={}",
        gossip_vectors::hex(frames.topic_id.as_bytes()),
        gossip_vectors::hex(frames.payload)
    );
    Ok(())
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

async fn gossip_endpoint(relay_url: RelayUrl) -> Result<Endpoint> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::custom([relay_url]))
        .addr_filter(AddrFilter::relay_only())
        .clear_ip_transports()
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .bind()
        .await?;
    endpoint.online().await;
    Ok(endpoint)
}

fn spawn_gossip_router(
    endpoint: Endpoint,
    bootstrap: Option<EndpointAddr>,
) -> Result<(Router, Gossip)> {
    let gossip = Gossip::builder().spawn(endpoint.clone());
    if let Some(address) = bootstrap {
        let lookup = MemoryLookup::new();
        lookup.add_endpoint_info(address);
        endpoint.address_lookup()?.add(lookup);
    }
    let router = Router::builder(endpoint)
        .accept(GOSSIP_ALPN, gossip.clone())
        .spawn();
    Ok((router, gossip))
}

async fn print_gossip_events(mut receiver: iroh_gossip::api::GossipReceiver) {
    while let Ok(Some(event)) = receiver.try_next().await {
        print_gossip_event("IROH_NATIVE_GOSSIP_EVENT", event);
    }
}

fn print_gossip_event(prefix: &str, event: GossipEvent) {
    match event {
        GossipEvent::NeighborUp(peer) => {
            println!(
                "{prefix} type=neighbor-up peer_hex={}",
                hex(peer.as_bytes())
            );
        }
        GossipEvent::NeighborDown(peer) => {
            println!(
                "{prefix} type=neighbor-down peer_hex={}",
                hex(peer.as_bytes())
            );
        }
        GossipEvent::Received(message) => {
            println!(
                "{prefix} type=message from_endpoint_id_hex={} payload_hex={}",
                hex(message.delivered_from.as_bytes()),
                hex(&message.content)
            );
        }
        GossipEvent::Lagged => {
            println!("{prefix} type=lagged");
        }
    }
}

async fn verify_optional_gossip_payload(topic: &mut iroh_gossip::api::GossipTopic) -> Result<()> {
    if let Some(expected) = expected_gossip_payload()? {
        let _message = wait_for_gossip_payload(topic, Some(expected)).await?;
    }
    Ok(())
}

async fn wait_for_gossip_payload(
    topic: &mut iroh_gossip::api::GossipTopic,
    expected: Option<Vec<u8>>,
) -> Result<iroh_gossip::api::Message> {
    timeout(Duration::from_secs(10), async {
        loop {
            let event = topic
                .try_next()
                .await?
                .ok_or_else(|| anyhow::anyhow!("gossip topic closed"))?;
            print_gossip_event("IROH_NATIVE_GOSSIP_EVENT", event.clone());
            if let GossipEvent::Received(message) = event {
                if let Some(expected) = &expected {
                    anyhow::ensure!(
                        &message.content[..] == expected,
                        "received unexpected gossip payload"
                    );
                }
                return Ok(message);
            }
        }
    })
    .await?
}

fn bootstrap_addr(endpoint_id: EndpointId, relay_url: RelayUrl) -> EndpointAddr {
    EndpointAddr::new(endpoint_id).with_relay_url(relay_url)
}

fn gossip_topic_id() -> Result<TopicId> {
    match std::env::var("IROH_GOSSIP_TOPIC_ID_HEX") {
        Ok(hex) => Ok(TopicId::from_bytes(parse_32_byte_hex(&hex)?)),
        Err(std::env::VarError::NotPresent) => Ok(TopicId::from_bytes(DEFAULT_GOSSIP_TOPIC_ID)),
        Err(error) => Err(error.into()),
    }
}

fn gossip_payload() -> Result<Vec<u8>> {
    match std::env::var("IROH_GOSSIP_PAYLOAD_HEX") {
        Ok(hex) => parse_hex(&hex),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_GOSSIP_PAYLOAD.to_vec()),
        Err(error) => Err(error.into()),
    }
}

fn expected_gossip_payload() -> Result<Option<Vec<u8>>> {
    match std::env::var("IROH_GOSSIP_EXPECT_PAYLOAD_HEX") {
        Ok(hex) => Ok(Some(parse_hex(&hex)?)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_endpoint_id_hex(hex: &str) -> Result<EndpointId> {
    let bytes = parse_32_byte_hex(hex)?;
    Ok(EndpointId::from_bytes(&bytes)?)
}

fn parse_32_byte_hex(hex: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(
        hex.len() == 64,
        "endpoint id hex must be 64 lowercase hex chars"
    );
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = parse_hex_byte(&hex[offset..offset + 2])?;
    }
    Ok(bytes)
}

fn parse_hex(hex: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        hex.len().is_multiple_of(2),
        "hex input must have an even length"
    );
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for offset in (0..hex.len()).step_by(2) {
        bytes.push(parse_hex_byte(&hex[offset..offset + 2])?);
    }
    Ok(bytes)
}

fn parse_hex_byte(hex: &str) -> Result<u8> {
    Ok(u8::from_str_radix(hex, 16)?)
}
