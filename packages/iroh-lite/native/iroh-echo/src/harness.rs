use anyhow::Result;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl,
    address_lookup::AddrFilter,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tokio::io;

mod gossip_vectors;

const ALPN: &[u8] = b"/iroh/echo/1";

pub async fn run_from_args(mut args: impl Iterator<Item = String>) -> Result<()> {
    let _program = args.next();
    match args.next().as_deref() {
        Some("client") => run_client().await,
        Some("gossip-send") => run_gossip_sender().await,
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
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    endpoint.online().await;
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();
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
    let connection = endpoint.connect(server_addr, ALPN).await?;
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
