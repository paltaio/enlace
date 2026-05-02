#![warn(clippy::all)]
#![warn(clippy::pedantic)]

use anyhow::Result;
use iroh::{
    Endpoint, RelayMode, RelayUrl,
    address_lookup::AddrFilter,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tokio::io;

const ALPN: &[u8] = b"/iroh/echo/1";

#[tokio::main]
async fn main() -> Result<()> {
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
