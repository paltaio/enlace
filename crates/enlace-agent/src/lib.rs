#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use enlace::{PeerCard, PeerConfig, PeerIdentity, PeerNamespace, TrustedPeer};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use tokio::sync::mpsc;
use x25519_dalek::StaticSecret;

const DEFAULT_CHANNEL: &str = "default";
const SESSION_BUFFER: usize = 64;

#[derive(Debug, Parser)]
#[command(name = "enlace-agent")]
#[command(about = "Local daemon for enlace clients.")]
struct Cli {
    #[arg(long)]
    seed: SecretArg,
    #[arg(long)]
    token: Option<SecretArg>,
    #[arg(long)]
    listen_ws: Option<SocketAddr>,
    #[arg(long)]
    listen_unix: Option<PathBuf>,
    #[arg(long)]
    peer: Vec<SecretArg>,
    #[arg(long)]
    transport: Vec<TransportFlag>,
    #[arg(long)]
    relay: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long, default_value = "info")]
    log: String,
}

impl Cli {
    fn load(self) -> anyhow::Result<AgentConfig> {
        let seed = load_seed(&self.seed)?;
        let token = self.token.as_ref().map(load_secret).transpose()?;
        let peers = self
            .peer
            .iter()
            .map(load_peer_card)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let listen_ws = self.listen_ws;

        if listen_ws.is_none() && self.listen_unix.is_none() {
            bail!("at least one listener is required");
        }
        if self.listen_unix.is_some() {
            bail!("unix socket listener is not implemented yet");
        }
        if let Some(addr) = listen_ws
            && !is_loopback(addr)
            && token.is_none()
        {
            bail!("non-loopback WebSocket listener requires --token");
        }

        Ok(AgentConfig {
            seed,
            token,
            listen_ws,
            peers,
            transports: enabled_transports(&self.transport),
            relay: self.relay,
            data_dir: self.data_dir,
            log: self.log,
        })
    }
}

#[derive(Clone)]
struct AgentConfig {
    seed: [u8; 32],
    token: Option<String>,
    listen_ws: Option<SocketAddr>,
    peers: Vec<PeerCard>,
    transports: Vec<&'static str>,
    relay: Option<String>,
    data_dir: Option<PathBuf>,
    log: String,
}

#[derive(Debug, Clone)]
struct SecretArg(String);

impl std::str::FromStr for SecretArg {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportFlag {
    Http,
    Dht,
    Pkarr,
    Iroh,
}

pub async fn run_from_env() -> anyhow::Result<()> {
    run(Cli::parse().load()?).await
}

async fn run(config: AgentConfig) -> anyhow::Result<()> {
    if let Some(addr) = config.listen_ws {
        run_ws(config, addr).await?;
    }
    Ok(())
}

async fn run_ws(config: AgentConfig, addr: SocketAddr) -> anyhow::Result<()> {
    let router = ws_router(Arc::new(AgentState::open(config).await?));
    axum_server::bind(addr)
        .serve(router.into_make_service())
        .await
        .context("websocket listener failed")
}

fn ws_router(state: Arc<AgentState>) -> Router {
    Router::new()
        .route("/", get(ws_handler))
        .route("/health", get(health_handler))
        .route_layer(from_fn_with_state(Arc::clone(&state), require_bearer_token))
        .with_state(state)
}

async fn health_handler(State(state): State<Arc<AgentState>>) -> Json<AgentResponse> {
    Json(AgentResponse::Health(state.health(None)))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AgentState>>) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn require_bearer_token(
    State(state): State<Arc<AgentState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    match state.authorize(&headers) {
        Ok(()) => next.run(request).await,
        Err(response) => response.into_response(),
    }
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AgentState>) {
    let (outbound_tx, mut outbound_rx) = mpsc::channel(SESSION_BUFFER);
    let session = Session::new(outbound_tx);

    loop {
        tokio::select! {
            frame = socket.recv() => {
                let Some(frame) = frame else {
                    break;
                };
                let response = match frame {
                    Ok(Message::Text(text)) => state.handle_text(&text, &session).await,
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(Message::Ping(_) | Message::Pong(_)) => continue,
                    Ok(Message::Binary(_)) => AgentResponse::error(None, ErrorCode::InvalidRequest),
                };
                if send_response(&mut socket, &response).await.is_err() {
                    break;
                }
            }
            response = outbound_rx.recv() => {
                let Some(response) = response else {
                    break;
                };
                if send_response(&mut socket, &response).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[derive(Clone)]
struct AgentState {
    config: AgentConfig,
    namespace: Arc<PeerNamespace>,
    peers: Arc<HashMap<String, PeerCard>>,
}

impl AgentState {
    async fn open(config: AgentConfig) -> anyhow::Result<Self> {
        let namespace = Arc::new(open_namespace(&config).await?);
        let peers = Arc::new(
            config
                .peers
                .iter()
                .cloned()
                .map(|peer| (peer.peer_id.to_string(), peer))
                .collect(),
        );
        Ok(Self {
            config,
            namespace,
            peers,
        })
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
        let Some(expected) = &self.config.token else {
            return Ok(());
        };
        let Some(actual) = bearer_token(headers) else {
            return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
        };
        if actual.as_bytes().ct_eq(expected.as_bytes()).into() {
            Ok(())
        } else {
            Err((StatusCode::UNAUTHORIZED, "unauthorized"))
        }
    }

    async fn handle_text(&self, text: &str, session: &Session) -> AgentResponse {
        match serde_json::from_str::<AgentRequest>(text) {
            Ok(AgentRequest::Health { id }) => AgentResponse::Health(self.health(id)),
            Ok(AgentRequest::ExportCard { id }) => AgentResponse::PeerCard(PeerCardResponse {
                id,
                peer_id: self.namespace.peer_id().to_string(),
                card: self.export_card(),
            }),
            Ok(AgentRequest::ListPeers { id }) => AgentResponse::Peers(PeersResponse {
                id,
                peers: self.list_peers(),
            }),
            Ok(AgentRequest::Send {
                id,
                to,
                channel,
                payload,
            }) => {
                let Ok(payload) = payload_bytes(&payload) else {
                    return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                };
                if invalid_name(&to) || invalid_name(&channel) {
                    return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                }
                let Some(peer) = self.peers.get(&to).cloned() else {
                    return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                };
                let Ok(mailbox) = self.namespace.mailbox(&channel) else {
                    return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                };
                match mailbox.send_to_peers(&[peer], &payload).await {
                    Ok(_) => AgentResponse::Ok(OkResponse { id }),
                    Err(_) => AgentResponse::error(Some(id), ErrorCode::TransportFailed),
                }
            }
            Ok(AgentRequest::Subscribe { id, channel }) => {
                if invalid_name(&channel) {
                    AgentResponse::error(Some(id), ErrorCode::InvalidRequest)
                } else {
                    self.spawn_subscription(channel, session.clone());
                    AgentResponse::Ok(OkResponse { id })
                }
            }
            Ok(AgentRequest::GetSlot { id, channel }) => {
                if invalid_name(&channel) {
                    AgentResponse::error(Some(id), ErrorCode::InvalidRequest)
                } else {
                    let Ok(slot) = self.namespace.slot(&channel) else {
                        return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                    };
                    match slot.get_pairwise().await {
                        Ok(value) => AgentResponse::Slot(SlotResponse {
                            id,
                            channel,
                            value: value.map(|value| SlotValueResponse {
                                from: value.sender.to_string(),
                                version: value.version,
                                payload: encode_payload(&value.payload),
                                via: value.via.to_string(),
                            }),
                        }),
                        Err(_) => AgentResponse::error(Some(id), ErrorCode::TransportFailed),
                    }
                }
            }
            Ok(AgentRequest::PutSlot {
                id,
                channel,
                payload,
            }) => {
                let Ok(payload) = payload_bytes(&payload) else {
                    return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                };
                if invalid_name(&channel) || self.peers.is_empty() {
                    return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                }
                let Ok(slot) = self.namespace.slot(&channel) else {
                    return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
                };
                let recipients = self.peers.values().cloned().collect::<Vec<_>>();
                match slot.put_for_peers(&recipients, &payload).await {
                    Ok(_) => AgentResponse::Ok(OkResponse { id }),
                    Err(_) => AgentResponse::error(Some(id), ErrorCode::TransportFailed),
                }
            }
            Err(_) => AgentResponse::error(None, ErrorCode::InvalidRequest),
        }
    }

    fn spawn_subscription(&self, channel: String, session: Session) {
        let namespace = Arc::clone(&self.namespace);
        tokio::spawn(async move {
            let Ok(mailbox) = namespace.mailbox(&channel) else {
                return;
            };
            while let Ok(message) = mailbox.recv().await {
                let response = AgentResponse::Message(MessageResponse {
                    from: message.sender.to_string(),
                    channel: channel.clone(),
                    payload: encode_payload(&message.payload),
                    received_at: unix_time_secs(),
                });
                if session.send(response).await.is_err() {
                    break;
                }
            }
        });
    }

    fn health(&self, id: Option<String>) -> HealthResponse {
        HealthResponse {
            id,
            status: "ok".to_owned(),
            peer_id: self.namespace.peer_id().to_string(),
            transports: self.config.transports.clone(),
            relay: self.config.relay.clone(),
            data_dir: self
                .config
                .data_dir
                .as_ref()
                .map(|path| path.display().to_string()),
            log: self.config.log.clone(),
        }
    }

    fn export_card(&self) -> String {
        let mut card = self.namespace.card();
        if let Some(endpoint) = self.namespace.iroh_endpoint_addr() {
            card.iroh_endpoint = Some(endpoint);
        }
        card.export_string()
    }

    fn list_peers(&self) -> Vec<PeerResponse> {
        self.namespace
            .trusted_peers()
            .into_iter()
            .map(|peer| PeerResponse {
                peer_id: peer.peer_id.to_string(),
                card: peer.export_string(),
            })
            .collect()
    }
}

#[derive(Clone)]
struct Session {
    outbound: mpsc::Sender<AgentResponse>,
}

impl Session {
    fn new(outbound: mpsc::Sender<AgentResponse>) -> Self {
        Self { outbound }
    }

    async fn send(
        &self,
        response: AgentResponse,
    ) -> Result<(), mpsc::error::SendError<AgentResponse>> {
        self.outbound.send(response).await
    }
}

async fn send_response(socket: &mut WebSocket, response: &AgentResponse) -> anyhow::Result<()> {
    let text = serde_json::to_string(response)?;
    socket
        .send(Message::Text(text.into()))
        .await
        .context("websocket send failed")
}

async fn open_namespace(config: &AgentConfig) -> anyhow::Result<PeerNamespace> {
    let state = match &config.data_dir {
        Some(path) => enlace::State::file(path)
            .with_context(|| format!("failed to open agent state at {}", path.display()))?,
        None => enlace::State::memory(),
    };
    let mut peer_config = PeerConfig {
        state,
        trusted_peers: config
            .peers
            .iter()
            .cloned()
            .map(TrustedPeer::try_from_card)
            .collect::<Result<Vec<_>, _>>()
            .context("invalid peer card")?,
        ..PeerConfig::default()
    };

    configure_transports(config, &mut peer_config)?;
    PeerNamespace::open(derive_identity(&config.seed)?, peer_config)
        .await
        .context("failed to open peer namespace")
}

fn configure_transports(config: &AgentConfig, peer_config: &mut PeerConfig) -> anyhow::Result<()> {
    #[cfg(not(any(feature = "http", feature = "dht", feature = "pkarr", feature = "iroh")))]
    {
        let _ = config;
        let _ = peer_config;
    }

    #[cfg(feature = "http")]
    if config.transports.contains(&"http")
        && let Some(relay) = &config.relay
    {
        peer_config.http = Some(enlace::HttpConfig::new(
            relay.parse().context("relay URL is invalid")?,
        ));
    }

    #[cfg(feature = "dht")]
    if config.transports.contains(&"dht") {
        peer_config.dht = Some(enlace::DhtConfig::default());
    }

    #[cfg(feature = "pkarr")]
    if config.transports.contains(&"pkarr") {
        peer_config.pkarr = Some(enlace::PkarrConfig::default());
    }

    #[cfg(feature = "iroh")]
    if config.transports.contains(&"iroh") {
        peer_config.iroh = Some(enlace::IrohConfig::default());
    }

    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value.strip_prefix("Bearer ")
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum AgentRequest {
    Send {
        id: String,
        to: String,
        #[serde(default = "default_channel")]
        channel: String,
        payload: String,
    },
    Subscribe {
        id: String,
        #[serde(default = "default_channel")]
        channel: String,
    },
    PutSlot {
        id: String,
        #[serde(default = "default_channel")]
        channel: String,
        payload: String,
    },
    GetSlot {
        id: String,
        #[serde(default = "default_channel")]
        channel: String,
    },
    ListPeers {
        id: String,
    },
    ExportCard {
        id: String,
    },
    Health {
        id: Option<String>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AgentResponse {
    Ok(OkResponse),
    Health(HealthResponse),
    Message(MessageResponse),
    Peers(PeersResponse),
    PeerCard(PeerCardResponse),
    Slot(SlotResponse),
    Error(ErrorResponse),
}

impl AgentResponse {
    fn error(id: Option<String>, code: ErrorCode) -> Self {
        Self::Error(ErrorResponse {
            id,
            code,
            message: code.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct OkResponse {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct HealthResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    status: String,
    peer_id: String,
    transports: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_dir: Option<String>,
    log: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct MessageResponse {
    from: String,
    channel: String,
    payload: String,
    received_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct PeersResponse {
    id: String,
    peers: Vec<PeerResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct PeerResponse {
    peer_id: String,
    card: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct PeerCardResponse {
    id: String,
    peer_id: String,
    card: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct SlotResponse {
    id: String,
    channel: String,
    value: Option<SlotValueResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct SlotValueResponse {
    from: String,
    version: u64,
    payload: String,
    via: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct ErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    code: ErrorCode,
    message: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    InvalidRequest,
    TransportFailed,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("invalid request"),
            Self::TransportFailed => f.write_str("transport failed"),
        }
    }
}

fn default_channel() -> String {
    DEFAULT_CHANNEL.to_owned()
}

fn enabled_transports(flags: &[TransportFlag]) -> Vec<&'static str> {
    if flags.is_empty() {
        return [
            #[cfg(feature = "http")]
            "http",
            #[cfg(feature = "dht")]
            "dht",
            #[cfg(feature = "pkarr")]
            "pkarr",
            #[cfg(feature = "iroh")]
            "iroh",
        ]
        .into_iter()
        .collect();
    }

    #[cfg(not(any(feature = "http", feature = "dht", feature = "pkarr", feature = "iroh")))]
    {
        let _ = flags;
        Vec::new()
    }

    #[cfg(any(feature = "http", feature = "dht", feature = "pkarr", feature = "iroh"))]
    {
        let mut transports = Vec::new();
        for flag in flags {
            match flag {
                TransportFlag::Http => {
                    #[cfg(feature = "http")]
                    transports.push("http");
                }
                TransportFlag::Dht => {
                    #[cfg(feature = "dht")]
                    transports.push("dht");
                }
                TransportFlag::Pkarr => {
                    #[cfg(feature = "pkarr")]
                    transports.push("pkarr");
                }
                TransportFlag::Iroh => {
                    #[cfg(feature = "iroh")]
                    transports.push("iroh");
                }
            }
        }
        transports
    }
}

fn load_seed(arg: &SecretArg) -> anyhow::Result<[u8; 32]> {
    let value = load_secret(arg)?;
    parse_hex_seed(value.trim())
}

fn load_secret(arg: &SecretArg) -> anyhow::Result<String> {
    let path = PathBuf::from(&arg.0);
    if path.exists() {
        return std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))
            .map(|value| value.trim_end_matches(['\r', '\n']).to_owned());
    }
    Ok(arg.0.clone())
}

fn load_peer_card(arg: &SecretArg) -> anyhow::Result<PeerCard> {
    let value = load_secret(arg)?;
    PeerCard::import_string(value.trim()).context("invalid peer card")
}

fn derive_identity(seed: &[u8; 32]) -> anyhow::Result<PeerIdentity> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"enlace-agent/v1/identity"), seed);
    let mut signing = [0_u8; 32];
    let mut exchange = [0_u8; 32];
    hkdf.expand(b"signing", &mut signing)
        .map_err(|_| anyhow::anyhow!("failed to derive signing key"))?;
    hkdf.expand(b"exchange", &mut exchange)
        .map_err(|_| anyhow::anyhow!("failed to derive exchange key"))?;
    Ok(PeerIdentity::from_parts(
        SigningKey::from_bytes(&signing),
        StaticSecret::from(exchange),
        None,
    ))
}

fn parse_hex_seed(value: &str) -> anyhow::Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("seed must be 32 bytes encoded as 64 hex characters");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("seed must be lowercase hex");
    }

    let mut seed = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).context("seed is not utf-8")?;
        seed[index] = u8::from_str_radix(text, 16).context("seed must be lowercase hex")?;
    }
    if seed.iter().all(|byte| *byte == 0) {
        bail!("seed must not be all zero");
    }
    Ok(seed)
}

fn payload_bytes(value: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("payload must be base64")
}

fn encode_payload(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn invalid_name(value: &str) -> bool {
    value.is_empty()
}

fn is_loopback(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use enlace::{ConfiguredTransport, TransportKind};
    use enlace_testkit::InMemoryTransport;
    use tower::ServiceExt as _;

    fn config(token: Option<&str>) -> AgentConfig {
        AgentConfig {
            seed: [1; 32],
            token: token.map(str::to_owned),
            listen_ws: Some("127.0.0.1:0".parse().unwrap()),
            peers: Vec::new(),
            transports: vec!["http"],
            relay: None,
            data_dir: None,
            log: "info".to_owned(),
        }
    }

    async fn state(
        seed: [u8; 32],
        peers: Vec<PeerCard>,
        transport: InMemoryTransport,
    ) -> AgentState {
        let namespace = PeerNamespace::open(
            derive_identity(&seed).unwrap(),
            PeerConfig {
                trusted_peers: peers
                    .iter()
                    .cloned()
                    .map(TrustedPeer::try_from_card)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                transports: vec![ConfiguredTransport::new(
                    TransportKind::Http,
                    Arc::new(transport),
                )],
                ..PeerConfig::default()
            },
        )
        .await
        .unwrap();
        AgentState {
            config: AgentConfig {
                seed,
                token: None,
                listen_ws: Some("127.0.0.1:0".parse().unwrap()),
                peers: peers.clone(),
                transports: vec!["http"],
                relay: None,
                data_dir: None,
                log: "info".to_owned(),
            },
            namespace: Arc::new(namespace),
            peers: Arc::new(
                peers
                    .into_iter()
                    .map(|peer| (peer.peer_id.to_string(), peer))
                    .collect(),
            ),
        }
    }

    fn session() -> (Session, mpsc::Receiver<AgentResponse>) {
        let (tx, rx) = mpsc::channel(SESSION_BUFFER);
        (Session::new(tx), rx)
    }

    #[test]
    fn seed_parser_accepts_32_bytes() {
        let seed = parse_hex_seed(&"01".repeat(32)).unwrap();

        assert_eq!(seed, [1; 32]);
    }

    #[test]
    fn seed_parser_rejects_all_zero() {
        let err = parse_hex_seed(&"00".repeat(32)).unwrap_err();

        assert!(err.to_string().contains("all zero"));
    }

    #[tokio::test]
    async fn send_request_rejects_bad_payload() {
        let state = state([1; 32], Vec::new(), InMemoryTransport::new()).await;
        let (session, _rx) = session();
        let response = state.handle_text(
            r#"{"id":"1","type":"send","to":"peer","channel":"default","payload":"not base64"}"#,
            &session,
        ).await;

        match response {
            AgentResponse::Error(error) => assert!(matches!(error.code, ErrorCode::InvalidRequest)),
            AgentResponse::Ok(_)
            | AgentResponse::Health(_)
            | AgentResponse::Message(_)
            | AgentResponse::Peers(_)
            | AgentResponse::PeerCard(_)
            | AgentResponse::Slot(_) => {
                panic!("expected error");
            }
        }
    }

    #[tokio::test]
    async fn health_response_has_single_type_field() {
        let state = state([1; 32], Vec::new(), InMemoryTransport::new()).await;
        let (session, _rx) = session();
        let response = state
            .handle_text(r#"{"id":"1","type":"health"}"#, &session)
            .await;
        let json = serde_json::to_value(response).unwrap();

        assert_eq!(json["type"], "health");
        assert_eq!(json["id"], "1");
        assert_eq!(
            json.as_object()
                .unwrap()
                .keys()
                .filter(|key| *key == "type")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn websocket_route_requires_bearer_token() {
        let mut state = state([1; 32], Vec::new(), InMemoryTransport::new()).await;
        state.config = config(Some("secret"));
        let router = ws_router(Arc::new(state));
        let response = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn non_loopback_listener_requires_token() {
        let cli = Cli {
            seed: SecretArg("01".repeat(32)),
            token: None,
            listen_ws: Some("0.0.0.0:3000".parse().unwrap()),
            listen_unix: None,
            peer: Vec::new(),
            transport: Vec::new(),
            relay: None,
            data_dir: None,
            log: "info".to_owned(),
        };

        let Err(err) = cli.load() else {
            panic!("expected config error");
        };

        assert!(err.to_string().contains("requires --token"));
    }

    #[tokio::test]
    async fn send_delivers_to_subscribed_peer() {
        let transport = InMemoryTransport::new();
        let alice_identity = derive_identity(&[1; 32]).unwrap();
        let bob_identity = derive_identity(&[2; 32]).unwrap();
        let alice_card = alice_identity.card();
        let bob_card = bob_identity.card();
        let alice = state([1; 32], vec![bob_card.clone()], transport.clone()).await;
        let bob = state([2; 32], vec![alice_card.clone()], transport).await;
        let (bob_session, mut bob_rx) = session();
        let (alice_session, _alice_rx) = session();

        let response = bob
            .handle_text(
                r#"{"id":"sub","type":"subscribe","channel":"default"}"#,
                &bob_session,
            )
            .await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        let request = serde_json::json!({
            "id": "send",
            "type": "send",
            "to": bob_card.peer_id.to_string(),
            "channel": "default",
            "payload": encode_payload(b"hello")
        });
        let response = alice
            .handle_text(&request.to_string(), &alice_session)
            .await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        let Some(AgentResponse::Message(message)) = bob_rx.recv().await else {
            panic!("expected message event");
        };
        assert_eq!(message.from, alice_card.peer_id.to_string());
        assert_eq!(message.channel, "default");
        assert_eq!(message.payload, encode_payload(b"hello"));
    }

    #[tokio::test]
    async fn pairing_commands_return_agent_and_peer_cards() {
        let transport = InMemoryTransport::new();
        let alice_identity = derive_identity(&[1; 32]).unwrap();
        let bob_identity = derive_identity(&[2; 32]).unwrap();
        let alice_card = alice_identity.card();
        let bob_card = bob_identity.card();
        let alice = state([1; 32], vec![bob_card.clone()], transport).await;
        let (session, _rx) = session();

        let response = alice
            .handle_text(r#"{"id":"card","type":"export_card"}"#, &session)
            .await;
        let AgentResponse::PeerCard(card) = response else {
            panic!("expected peer card response");
        };
        assert_eq!(card.id, "card");
        assert_eq!(card.peer_id, alice_card.peer_id.to_string());
        assert_eq!(
            PeerCard::import_string(&card.card).unwrap().peer_id,
            alice_card.peer_id
        );

        let response = alice
            .handle_text(r#"{"id":"peers","type":"list_peers"}"#, &session)
            .await;
        let AgentResponse::Peers(peers) = response else {
            panic!("expected peers response");
        };
        assert_eq!(peers.id, "peers");
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.peers[0].peer_id, bob_card.peer_id.to_string());
        assert_eq!(
            PeerCard::import_string(&peers.peers[0].card)
                .unwrap()
                .peer_id,
            bob_card.peer_id
        );
    }

    #[tokio::test]
    async fn slot_put_and_get_exchange_latest_value() {
        let transport = InMemoryTransport::new();
        let alice_identity = derive_identity(&[1; 32]).unwrap();
        let bob_identity = derive_identity(&[2; 32]).unwrap();
        let alice_card = alice_identity.card();
        let bob_card = bob_identity.card();
        let alice = state([1; 32], vec![bob_card.clone()], transport.clone()).await;
        let bob = state([2; 32], vec![alice_card.clone()], transport).await;
        let (alice_session, _alice_rx) = session();
        let (bob_session, _bob_rx) = session();

        let put = serde_json::json!({
            "id": "put",
            "type": "put_slot",
            "channel": "status",
            "payload": encode_payload(b"ready")
        });
        let response = alice.handle_text(&put.to_string(), &alice_session).await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        let response = bob
            .handle_text(
                r#"{"id":"get","type":"get_slot","channel":"status"}"#,
                &bob_session,
            )
            .await;
        let AgentResponse::Slot(slot) = response else {
            panic!("expected slot response");
        };
        let value = slot.value.expect("slot value");
        assert_eq!(slot.id, "get");
        assert_eq!(slot.channel, "status");
        assert_eq!(value.from, alice_card.peer_id.to_string());
        assert_eq!(value.version, 1);
        assert_eq!(value.payload, encode_payload(b"ready"));
        assert_eq!(value.via, "http");
    }
}
