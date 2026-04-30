#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::fmt;
use std::future::Future;
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
use enlace::{PeerCard, PeerConfig, PeerId, PeerIdentity, PeerNamespace, TrustedPeer};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
#[cfg(all(feature = "unix-socket", unix))]
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
#[cfg(all(feature = "unix-socket", unix))]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use x25519_dalek::StaticSecret;

const DEFAULT_CHANNEL: &str = "default";
const SESSION_BUFFER: usize = 64;
type ShutdownReceiver = watch::Receiver<bool>;

#[derive(Debug, Parser)]
#[command(name = "enlace-agent")]
#[command(about = "Local daemon for enlace clients.")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    seed: Option<SecretArg>,
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
    #[arg(long)]
    log: Option<String>,
}

impl Cli {
    fn load(self) -> anyhow::Result<AgentConfig> {
        let file = self
            .config
            .as_ref()
            .map(load_file_config)
            .transpose()?
            .unwrap_or_default();
        let seed = load_config_seed(self.seed.as_ref(), &file)?;
        let token = load_config_token(self.token.as_ref(), &file)?;
        let peers = load_config_peers(&self.peer, &file)?;
        let listen_ws = self.listen_ws.or(file.listen_ws);
        let listen_unix = self.listen_unix.or(file.listen_unix);
        let transports = if self.transport.is_empty() {
            file.transports.unwrap_or_default()
        } else {
            self.transport
        };

        if listen_ws.is_none() && listen_unix.is_none() {
            bail!("at least one listener is required");
        }
        validate_transport_flags(&transports)?;
        #[cfg(not(all(feature = "unix-socket", unix)))]
        if listen_unix.is_some() {
            bail!("unix socket listener requires unix-socket feature on unix platforms");
        }
        if let Some(addr) = listen_ws
            && token.is_none()
        {
            if !is_loopback(addr) {
                bail!("non-loopback WebSocket listener requires --token");
            }
            bail!("websocket listener requires --token");
        }

        Ok(AgentConfig {
            seed,
            token,
            listen_ws,
            listen_unix,
            peers,
            transports: enabled_transports(&transports),
            relay: self.relay.or(file.relay),
            data_dir: self.data_dir.or(file.data_dir),
            log: self.log.or(file.log).unwrap_or_else(|| "info".to_owned()),
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct FileConfig {
    seed: Option<String>,
    seed_file: Option<PathBuf>,
    token: Option<String>,
    token_file: Option<PathBuf>,
    listen_ws: Option<SocketAddr>,
    listen_unix: Option<PathBuf>,
    peers: Option<Vec<String>>,
    transports: Option<Vec<TransportFlag>>,
    relay: Option<String>,
    data_dir: Option<PathBuf>,
    log: Option<String>,
}

#[derive(Clone)]
struct AgentConfig {
    seed: [u8; 32],
    token: Option<String>,
    listen_ws: Option<SocketAddr>,
    listen_unix: Option<PathBuf>,
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

#[derive(Debug, Clone, Copy, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum TransportFlag {
    Http,
    Dht,
    Pkarr,
    Iroh,
}

impl TransportFlag {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Dht => "dht",
            Self::Pkarr => "pkarr",
            Self::Iroh => "iroh",
        }
    }

    const fn enabled(self) -> bool {
        match self {
            Self::Http => cfg!(feature = "http"),
            Self::Dht => cfg!(feature = "dht"),
            Self::Pkarr => cfg!(feature = "pkarr"),
            Self::Iroh => cfg!(feature = "iroh"),
        }
    }
}

pub async fn run_from_env() -> anyhow::Result<()> {
    run(Cli::parse().load()?).await
}

async fn run(config: AgentConfig) -> anyhow::Result<()> {
    run_with_shutdown(config, std::future::pending()).await
}

async fn run_with_shutdown<F>(config: AgentConfig, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_task = tokio::spawn(async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    });
    let result = run_until(config, shutdown_rx).await;
    shutdown_task.abort();
    let _ = shutdown_task.await;
    result
}

async fn run_until(config: AgentConfig, shutdown: ShutdownReceiver) -> anyhow::Result<()> {
    let listen_ws = config.listen_ws;
    let listen_unix = config.listen_unix.clone();
    let state = Arc::new(AgentState::open(config).await?);

    match (listen_ws, listen_unix) {
        (Some(addr), Some(path)) => {
            #[cfg(all(feature = "unix-socket", unix))]
            {
                run_ws_and_unix(state, addr, path, shutdown).await?;
            }
            #[cfg(not(all(feature = "unix-socket", unix)))]
            {
                let _ = (state, addr, path, shutdown);
                bail!("unix socket listener requires unix-socket feature on unix platforms");
            }
        }
        (Some(addr), None) => run_ws_until(state, addr, shutdown).await?,
        (None, Some(path)) => {
            #[cfg(all(feature = "unix-socket", unix))]
            {
                run_unix_until(state, path, shutdown).await?;
            }
            #[cfg(not(all(feature = "unix-socket", unix)))]
            {
                let _ = (state, path, shutdown);
                bail!("unix socket listener requires unix-socket feature on unix platforms");
            }
        }
        (None, None) => {}
    }
    Ok(())
}

#[cfg(test)]
async fn run_ws(state: Arc<AgentState>, addr: SocketAddr) -> anyhow::Result<()> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_ws_until(state, addr, shutdown_rx).await
}

async fn run_ws_until(
    state: Arc<AgentState>,
    addr: SocketAddr,
    mut shutdown: ShutdownReceiver,
) -> anyhow::Result<()> {
    let router = ws_router(state);
    let handle = axum_server::Handle::new();
    let shutdown_task = tokio::spawn({
        let handle = handle.clone();
        async move {
            wait_for_shutdown(&mut shutdown).await;
            handle.graceful_shutdown(None);
        }
    });
    let result = axum_server::bind(addr)
        .handle(handle)
        .serve(router.into_make_service())
        .await
        .context("websocket listener failed");
    shutdown_task.abort();
    let _ = shutdown_task.await;
    result
}

#[cfg(all(feature = "unix-socket", unix))]
async fn run_ws_and_unix(
    state: Arc<AgentState>,
    addr: SocketAddr,
    path: PathBuf,
    shutdown: ShutdownReceiver,
) -> anyhow::Result<()> {
    tokio::try_join!(
        run_ws_until(Arc::clone(&state), addr, shutdown.clone()),
        run_unix_until(state, path, shutdown)
    )?;
    Ok(())
}

async fn wait_for_shutdown(shutdown: &mut ShutdownReceiver) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        if shutdown.changed().await.is_err() {
            break;
        }
    }
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

#[cfg(all(test, feature = "unix-socket", unix))]
async fn run_unix(state: Arc<AgentState>, path: PathBuf) -> anyhow::Result<()> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_unix_until(state, path, shutdown_rx).await
}

#[cfg(all(feature = "unix-socket", unix))]
async fn run_unix_until(
    state: Arc<AgentState>,
    path: PathBuf,
    mut shutdown: ShutdownReceiver,
) -> anyhow::Result<()> {
    prepare_unix_socket_path(path.clone()).await?;
    let listener =
        UnixListener::bind(&path).with_context(|| format!("failed to bind {}", path.display()))?;

    loop {
        tokio::select! {
            stream = listener.accept() => {
                let (stream, _) = stream
                    .with_context(|| format!("failed to accept on {}", path.display()))?;
                tokio::spawn(handle_unix_stream(stream, Arc::clone(&state)));
            }
            () = wait_for_shutdown(&mut shutdown) => break,
        }
    }
    Ok(())
}

#[cfg(all(feature = "unix-socket", unix))]
async fn prepare_unix_socket_path(path: PathBuf) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("failed to remove {}", path.display()));
            }
        }
        Ok(())
    })
    .await
    .context("failed to prepare unix socket path")?
}

#[cfg(all(feature = "unix-socket", unix))]
async fn handle_unix_stream(stream: UnixStream, state: Arc<AgentState>) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let (outbound_tx, mut outbound_rx) = mpsc::channel(SESSION_BUFFER);
    let session = Session::new(outbound_tx);

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Ok(Some(line)) = line else {
                    break;
                };
                let response = state.handle_text(&line, &session).await;
                if write_json_line(&mut writer, &response).await.is_err() {
                    break;
                }
            }
            response = outbound_rx.recv() => {
                let Some(response) = response else {
                    break;
                };
                if write_json_line(&mut writer, &response).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(all(feature = "unix-socket", unix))]
async fn write_json_line<W>(writer: &mut W, response: &AgentResponse) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let text = serde_json::to_string(response)?;
    writer
        .write_all(text.as_bytes())
        .await
        .context("unix socket send failed")?;
    writer
        .write_all(b"\n")
        .await
        .context("unix socket send failed")?;
    Ok(())
}

#[derive(Clone)]
struct AgentState {
    config: AgentConfig,
    namespace: Arc<PeerNamespace>,
}

impl AgentState {
    async fn open(config: AgentConfig) -> anyhow::Result<Self> {
        let namespace = Arc::new(open_namespace(&config).await?);
        Ok(Self { config, namespace })
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
            Ok(AgentRequest::AddPeer { id, card }) => self.handle_add_peer(id, &card),
            Ok(AgentRequest::RemovePeer { id, peer_id }) => self.handle_remove_peer(id, &peer_id),
            Ok(AgentRequest::Send {
                id,
                to,
                channel,
                payload,
            }) => self.handle_send(id, to, channel, payload).await,
            Ok(AgentRequest::Subscribe { id, channel }) => {
                if invalid_name(&channel) {
                    AgentResponse::error(Some(id), ErrorCode::InvalidRequest)
                } else {
                    self.spawn_subscription(channel, session.clone());
                    AgentResponse::Ok(OkResponse { id })
                }
            }
            Ok(AgentRequest::GetSlot { id, channel }) => self.handle_get_slot(id, channel).await,
            Ok(AgentRequest::PutSlot {
                id,
                channel,
                payload,
            }) => self.handle_put_slot(id, channel, payload).await,
            Err(_) => AgentResponse::error(None, ErrorCode::InvalidRequest),
        }
    }

    fn handle_add_peer(&self, id: String, card: &str) -> AgentResponse {
        let Ok(card) = self.add_peer(card) else {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        };
        AgentResponse::PeerCard(PeerCardResponse {
            id,
            peer_id: card.peer_id.to_string(),
            card: card.export_string(),
        })
    }

    fn handle_remove_peer(&self, id: String, peer_id: &str) -> AgentResponse {
        let Ok(peer_id) = parse_peer_id(peer_id) else {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        };
        match self.namespace.remove_trusted_peer(peer_id) {
            Ok(()) => AgentResponse::Ok(OkResponse { id }),
            Err(_) => AgentResponse::error(Some(id), ErrorCode::InvalidRequest),
        }
    }

    async fn handle_send(
        &self,
        id: String,
        to: String,
        channel: String,
        payload: String,
    ) -> AgentResponse {
        let Ok(payload) = payload_bytes(&payload) else {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        };
        if invalid_name(&to) || invalid_name(&channel) {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        }
        let Some(peer) = self.find_peer(&to) else {
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

    async fn handle_get_slot(&self, id: String, channel: String) -> AgentResponse {
        if invalid_name(&channel) {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        }
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

    async fn handle_put_slot(&self, id: String, channel: String, payload: String) -> AgentResponse {
        let Ok(payload) = payload_bytes(&payload) else {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        };
        let recipients = self.namespace.trusted_peers();
        if invalid_name(&channel) || recipients.is_empty() {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        }
        let Ok(slot) = self.namespace.slot(&channel) else {
            return AgentResponse::error(Some(id), ErrorCode::InvalidRequest);
        };
        match slot.put_for_peers(&recipients, &payload).await {
            Ok(_) => AgentResponse::Ok(OkResponse { id }),
            Err(_) => AgentResponse::error(Some(id), ErrorCode::TransportFailed),
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

    fn add_peer(&self, card: &str) -> anyhow::Result<PeerCard> {
        let card = PeerCard::import_string(card.trim()).context("invalid peer card")?;
        self.namespace
            .trust_peer(TrustedPeer::try_from_card(card.clone()).context("invalid peer card")?)
            .context("failed to trust peer")?;
        Ok(card)
    }

    fn find_peer(&self, peer_id: &str) -> Option<PeerCard> {
        let peer_id = parse_peer_id(peer_id).ok()?;
        self.namespace
            .trusted_peers()
            .into_iter()
            .find(|peer| peer.peer_id == peer_id)
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
    AddPeer {
        id: String,
        card: String,
    },
    RemovePeer {
        id: String,
        peer_id: String,
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

fn validate_transport_flags(flags: &[TransportFlag]) -> anyhow::Result<()> {
    for flag in flags {
        if !flag.enabled() {
            bail!("{} transport feature is not enabled", flag.as_str());
        }
    }
    Ok(())
}

fn load_file_config(path: &PathBuf) -> anyhow::Result<FileConfig> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&value).with_context(|| format!("failed to parse {}", path.display()))
}

fn load_config_seed(arg: Option<&SecretArg>, file: &FileConfig) -> anyhow::Result<[u8; 32]> {
    if let Some(arg) = arg {
        return load_seed(arg);
    }
    match (&file.seed, &file.seed_file) {
        (Some(_), Some(_)) => bail!("seed and seed_file are mutually exclusive"),
        (Some(seed), None) => parse_hex_seed(seed.trim()),
        (None, Some(path)) => parse_hex_seed(load_secret_file(path)?.trim()),
        (None, None) => bail!("seed is required"),
    }
}

fn load_config_token(arg: Option<&SecretArg>, file: &FileConfig) -> anyhow::Result<Option<String>> {
    if let Some(arg) = arg {
        return load_secret(arg).map(Some);
    }
    match (&file.token, &file.token_file) {
        (Some(_), Some(_)) => bail!("token and token_file are mutually exclusive"),
        (Some(token), None) => Ok(Some(token.clone())),
        (None, Some(path)) => load_secret_file(path).map(Some),
        (None, None) => Ok(None),
    }
}

fn load_config_peers(cli: &[SecretArg], file: &FileConfig) -> anyhow::Result<Vec<PeerCard>> {
    if cli.is_empty() {
        return file
            .peers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|peer| load_peer_card(&SecretArg(peer.clone())))
            .collect();
    }
    cli.iter().map(load_peer_card).collect()
}

fn load_seed(arg: &SecretArg) -> anyhow::Result<[u8; 32]> {
    let value = load_secret(arg)?;
    parse_hex_seed(value.trim())
}

fn load_secret(arg: &SecretArg) -> anyhow::Result<String> {
    let path = PathBuf::from(&arg.0);
    if path.exists() {
        return load_secret_file(&path);
    }
    Ok(arg.0.clone())
}

fn load_secret_file(path: &PathBuf) -> anyhow::Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))
        .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
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

fn parse_peer_id(value: &str) -> anyhow::Result<PeerId> {
    if value.len() != 64 {
        bail!("peer id must be 32 bytes encoded as 64 hex characters");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("peer id must be lowercase hex");
    }

    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).context("peer id is not utf-8")?;
        bytes[index] = u8::from_str_radix(text, 16).context("peer id must be lowercase hex")?;
    }
    Ok(PeerId::from_bytes(bytes))
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
    enlace::guard::validate_channel_name(value).is_err()
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
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    use tower::ServiceExt as _;

    fn config(token: Option<&str>) -> AgentConfig {
        AgentConfig {
            seed: [1; 32],
            token: token.map(str::to_owned),
            listen_ws: Some("127.0.0.1:0".parse().unwrap()),
            listen_unix: None,
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
                listen_unix: None,
                peers,
                transports: vec!["http"],
                relay: None,
                data_dir: None,
                log: "info".to_owned(),
            },
            namespace: Arc::new(namespace),
        }
    }

    fn session() -> (Session, mpsc::Receiver<AgentResponse>) {
        let (tx, rx) = mpsc::channel(SESSION_BUFFER);
        (Session::new(tx), rx)
    }

    fn temp_path_for_test(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "enlace-agent-{name}-{}-{suffix}",
            std::process::id()
        ))
    }

    fn local_ws_addr_for_test() -> SocketAddr {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap()
    }

    async fn connect_ws_for_test(
        addr: SocketAddr,
        token: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let uri = format!("ws://{addr}/");
        for _ in 0..50 {
            let mut request = uri.as_str().into_client_request().unwrap();
            request
                .headers_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            match tokio_tungstenite::connect_async(request).await {
                Ok((stream, _response)) => return stream,
                Err(tokio_tungstenite::tungstenite::Error::Io(err))
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(err) => panic!("failed to connect websocket: {err}"),
            }
        }
        panic!("timed out waiting for websocket");
    }

    #[cfg(all(feature = "unix-socket", unix))]
    async fn connect_unix_for_test(path: &std::path::Path) -> UnixStream {
        for _ in 0..50 {
            match UnixStream::connect(path).await {
                Ok(stream) => return stream,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(err) => panic!("failed to connect unix socket: {err}"),
            }
        }
        panic!("timed out waiting for unix socket");
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
    async fn subscribe_rejects_invalid_channel() {
        let state = state([1; 32], Vec::new(), InMemoryTransport::new()).await;
        let (session, _rx) = session();
        let response = state
            .handle_text(
                r#"{"id":"sub","type":"subscribe","channel":"Bad"}"#,
                &session,
            )
            .await;

        let AgentResponse::Error(error) = response else {
            panic!("expected error response");
        };
        assert_eq!(error.id.as_deref(), Some("sub"));
        assert!(matches!(error.code, ErrorCode::InvalidRequest));
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

    #[tokio::test]
    async fn websocket_stream_receives_subscription_events() {
        let transport = InMemoryTransport::new();
        let alice_identity = derive_identity(&[1; 32]).unwrap();
        let bob_identity = derive_identity(&[2; 32]).unwrap();
        let alice_card = alice_identity.card();
        let bob_card = bob_identity.card();
        let alice = state([1; 32], vec![bob_card.clone()], transport.clone()).await;
        let mut bob = state([2; 32], vec![alice_card.clone()], transport).await;
        bob.config.token = Some("secret".to_owned());
        let addr = local_ws_addr_for_test();
        let task = tokio::spawn(run_ws(Arc::new(bob), addr));
        let mut socket = connect_ws_for_test(addr, "secret").await;

        socket
            .send(WsMessage::Text(
                r#"{"id":"sub","type":"subscribe","channel":"default"}"#.into(),
            ))
            .await
            .unwrap();
        let Some(Ok(WsMessage::Text(text))) = socket.next().await else {
            panic!("expected subscribe response");
        };
        let json = serde_json::from_str::<serde_json::Value>(&text).unwrap();
        assert_eq!(json["type"], "ok");
        assert_eq!(json["id"], "sub");

        tokio::task::yield_now().await;
        let (session, _rx) = session();
        let request = serde_json::json!({
            "id": "send",
            "type": "send",
            "to": bob_card.peer_id.to_string(),
            "channel": "default",
            "payload": encode_payload(b"hello")
        });
        let response = alice.handle_text(&request.to_string(), &session).await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        let Some(Ok(WsMessage::Text(text))) = socket.next().await else {
            panic!("expected message event");
        };
        let json = serde_json::from_str::<serde_json::Value>(&text).unwrap();
        assert_eq!(json["type"], "message");
        assert_eq!(json["from"], alice_card.peer_id.to_string());
        assert_eq!(json["channel"], "default");
        assert_eq!(json["payload"], encode_payload(b"hello"));

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn websocket_listener_stops_on_shutdown() {
        let mut state = state([1; 32], Vec::new(), InMemoryTransport::new()).await;
        state.config.token = Some("secret".to_owned());
        let addr = local_ws_addr_for_test();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_ws_until(Arc::new(state), addr, shutdown_rx));
        let socket = connect_ws_for_test(addr, "secret").await;
        drop(socket);

        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();

        result.unwrap();
    }

    #[cfg(all(feature = "unix-socket", unix))]
    #[tokio::test]
    async fn unix_socket_accepts_health_request() {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

        let state = Arc::new(state([1; 32], Vec::new(), InMemoryTransport::new()).await);
        let path = temp_path_for_test("health.sock");
        let task = tokio::spawn(run_unix(Arc::clone(&state), path.clone()));

        let mut stream = connect_unix_for_test(&path).await;
        stream
            .write_all(br#"{"id":"health","type":"health"}"#)
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut line = String::new();
        let mut reader = BufReader::new(stream);
        reader.read_line(&mut line).await.unwrap();
        let json = serde_json::from_str::<serde_json::Value>(&line).unwrap();

        assert_eq!(json["type"], "health");
        assert_eq!(json["id"], "health");
        task.abort();
        let _ = task.await;
        let _ = std::fs::remove_file(path);
    }

    #[cfg(all(feature = "unix-socket", unix))]
    #[tokio::test]
    async fn unix_socket_stream_receives_subscription_events() {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

        let transport = InMemoryTransport::new();
        let alice_identity = derive_identity(&[1; 32]).unwrap();
        let bob_identity = derive_identity(&[2; 32]).unwrap();
        let alice_card = alice_identity.card();
        let bob_card = bob_identity.card();
        let alice = state([1; 32], vec![bob_card.clone()], transport.clone()).await;
        let bob = Arc::new(state([2; 32], vec![alice_card.clone()], transport).await);
        let path = temp_path_for_test("stream.sock");
        let task = tokio::spawn(run_unix(Arc::clone(&bob), path.clone()));

        let mut stream = connect_unix_for_test(&path).await;
        stream
            .write_all(br#"{"id":"sub","type":"subscribe","channel":"default"}"#)
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let json = serde_json::from_str::<serde_json::Value>(&line).unwrap();
        assert_eq!(json["type"], "ok");
        assert_eq!(json["id"], "sub");

        tokio::task::yield_now().await;
        let (session, _rx) = session();
        let request = serde_json::json!({
            "id": "send",
            "type": "send",
            "to": bob_card.peer_id.to_string(),
            "channel": "default",
            "payload": encode_payload(b"hello")
        });
        let response = alice.handle_text(&request.to_string(), &session).await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let json = serde_json::from_str::<serde_json::Value>(&line).unwrap();
        assert_eq!(json["type"], "message");
        assert_eq!(json["from"], alice_card.peer_id.to_string());
        assert_eq!(json["channel"], "default");
        assert_eq!(json["payload"], encode_payload(b"hello"));

        task.abort();
        let _ = task.await;
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn non_loopback_listener_requires_token() {
        let cli = Cli {
            config: None,
            seed: Some(SecretArg("01".repeat(32))),
            token: None,
            listen_ws: Some("0.0.0.0:3000".parse().unwrap()),
            listen_unix: None,
            peer: Vec::new(),
            transport: Vec::new(),
            relay: None,
            data_dir: None,
            log: None,
        };

        let Err(err) = cli.load() else {
            panic!("expected config error");
        };

        assert!(err.to_string().contains("requires --token"));
    }

    #[test]
    fn websocket_listener_requires_token() {
        let cli = Cli {
            config: None,
            seed: Some(SecretArg("01".repeat(32))),
            token: None,
            listen_ws: Some("127.0.0.1:3000".parse().unwrap()),
            listen_unix: None,
            peer: Vec::new(),
            transport: Vec::new(),
            relay: None,
            data_dir: None,
            log: None,
        };

        let Err(err) = cli.load() else {
            panic!("expected config error");
        };

        assert_eq!(err.to_string(), "websocket listener requires --token");
    }

    #[test]
    fn config_file_supplies_agent_options() {
        let config_path = temp_path_for_test("agent.toml");
        let seed_path = temp_path_for_test("seed");
        let token_path = temp_path_for_test("token");
        let data_dir = temp_path_for_test("data");
        std::fs::write(&seed_path, "01".repeat(32)).unwrap();
        std::fs::write(&token_path, "file-token\n").unwrap();
        std::fs::write(
            &config_path,
            format!(
                r#"
seed_file = "{}"
token_file = "{}"
listen_ws = "127.0.0.1:3000"
data_dir = "{}"
relay = "https://relay.example.com"
log = "debug"
"#,
                seed_path.display(),
                token_path.display(),
                data_dir.display()
            ),
        )
        .unwrap();

        let config = Cli {
            config: Some(config_path.clone()),
            seed: None,
            token: None,
            listen_ws: None,
            listen_unix: None,
            peer: Vec::new(),
            transport: Vec::new(),
            relay: None,
            data_dir: None,
            log: None,
        }
        .load()
        .unwrap();

        assert_eq!(config.seed, [1; 32]);
        assert_eq!(config.token.as_deref(), Some("file-token"));
        assert_eq!(config.listen_ws, Some("127.0.0.1:3000".parse().unwrap()));
        assert_eq!(config.data_dir.as_deref(), Some(data_dir.as_path()));
        assert_eq!(config.relay.as_deref(), Some("https://relay.example.com"));
        assert_eq!(config.log, "debug");
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(seed_path);
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn cli_flags_override_config_file() {
        let config_path = temp_path_for_test("agent.toml");
        let seed_path = temp_path_for_test("seed");
        let token_path = temp_path_for_test("token");
        let config_data_dir = temp_path_for_test("config-data");
        let cli_data_dir = temp_path_for_test("cli-data");
        std::fs::write(&seed_path, "01".repeat(32)).unwrap();
        std::fs::write(&token_path, "file-token").unwrap();
        std::fs::write(
            &config_path,
            format!(
                r#"
seed_file = "{}"
token_file = "{}"
listen_ws = "127.0.0.1:3000"
data_dir = "{}"
relay = "https://relay.example.com"
log = "debug"
"#,
                seed_path.display(),
                token_path.display(),
                config_data_dir.display()
            ),
        )
        .unwrap();

        let config = Cli {
            config: Some(config_path.clone()),
            seed: Some(SecretArg("02".repeat(32))),
            token: Some(SecretArg("cli-token".to_owned())),
            listen_ws: Some("127.0.0.1:4000".parse().unwrap()),
            listen_unix: None,
            peer: Vec::new(),
            transport: Vec::new(),
            relay: Some("https://cli-relay.example.com".to_owned()),
            data_dir: Some(cli_data_dir.clone()),
            log: Some("trace".to_owned()),
        }
        .load()
        .unwrap();

        assert_eq!(config.seed, [2; 32]);
        assert_eq!(config.token.as_deref(), Some("cli-token"));
        assert_eq!(config.listen_ws, Some("127.0.0.1:4000".parse().unwrap()));
        assert_eq!(config.data_dir.as_deref(), Some(cli_data_dir.as_path()));
        assert_eq!(
            config.relay.as_deref(),
            Some("https://cli-relay.example.com")
        );
        assert_eq!(config.log, "trace");
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(seed_path);
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn explicit_unavailable_transport_is_rejected() {
        let Some(flag) = [
            TransportFlag::Http,
            TransportFlag::Dht,
            TransportFlag::Pkarr,
            TransportFlag::Iroh,
        ]
        .into_iter()
        .find(|flag| !flag.enabled()) else {
            return;
        };
        let name = flag.as_str();
        let cli = Cli {
            config: None,
            seed: Some(SecretArg("01".repeat(32))),
            token: Some(SecretArg("secret".to_owned())),
            listen_ws: Some("127.0.0.1:3000".parse().unwrap()),
            listen_unix: None,
            peer: Vec::new(),
            transport: vec![flag],
            relay: None,
            data_dir: None,
            log: None,
        };

        let Err(err) = cli.load() else {
            panic!("expected config error");
        };

        let message = err.to_string();
        assert!(message.contains(name));
        assert!(message.contains("not enabled"));
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
    async fn add_peer_updates_live_trust_set() {
        let transport = InMemoryTransport::new();
        let alice_identity = derive_identity(&[1; 32]).unwrap();
        let bob_identity = derive_identity(&[2; 32]).unwrap();
        let alice_card = alice_identity.card();
        let bob_card = bob_identity.card();
        let alice = state([1; 32], Vec::new(), transport.clone()).await;
        let bob = state([2; 32], vec![alice_card.clone()], transport).await;
        let (alice_session, _alice_rx) = session();
        let (bob_session, mut bob_rx) = session();

        let add = serde_json::json!({
            "id": "add",
            "type": "add_peer",
            "card": bob_card.export_string()
        });
        let response = alice.handle_text(&add.to_string(), &alice_session).await;
        let AgentResponse::PeerCard(card) = response else {
            panic!("expected peer card response");
        };
        assert_eq!(card.id, "add");
        assert_eq!(card.peer_id, bob_card.peer_id.to_string());

        let response = bob
            .handle_text(
                r#"{"id":"sub","type":"subscribe","channel":"default"}"#,
                &bob_session,
            )
            .await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        let send = serde_json::json!({
            "id": "send",
            "type": "send",
            "to": bob_card.peer_id.to_string(),
            "channel": "default",
            "payload": encode_payload(b"hello")
        });
        let response = alice.handle_text(&send.to_string(), &alice_session).await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        let Some(AgentResponse::Message(message)) = bob_rx.recv().await else {
            panic!("expected message event");
        };
        assert_eq!(message.from, alice_card.peer_id.to_string());
        assert_eq!(message.payload, encode_payload(b"hello"));
    }

    #[tokio::test]
    async fn remove_peer_deletes_live_trust_entry() {
        let transport = InMemoryTransport::new();
        let bob_identity = derive_identity(&[2; 32]).unwrap();
        let bob_card = bob_identity.card();
        let alice = state([1; 32], vec![bob_card.clone()], transport).await;
        let (session, _rx) = session();

        let remove = serde_json::json!({
            "id": "remove",
            "type": "remove_peer",
            "peer_id": bob_card.peer_id.to_string()
        });
        let response = alice.handle_text(&remove.to_string(), &session).await;
        assert!(matches!(response, AgentResponse::Ok(_)));

        let response = alice
            .handle_text(r#"{"id":"peers","type":"list_peers"}"#, &session)
            .await;
        let AgentResponse::Peers(peers) = response else {
            panic!("expected peers response");
        };
        assert!(peers.peers.is_empty());

        let send = serde_json::json!({
            "id": "send",
            "type": "send",
            "to": bob_card.peer_id.to_string(),
            "channel": "default",
            "payload": encode_payload(b"hello")
        });
        let response = alice.handle_text(&send.to_string(), &session).await;
        let AgentResponse::Error(error) = response else {
            panic!("expected error response");
        };
        assert!(matches!(error.code, ErrorCode::InvalidRequest));
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
