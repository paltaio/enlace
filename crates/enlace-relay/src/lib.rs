#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue,
};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{options, post, put};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use clap::Parser;

const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 7777);
const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_WAIT_SECONDS: u64 = 30;
const DEFAULT_MAILBOX_CAPACITY: usize = 128;
const DEFAULT_MAILBOX_TTL_SECONDS: u64 = 60 * 60;
const DEFAULT_SLOT_TTL_SECONDS: u64 = 24 * 60 * 60;
const VERSION_HEADER: &str = "x-enlace-version";
const OCTET_STREAM: &str = "application/octet-stream";
const TEXT_PLAIN: &str = "text/plain; charset=utf-8";
const CORS_METHODS: &str = "GET, POST, PUT, OPTIONS";
const CORS_HEADERS: &str = "Content-Type, Authorization, X-Enlace-Version";

#[derive(Parser, Debug)]
pub struct Cli {
    #[arg(long, default_value_t = DEFAULT_LISTEN)]
    listen: SocketAddr,
    #[arg(long)]
    auth: Option<String>,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long)]
    persist: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_MAX_BODY_BYTES)]
    max_body_bytes: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_WAIT_SECONDS)]
    max_wait_seconds: u64,
    #[arg(long, default_value_t = DEFAULT_MAILBOX_CAPACITY)]
    mailbox_capacity: usize,
    #[arg(long, default_value_t = DEFAULT_MAILBOX_TTL_SECONDS)]
    mailbox_ttl_seconds: u64,
    #[arg(long, default_value_t = DEFAULT_SLOT_TTL_SECONDS)]
    slot_ttl_seconds: u64,
}

#[derive(Debug)]
pub struct RelayConfig {
    listen: SocketAddr,
    auth: Option<String>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    persist: Option<PathBuf>,
    max_body_bytes: usize,
    max_wait: Duration,
    mailbox_capacity: usize,
    mailbox_ttl: Duration,
    slot_ttl: Duration,
}

impl RelayConfig {
    pub fn from_cli(cli: Cli) -> Result<Self> {
        let auth = cli
            .auth
            .or_else(|| std::env::var("ENLACE_RELAY_AUTH").ok())
            .map(auth_header)
            .transpose()?;

        if cli.cert.is_some() != cli.key.is_some() {
            bail!("--cert and --key must be provided together");
        }

        Ok(Self {
            listen: cli.listen,
            auth,
            cert: cli.cert,
            key: cli.key,
            persist: cli.persist,
            max_body_bytes: cli.max_body_bytes,
            max_wait: Duration::from_secs(cli.max_wait_seconds),
            mailbox_capacity: cli.mailbox_capacity.max(1),
            mailbox_ttl: Duration::from_secs(cli.mailbox_ttl_seconds),
            slot_ttl: Duration::from_secs(cli.slot_ttl_seconds),
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    tables: Arc<Mutex<Tables>>,
    mailbox_notify: Arc<tokio::sync::Notify>,
    slot_notify: Arc<tokio::sync::Notify>,
    auth: Option<String>,
    persist: Option<PersistentSlots>,
    max_body_bytes: usize,
    max_wait: Duration,
    mailbox_capacity: usize,
    mailbox_ttl: Duration,
    slot_ttl: Duration,
}

#[derive(Default)]
struct Tables {
    mailboxes: HashMap<RelayId, VecDeque<MailboxEntry>>,
    slots: HashMap<RelayId, SlotEntry>,
}

#[derive(Clone)]
struct MailboxEntry {
    body: Vec<u8>,
    expires_at: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SlotEntry {
    version: u64,
    body: Vec<u8>,
    expires_at: SystemTime,
}

#[derive(Clone)]
struct PersistentSlots {
    db: sled::Db,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RelayId(String);

enum PutOutcome {
    Stored,
    Stale,
}

pub async fn run_from_env() -> Result<()> {
    run(Cli::parse()).await
}

pub async fn run(cli: Cli) -> Result<()> {
    let config = RelayConfig::from_cli(cli)?;
    let listen = config.listen;
    let cert = config.cert.clone();
    let key = config.key.clone();
    let app = build_router(config).await?;

    if let (Some(cert), Some(key)) = (cert, key) {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .context("loading rustls certificate and key")?;
        axum_server::bind_rustls(listen, tls)
            .serve(app.into_make_service())
            .await
            .context("serving TLS relay")?;
    } else {
        axum_server::bind(listen)
            .serve(app.into_make_service())
            .await
            .context("serving relay")?;
    }

    Ok(())
}

pub async fn build_router(config: RelayConfig) -> Result<Router> {
    let (persist, slots) = match config.persist {
        Some(path) => {
            let (persist, slots) = PersistentSlots::open(path).await?;
            (Some(persist), slots)
        }
        None => (None, HashMap::new()),
    };

    let state = AppState {
        tables: Arc::new(Mutex::new(Tables {
            mailboxes: HashMap::new(),
            slots,
        })),
        mailbox_notify: Arc::new(tokio::sync::Notify::new()),
        slot_notify: Arc::new(tokio::sync::Notify::new()),
        auth: config.auth,
        persist,
        max_body_bytes: config.max_body_bytes,
        max_wait: config.max_wait,
        mailbox_capacity: config.mailbox_capacity,
        mailbox_ttl: config.mailbox_ttl,
        slot_ttl: config.slot_ttl,
    };

    Ok(Router::new()
        .route(
            "/m/{id}",
            post(mailbox_enqueue)
                .get(mailbox_dequeue)
                .options(preflight),
        )
        .route("/s/{id}", put(slot_write).get(slot_read).options(preflight))
        .route("/{*path}", options(preflight))
        .with_state(state))
}

async fn mailbox_enqueue(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    if !check_auth(&state, &headers) {
        return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(id) = RelayId::parse(&id) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed id");
    };
    let Ok(body) = bounded_body(body, state.max_body_bytes).await else {
        return text_response(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
    };

    match state.push_mailbox(id, body) {
        Ok(()) => {
            state.mailbox_notify.notify_waiters();
            empty_response(StatusCode::NO_CONTENT)
        }
        Err(()) => server_error(),
    }
}

async fn mailbox_dequeue(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    if !check_auth(&state, &headers) {
        return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(id) = RelayId::parse(&id) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed id");
    };
    let Ok(wait) = parse_wait(&query, state.max_wait) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed wait");
    };

    let deadline = Instant::now() + wait;
    loop {
        let notified = state.mailbox_notify.notified();
        match state.pop_mailbox(&id) {
            Ok(Some(body)) => return octet_response(StatusCode::OK, body, None),
            Ok(None) => {}
            Err(()) => return server_error(),
        }

        let Some(remaining) = remaining(wait, deadline) else {
            return empty_response(StatusCode::NO_CONTENT);
        };

        if tokio::time::timeout(remaining, notified).await.is_err() {
            return empty_response(StatusCode::NO_CONTENT);
        }
    }
}

async fn slot_write(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    if !check_auth(&state, &headers) {
        return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(id) = RelayId::parse(&id) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed id");
    };
    let Ok(version) = parse_version(&headers) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed version");
    };
    let Ok(body) = bounded_body(body, state.max_body_bytes).await else {
        return text_response(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
    };
    let slot = SlotEntry {
        version,
        body,
        expires_at: SystemTime::now() + state.slot_ttl,
    };

    match state.put_slot(id.clone(), slot.clone()) {
        Ok(PutOutcome::Stored) => {}
        Ok(PutOutcome::Stale) => return text_response(StatusCode::CONFLICT, "stale version"),
        Err(()) => return server_error(),
    }

    if let Some(persist) = state.persist.as_ref()
        && persist.insert(id, slot).await.is_err()
    {
        return server_error();
    }

    state.slot_notify.notify_waiters();
    empty_response(StatusCode::NO_CONTENT)
}

async fn slot_read(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    if !check_auth(&state, &headers) {
        return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(id) = RelayId::parse(&id) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed id");
    };
    let Ok(since) = parse_since(&query) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed since");
    };
    let Ok(wait) = parse_wait(&query, state.max_wait) else {
        return text_response(StatusCode::BAD_REQUEST, "malformed wait");
    };

    let deadline = Instant::now() + wait;
    loop {
        let notified = state.slot_notify.notified();
        match state.get_slot_newer(&id, since) {
            Ok(Some(slot)) => {
                return octet_response(StatusCode::OK, slot.body, Some(slot.version));
            }
            Ok(None) => {}
            Err(()) => return server_error(),
        }

        let Some(remaining) = remaining(wait, deadline) else {
            return empty_response(StatusCode::NO_CONTENT);
        };

        if tokio::time::timeout(remaining, notified).await.is_err() {
            return empty_response(StatusCode::NO_CONTENT);
        }
    }
}

async fn preflight() -> Response<Body> {
    empty_response(StatusCode::NO_CONTENT)
}

impl AppState {
    fn push_mailbox(&self, id: RelayId, body: Vec<u8>) -> Result<(), ()> {
        let mut tables = self.tables.lock().map_err(|_| ())?;
        let queue = tables.mailboxes.entry(id).or_default();
        while queue.len() >= self.mailbox_capacity {
            queue.pop_front();
        }
        queue.push_back(MailboxEntry {
            body,
            expires_at: SystemTime::now() + self.mailbox_ttl,
        });
        Ok(())
    }

    fn pop_mailbox(&self, id: &RelayId) -> Result<Option<Vec<u8>>, ()> {
        let mut tables = self.tables.lock().map_err(|_| ())?;
        let Some(queue) = tables.mailboxes.get_mut(id) else {
            return Ok(None);
        };

        let mut body = None;
        while let Some(entry) = queue.pop_front() {
            if !entry.expired() {
                body = Some(entry.body);
                break;
            }
        }
        let remove_empty = queue.is_empty();
        if remove_empty {
            tables.mailboxes.remove(id);
        }
        Ok(body)
    }

    fn put_slot(&self, id: RelayId, slot: SlotEntry) -> Result<PutOutcome, ()> {
        let mut tables = self.tables.lock().map_err(|_| ())?;
        if tables
            .slots
            .get(&id)
            .is_some_and(|current| !current.expired() && current.version >= slot.version)
        {
            return Ok(PutOutcome::Stale);
        }
        tables.slots.insert(id, slot);
        Ok(PutOutcome::Stored)
    }

    fn get_slot_newer(&self, id: &RelayId, since: u64) -> Result<Option<SlotEntry>, ()> {
        let mut tables = self.tables.lock().map_err(|_| ())?;
        let Some(slot) = tables.slots.get(id) else {
            return Ok(None);
        };
        if slot.expired() {
            tables.slots.remove(id);
            return Ok(None);
        }
        Ok((slot.version > since).then(|| slot.clone()))
    }
}

impl MailboxEntry {
    fn expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }
}

impl SlotEntry {
    fn expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }
}

impl PersistentSlots {
    async fn open(path: PathBuf) -> Result<(Self, HashMap<RelayId, SlotEntry>)> {
        tokio::task::spawn_blocking(move || {
            let db = sled::open(path).context("opening slot store")?;
            let mut slots = HashMap::new();
            let mut expired = Vec::new();

            for item in db.iter() {
                let (key, value) = item.context("reading persisted slot")?;
                let Some(id) = std::str::from_utf8(&key).ok().and_then(RelayId::valid) else {
                    continue;
                };
                let Some(slot) = decode_slot(&value) else {
                    continue;
                };
                if slot.expired() {
                    expired.push(key);
                } else {
                    slots.insert(id, slot);
                }
            }

            for key in expired {
                db.remove(key).context("removing expired persisted slot")?;
            }
            db.flush().context("flushing slot store")?;

            Ok((Self { db }, slots))
        })
        .await
        .context("joining slot store opener")?
    }

    async fn insert(&self, id: RelayId, slot: SlotEntry) -> Result<()> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            db.insert(id.as_str().as_bytes(), encode_slot(&slot))
                .context("persisting slot")?;
            db.flush().context("flushing slot store")?;
            Ok(())
        })
        .await
        .context("joining slot store writer")?
    }
}

impl RelayId {
    fn parse(raw: &str) -> Result<Self, ()> {
        Self::valid(raw).ok_or(())
    }

    fn valid(raw: &str) -> Option<Self> {
        (raw.len() == 32
            && raw
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
        .then(|| Self(raw.to_owned()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn auth_header(raw: String) -> Result<String> {
    if !raw.contains(':') {
        bail!("auth must be formatted as user:pass");
    }
    Ok(format!("Basic {}", BASE64_STANDARD.encode(raw)))
}

fn check_auth(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.auth.as_deref() else {
        return true;
    };
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected)
}

async fn bounded_body(body: Body, max_body_bytes: usize) -> Result<Vec<u8>, ()> {
    to_bytes(body, max_body_bytes)
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|_| ())
}

fn parse_wait(query: &HashMap<String, String>, max_wait: Duration) -> Result<Duration, ()> {
    parse_query_u64(query, "wait").map(|seconds| Duration::from_secs(seconds).min(max_wait))
}

fn parse_since(query: &HashMap<String, String>) -> Result<u64, ()> {
    parse_query_u64(query, "since")
}

fn parse_query_u64(query: &HashMap<String, String>, key: &str) -> Result<u64, ()> {
    query
        .get(key)
        .map_or(Ok(0), |value| value.parse().map_err(|_| ()))
}

fn parse_version(headers: &HeaderMap) -> Result<u64, ()> {
    headers
        .get(VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or(())
}

fn remaining(wait: Duration, deadline: Instant) -> Option<Duration> {
    if wait.is_zero() {
        return None;
    }
    deadline.checked_duration_since(Instant::now())
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(TEXT_PLAIN));
    finish(response)
}

fn server_error() -> Response<Body> {
    finish((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
}

fn empty_response(status: StatusCode) -> Response<Body> {
    finish(status.into_response())
}

fn octet_response(status: StatusCode, body: Vec<u8>, version: Option<u64>) -> Response<Body> {
    let mut response = Response::builder()
        .status(status)
        .body(Body::from(body))
        .expect("response builder accepts valid status and body");
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(OCTET_STREAM));
    if let Some(version) = version {
        let value = HeaderValue::from_str(&version.to_string())
            .expect("u64 string is a valid header value");
        headers.insert(VERSION_HEADER, value);
    }
    finish(response)
}

fn finish(mut response: Response<Body>) -> Response<Body> {
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(CORS_METHODS),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(CORS_HEADERS),
    );
    response
}

fn encode_slot(slot: &SlotEntry) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(16 + slot.body.len());
    encoded.extend_from_slice(&slot.version.to_be_bytes());
    encoded.extend_from_slice(&unix_secs(slot.expires_at).to_be_bytes());
    encoded.extend_from_slice(&slot.body);
    encoded
}

fn decode_slot(raw: &[u8]) -> Option<SlotEntry> {
    let version = u64::from_be_bytes(raw.get(..8)?.try_into().ok()?);
    let expires_at = u64::from_be_bytes(raw.get(8..16)?.try_into().ok()?);
    let body = raw.get(16..)?.to_vec();
    Some(SlotEntry {
        version,
        body,
        expires_at: UNIX_EPOCH + Duration::from_secs(expires_at),
    })
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn test_config() -> RelayConfig {
        RelayConfig {
            listen: DEFAULT_LISTEN,
            auth: None,
            cert: None,
            key: None,
            persist: None,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_wait: Duration::from_secs(1),
            mailbox_capacity: DEFAULT_MAILBOX_CAPACITY,
            mailbox_ttl: Duration::from_mins(1),
            slot_ttl: Duration::from_mins(1),
        }
    }

    async fn body_bytes(response: Response<Body>) -> Bytes {
        to_bytes(response.into_body(), usize::MAX).await.unwrap()
    }

    #[tokio::test]
    async fn mailbox_roundtrip_pops_once() {
        let app = build_router(test_config()).await.unwrap();
        let post_req = Request::builder()
            .method(Method::POST)
            .uri(format!("/m/{ID}"))
            .body(Body::from("msg-1"))
            .unwrap();
        let response = app.clone().oneshot(post_req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let get_req = Request::builder()
            .uri(format!("/m/{ID}?wait=1"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await, "msg-1");

        let empty_req = Request::builder()
            .uri(format!("/m/{ID}"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(empty_req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn slot_rejects_stale_version() {
        let app = build_router(test_config()).await.unwrap();
        let put_req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/s/{ID}"))
            .header(VERSION_HEADER, "1")
            .body(Body::from("hello"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(put_req).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );

        let stale_req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/s/{ID}"))
            .header(VERSION_HEADER, "1")
            .body(Body::from("oops"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(stale_req).await.unwrap().status(),
            StatusCode::CONFLICT
        );

        let get_req = Request::builder()
            .uri(format!("/s/{ID}?since=0"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(get_req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[VERSION_HEADER], "1");
        assert_eq!(body_bytes(response).await, "hello");
    }

    #[tokio::test]
    async fn malformed_inputs_are_text_errors() {
        let app = build_router(test_config()).await.unwrap();
        let bad_id = Request::builder()
            .uri("/m/not-hex")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(bad_id).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[CONTENT_TYPE], TEXT_PLAIN);

        let non_hex_id = Request::builder()
            .uri("/m/gggggggggggggggggggggggggggggggg")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(non_hex_id).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let bad_wait = Request::builder()
            .uri(format!("/m/{ID}?wait=nope"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(bad_wait).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn auth_and_size_limits_are_enforced() {
        let mut config = test_config();
        config.auth = Some(auth_header("u:p".to_owned()).unwrap());
        config.max_body_bytes = 3;
        let app = build_router(config).await.unwrap();

        let missing_auth = Request::builder()
            .method(Method::POST)
            .uri(format!("/m/{ID}"))
            .body(Body::from("abc"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(missing_auth).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let too_large = Request::builder()
            .method(Method::POST)
            .uri(format!("/m/{ID}"))
            .header(AUTHORIZATION, auth_header("u:p".to_owned()).unwrap())
            .body(Body::from("abcd"))
            .unwrap();
        assert_eq!(
            app.oneshot(too_large).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn options_returns_cors_preflight() {
        let app = build_router(test_config()).await.unwrap();
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("/m/{ID}"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    }

    #[tokio::test]
    async fn persisted_slots_load_on_restart() {
        let path = std::env::temp_dir().join(format!(
            "enlace-relay-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let (persist, _) = PersistentSlots::open(path.clone()).await.unwrap();
        let id = RelayId::parse(ID).unwrap();
        persist
            .insert(
                id.clone(),
                SlotEntry {
                    version: 7,
                    body: b"stored".to_vec(),
                    expires_at: SystemTime::now() + Duration::from_mins(1),
                },
            )
            .await
            .unwrap();
        drop(persist);

        let (_persist, slots) = PersistentSlots::open(path.clone()).await.unwrap();
        assert_eq!(slots.get(&id).unwrap().version, 7);
        assert_eq!(slots.get(&id).unwrap().body, b"stored");

        let _ = std::fs::remove_dir_all(path);
    }
}
