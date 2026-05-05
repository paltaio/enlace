mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use enlace_relay::{RelayConfig, build_router};
use reqwest::{StatusCode, header};
use tokio::task::JoinHandle;

const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct RelayProcess {
    base_url: String,
    task: JoinHandle<()>,
}

impl RelayProcess {
    async fn spawn(config: RelayConfig) -> Self {
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("ephemeral listener binds");
        listener
            .set_nonblocking(true)
            .expect("listener switches to nonblocking");
        let addr = listener.local_addr().expect("listener has local addr");
        let app = build_router(config).await.expect("relay router builds");
        let server = axum_server::from_tcp(listener)
            .expect("server accepts listener")
            .serve(app.into_make_service());
        let task = tokio::spawn(async move {
            let _ = server.await;
        });
        let relay = Self {
            base_url: format!("http://{addr}"),
            task,
        };
        relay.wait_ready().await;
        relay
    }

    async fn wait_ready(&self) {
        let client = support::reqwest_client();
        for _ in 0..20 {
            if client
                .get(format!("{}/m/{ID}", self.base_url))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("relay did not become ready");
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config() -> RelayConfig {
    RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .with_max_body_bytes(3)
        .with_max_wait(Duration::from_secs(1))
}

fn default_config() -> RelayConfig {
    RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .with_max_wait(Duration::from_secs(1))
}

async fn assert_text_error(response: reqwest::Response, status: StatusCode) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert!(!response.bytes().await.expect("error body reads").is_empty());
}

#[tokio::test]
async fn mailbox_status_paths() {
    let relay = RelayProcess::spawn(config()).await;
    let client = support::reqwest_client();

    let response = client
        .post(format!("{}/m/{ID}", relay.base_url))
        .body("abc")
        .send()
        .await
        .expect("mailbox post succeeds");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .post(format!("{}/m/not-hex", relay.base_url))
        .body("abc")
        .send()
        .await
        .expect("bad id request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;

    let response = client
        .post(format!("{}/m/{ID}", relay.base_url))
        .body("abcd")
        .send()
        .await
        .expect("large mailbox post completes");
    assert_text_error(response, StatusCode::PAYLOAD_TOO_LARGE).await;

    let response = client
        .get(format!("{}/m/{ID}?wait=1", relay.base_url))
        .send()
        .await
        .expect("mailbox get succeeds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.expect("mail body reads"), "abc");

    let response = client
        .get(format!("{}/m/{ID}?wait=0", relay.base_url))
        .send()
        .await
        .expect("empty mailbox get succeeds");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .get(format!("{}/m/not-hex", relay.base_url))
        .send()
        .await
        .expect("bad id request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;

    let response = client
        .get(format!("{}/m/{ID}?wait=nope", relay.base_url))
        .send()
        .await
        .expect("bad wait request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;
}

#[tokio::test]
async fn slot_status_paths() {
    let relay = RelayProcess::spawn(config()).await;
    let client = support::reqwest_client();

    let response = client
        .put(format!("{}/s/{ID}", relay.base_url))
        .body("abc")
        .send()
        .await
        .expect("missing version request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;

    let response = client
        .put(format!("{}/s/{ID}", relay.base_url))
        .header("x-enlace-version", "nope")
        .body("abc")
        .send()
        .await
        .expect("bad version request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;

    let response = client
        .put(format!("{}/s/{ID}", relay.base_url))
        .header("x-enlace-version", "1")
        .body("abcd")
        .send()
        .await
        .expect("large slot put completes");
    assert_text_error(response, StatusCode::PAYLOAD_TOO_LARGE).await;

    let response = client
        .put(format!("{}/s/{ID}", relay.base_url))
        .header("x-enlace-version", "1")
        .body("abc")
        .send()
        .await
        .expect("slot put succeeds");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .get(format!("{}/s/{ID}?since=0", relay.base_url))
        .send()
        .await
        .expect("slot get succeeds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-enlace-version"], "1");
    assert_eq!(response.bytes().await.expect("slot body reads"), "abc");

    let response = client
        .get(format!("{}/s/{ID}?since=1", relay.base_url))
        .send()
        .await
        .expect("slot no-content get succeeds");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .put(format!("{}/s/{ID}", relay.base_url))
        .header("x-enlace-version", "1")
        .body("zzz")
        .send()
        .await
        .expect("stale slot put completes");
    assert_text_error(response, StatusCode::CONFLICT).await;

    let response = client
        .get(format!("{}/s/not-hex", relay.base_url))
        .send()
        .await
        .expect("bad slot id request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;

    let response = client
        .get(format!("{}/s/{ID}?since=nope", relay.base_url))
        .send()
        .await
        .expect("bad since request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;

    let response = client
        .get(format!("{}/s/{ID}?wait=nope", relay.base_url))
        .send()
        .await
        .expect("bad wait request completes");
    assert_text_error(response, StatusCode::BAD_REQUEST).await;
}

#[tokio::test]
async fn auth_status_paths() {
    let relay = RelayProcess::spawn(
        config()
            .with_auth("user:pass")
            .expect("auth config accepts user pass"),
    )
    .await;
    let client = support::reqwest_client();

    let response = client
        .get(format!("{}/m/{ID}", relay.base_url))
        .send()
        .await
        .expect("unauthenticated request completes");
    assert_text_error(response, StatusCode::UNAUTHORIZED).await;

    let response = client
        .get(format!("{}/m/{ID}", relay.base_url))
        .basic_auth("user", Some("wrong"))
        .send()
        .await
        .expect("bad auth request completes");
    assert_text_error(response, StatusCode::UNAUTHORIZED).await;

    let response = client
        .get(format!("{}/m/{ID}", relay.base_url))
        .basic_auth("user", Some("pass"))
        .send()
        .await
        .expect("authenticated request completes");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn cors_preflight_path() {
    let relay = RelayProcess::spawn(config()).await;
    let client = support::reqwest_client();

    let response = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/m/{ID}", relay.base_url),
        )
        .send()
        .await
        .expect("preflight completes");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    assert_eq!(
        response.headers()["access-control-allow-methods"],
        "GET, POST, PUT, OPTIONS"
    );
    assert_eq!(
        response.headers()["access-control-allow-headers"],
        "Content-Type, Authorization, X-Enlace-Version"
    );
}

#[tokio::test]
async fn documented_smoke_flow() {
    let relay = RelayProcess::spawn(default_config()).await;
    let client = support::reqwest_client();

    let response = client
        .put(format!("{}/s/{ID}", relay.base_url))
        .header("x-enlace-version", "1")
        .body("hello")
        .send()
        .await
        .expect("slot put succeeds");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .get(format!("{}/s/{ID}?since=0", relay.base_url))
        .send()
        .await
        .expect("slot get succeeds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-enlace-version"], "1");
    assert_eq!(response.bytes().await.expect("slot body reads"), "hello");

    let response = client
        .put(format!("{}/s/{ID}", relay.base_url))
        .header("x-enlace-version", "1")
        .body("oops")
        .send()
        .await
        .expect("stale slot put completes");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let response = client
        .post(format!("{}/m/{ID}", relay.base_url))
        .body("msg-1")
        .send()
        .await
        .expect("mailbox post succeeds");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = client
        .get(format!("{}/m/{ID}?wait=1", relay.base_url))
        .send()
        .await
        .expect("mailbox get succeeds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.expect("mail body reads"), "msg-1");

    let response = client
        .get(format!("{}/m/{ID}?wait=1", relay.base_url))
        .send()
        .await
        .expect("empty mailbox get succeeds");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
