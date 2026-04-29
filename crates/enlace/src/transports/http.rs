use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::config::{BasicAuth, HttpConfig};
use crate::error::TransportError;
use crate::transports::{MailboxTransport, SlotTransport, SlotWatchStream};

const VERSION_HEADER: &str = "x-enlace-version";
const WATCH_BUFFER: usize = 64;

#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: Client,
    base_url: Url,
    auth: Option<BasicAuth>,
    long_poll: Duration,
}

impl HttpTransport {
    pub fn new(config: HttpConfig) -> Result<Self, TransportError> {
        let client = Client::builder()
            .danger_accept_invalid_certs(config.skip_verify)
            .build()
            .map_err(map_reqwest_error)?;
        Ok(Self {
            client,
            base_url: config.url,
            auth: config.auth,
            long_poll: Duration::from_secs(u64::from(config.long_poll_secs)),
        })
    }

    fn request(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(auth) = self.auth.as_ref() {
            builder.basic_auth(&auth.username, Some(&auth.password))
        } else {
            builder
        }
    }

    fn mailbox_url(&self, id: &[u8; 16]) -> Url {
        self.channel_url("m", id)
    }

    fn slot_url(&self, id: &[u8; 16]) -> Url {
        self.channel_url("s", id)
    }

    fn channel_url(&self, prefix: &str, id: &[u8; 16]) -> Url {
        let mut url = self.base_url.clone();
        let base_path = self.base_url.path().trim_end_matches('/');
        let id = hex_id(id);
        let path = if base_path.is_empty() {
            format!("/{prefix}/{id}")
        } else {
            format!("{base_path}/{prefix}/{id}")
        };
        url.set_path(&path);
        url.set_query(None);
        url
    }

    async fn slot_get_since(
        &self,
        id: &[u8; 16],
        since: u64,
        wait: Duration,
    ) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let mut url = self.slot_url(id);
        url.query_pairs_mut()
            .append_pair("since", &since.to_string())
            .append_pair("wait", &wait.as_secs().to_string());
        let response = self
            .request(self.client.get(url))
            .send()
            .await
            .map_err(map_reqwest_error)?;

        match response.status() {
            StatusCode::OK => {
                let version = parse_version(response.headers())?;
                let body = response.bytes().await.map_err(map_reqwest_error)?.to_vec();
                Ok(Some((version, body)))
            }
            StatusCode::NO_CONTENT => Ok(None),
            status => Err(map_status(status)),
        }
    }
}

#[async_trait]
impl MailboxTransport for HttpTransport {
    async fn send(&self, id: &[u8; 16], sealed: &[u8]) -> Result<(), TransportError> {
        let response = self
            .request(
                self.client
                    .post(self.mailbox_url(id))
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .body(sealed.to_vec()),
            )
            .send()
            .await
            .map_err(map_reqwest_error)?;

        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            status => Err(map_status(status)),
        }
    }

    async fn recv(&self, id: &[u8; 16], wait: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        let mut url = self.mailbox_url(id);
        url.query_pairs_mut()
            .append_pair("wait", &wait.as_secs().to_string());
        let response = self
            .request(self.client.get(url))
            .send()
            .await
            .map_err(map_reqwest_error)?;

        match response.status() {
            StatusCode::OK => response
                .bytes()
                .await
                .map(|bytes| Some(bytes.to_vec()))
                .map_err(map_reqwest_error),
            StatusCode::NO_CONTENT => Ok(None),
            status => Err(map_status(status)),
        }
    }
}

#[async_trait]
impl SlotTransport for HttpTransport {
    async fn put(&self, id: &[u8; 16], version: u64, sealed: &[u8]) -> Result<(), TransportError> {
        let response = self
            .request(
                self.client
                    .put(self.slot_url(id))
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .header(VERSION_HEADER, version.to_string())
                    .body(sealed.to_vec()),
            )
            .send()
            .await
            .map_err(map_reqwest_error)?;

        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            status => Err(map_status(status)),
        }
    }

    async fn get(&self, id: &[u8; 16]) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        self.slot_get_since(id, 0, Duration::ZERO).await
    }

    fn watch(&self, id: &[u8; 16], since: u64) -> SlotWatchStream {
        let transport = self.clone();
        let id = *id;
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);

        tokio::spawn(async move {
            let mut since = since;
            loop {
                match transport
                    .slot_get_since(&id, since, transport.long_poll)
                    .await
                {
                    Ok(Some((version, body))) => {
                        since = version;
                        if tx.send(Ok((version, body))).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if tx.send(Err(err)).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}

fn parse_version(headers: &reqwest::header::HeaderMap) -> Result<u64, TransportError> {
    headers
        .get(VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| TransportError::Network("relay omitted slot version".to_owned()))
}

fn map_status(status: StatusCode) -> TransportError {
    match status {
        StatusCode::UNAUTHORIZED => TransportError::Auth,
        StatusCode::CONFLICT => TransportError::Stale,
        StatusCode::PAYLOAD_TOO_LARGE => TransportError::BodyTooLarge,
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => TransportError::Timeout,
        _ => TransportError::Network(format!("relay returned status {status}")),
    }
}

fn map_reqwest_error(err: reqwest::Error) -> TransportError {
    let timed_out = err.is_timeout();
    let message = err.to_string();
    drop(err);
    if timed_out {
        TransportError::Timeout
    } else {
        TransportError::Network(message)
    }
}

fn hex_id(id: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in id {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_id_is_lowercase_32_chars() {
        let id = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        assert_eq!(hex_id(&id), "000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn status_mapping_matches_transport_errors() {
        assert!(matches!(
            map_status(StatusCode::UNAUTHORIZED),
            TransportError::Auth
        ));
        assert!(matches!(
            map_status(StatusCode::CONFLICT),
            TransportError::Stale
        ));
        assert!(matches!(
            map_status(StatusCode::PAYLOAD_TOO_LARGE),
            TransportError::BodyTooLarge
        ));
    }
}
