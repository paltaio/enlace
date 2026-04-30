use std::sync::Arc;

use crate::config::Config;
use crate::coordinator::Coordinator;
use crate::crypto;
use crate::kdf::{ChannelKind, channel_aead_key};
use crate::state::State;
use crate::transports::{
    HealthTracker, decode_empty_response, decode_mailbox_recv_response, decode_slot_get_response,
};

use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

const SEED: [u8; 32] = [0xA5; 32];
const NAME: &str = "fuzz";
const MAX_PLAINTEXT_BYTES: usize = 65_536;

pub fn open_mailbox(data: &[u8]) {
    let config = Config {
        dedup_buffer: 0,
        max_plaintext_bytes: MAX_PLAINTEXT_BYTES,
        ..Config::default()
    };
    let coordinator = Coordinator::new(
        &SEED,
        Vec::new(),
        &config,
        State::memory().store(),
        Arc::new(HealthTracker::from_config(&config)),
    );
    let Some((&mode, bytes)) = data.split_first() else {
        coordinator.open_for_fuzz(ChannelKind::Mailbox, NAME, data);
        return;
    };

    if mode & 1 == 0 {
        coordinator.open_for_fuzz(ChannelKind::Mailbox, NAME, bytes);
        return;
    }

    let Ok(key) = channel_aead_key(&SEED, ChannelKind::Mailbox, NAME) else {
        return;
    };
    let sealed = crypto::seal(&key, &mailbox_aad(), bytes);
    coordinator.open_for_fuzz(ChannelKind::Mailbox, NAME, &sealed);
}

pub fn http_relay_client_response(data: &[u8]) {
    let Some((operation, status, headers, body)) =
        parse_http_response(data).or_else(|| parse_compact_response(data))
    else {
        return;
    };

    match operation % 4 {
        0 | 1 => {
            let _ = decode_empty_response(status);
        }
        2 => {
            let _ = decode_mailbox_recv_response(status, body);
        }
        _ => {
            let _ = decode_slot_get_response(status, &headers, body);
        }
    }
}

fn mailbox_aad() -> Vec<u8> {
    let mut aad = Vec::with_capacity(b"enlace/v1/aead/mailbox/".len() + NAME.len());
    aad.extend_from_slice(b"enlace/v1/aead/mailbox/");
    aad.extend_from_slice(NAME.as_bytes());
    aad
}

fn parse_http_response(data: &[u8]) -> Option<(u8, StatusCode, HeaderMap, Vec<u8>)> {
    let (&operation, response) = data.split_first()?;
    let split_at = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let (head, body) = response.split_at(split_at);
    let body = body.get(4..)?.to_vec();

    let mut lines = head.split(|byte| *byte == b'\n');
    let status = parse_status_line(lines.next()?)?;
    let mut headers = HeaderMap::new();

    for line in lines.take(32) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value) = line.split_at(colon);
        let value = trim_ascii(value.get(1..)?);
        let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        else {
            continue;
        };
        headers.append(name, value);
    }

    Some((operation, status, headers, body))
}

fn parse_compact_response(data: &[u8]) -> Option<(u8, StatusCode, HeaderMap, Vec<u8>)> {
    let (&operation, rest) = data.split_first()?;
    let status_bytes: [u8; 2] = rest.get(..2)?.try_into().ok()?;
    let code = 100 + (u16::from_be_bytes(status_bytes) % 500);
    let status = StatusCode::from_u16(code).ok()?;
    let rest = rest.get(2..)?;
    let mut headers = HeaderMap::new();

    let body = if let Some((&version_len, rest)) = rest.split_first() {
        let version_len = usize::from(version_len).min(rest.len());
        let (version, body) = rest.split_at(version_len);
        if let Ok(value) = HeaderValue::from_bytes(version) {
            headers.insert(HeaderName::from_static("x-enlace-version"), value);
        }
        body.to_vec()
    } else {
        Vec::new()
    };

    Some((operation, status, headers, body))
}

fn parse_status_line(line: &[u8]) -> Option<StatusCode> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line
        .split(u8::is_ascii_whitespace)
        .filter(|part| !part.is_empty());
    let _version = parts.next()?;
    let code = std::str::from_utf8(parts.next()?).ok()?.parse().ok()?;
    StatusCode::from_u16(code).ok()
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = value.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        value = rest;
    }
    while let Some((&last, rest)) = value.split_last() {
        if !last.is_ascii_whitespace() {
            break;
        }
        value = rest;
    }
    value
}
