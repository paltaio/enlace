#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::{
    env,
    error::Error,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use bytes::Bytes;
use pkarr::{
    dns::{
        rdata::{RData, SVCParam, SVCB, TXT},
        Name,
    },
    Client, Keypair, PublicKey, SignedPacket, Timestamp,
};
use serde::{Deserialize, Serialize};

const SECRET_KEY: [u8; 32] = [7; 32];
const TIMESTAMP_MICROS: u64 = 123_456_789;
const LAST_SEEN_MICROS: u64 = 987_654_321;

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct NativeVectors {
    key: KeyVector,
    packet: PacketVector,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct KeyVector {
    secret_key_hex: String,
    public_key_hex: String,
    z32: String,
    uri: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct RecordSummary {
    name: String,
    record_type: String,
    ttl: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct LookupVector {
    name: String,
    names: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct PacketVector {
    timestamp_micros: u64,
    last_seen_micros: u64,
    signature_hex: String,
    signable_hex: String,
    encoded_packet_hex: String,
    signed_packet_hex: String,
    relay_payload_hex: String,
    serialized_hex: String,
    ttl_default: u32,
    ttl_unclamped: u32,
    records: Vec<RecordSummary>,
    lookups: Vec<LookupVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct VerifyTsVector {
    public_key_hex: String,
    packet: TsPacketVector,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct TsPacketVector {
    timestamp_micros: u64,
    signature_hex: String,
    signable_hex: String,
    encoded_packet_hex: String,
    signed_packet_hex: String,
    relay_payload_hex: String,
    ttl_default: u32,
    ttl_unclamped: u32,
    records: Vec<RecordSummary>,
    lookups: Vec<LookupVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct RelayPublishInput {
    relay_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct RelayResolveInput {
    relay_url: String,
    public_key_hex: String,
}

/// Runs the native test harness command.
///
/// # Errors
///
/// Returns an error when input parsing, packet handling, or relay I/O fails.
pub async fn run() -> Result<(), Box<dyn Error>> {
    let command = env::args().nth(1);
    match command.as_deref() {
        Some("vectors") => print_vectors(),
        Some("verify-ts") => verify_ts(),
        Some("publish-relay") => publish_relay().await,
        Some("resolve-relay") => resolve_relay().await,
        _ => Err("usage: pkarr-lite-native <vectors|verify-ts|publish-relay|resolve-relay>".into()),
    }
}

fn print_vectors() -> Result<(), Box<dyn Error>> {
    let keypair = vector_keypair();
    let packet = vector_packet(&keypair)?;
    let vectors = NativeVectors {
        key: KeyVector {
            secret_key_hex: hex::encode(SECRET_KEY),
            public_key_hex: hex::encode(keypair.public_key().as_bytes()),
            z32: keypair.to_z32(),
            uri: keypair.to_uri_string(),
        },
        packet: packet_vector(packet),
    };

    println!("{}", serde_json::to_string_pretty(&vectors)?);
    Ok(())
}

fn verify_ts() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let vector: VerifyTsVector = serde_json::from_str(&input)?;
    let public_key_bytes = hex::decode(&vector.public_key_hex)?;
    let public_key = PublicKey::try_from(public_key_bytes.as_slice())?;
    let relay_payload = Bytes::from(hex::decode(&vector.packet.relay_payload_hex)?);
    let packet = SignedPacket::from_relay_payload(&public_key, &relay_payload)?;

    ensure_eq(
        &hex::encode(packet.as_bytes()),
        &vector.packet.signed_packet_hex,
        "signed packet bytes",
    )?;
    ensure_eq(
        &hex::encode(packet.signature().to_bytes()),
        &vector.packet.signature_hex,
        "signature",
    )?;
    ensure_eq(
        &hex::encode(packet.encoded_packet()),
        &vector.packet.encoded_packet_hex,
        "encoded DNS packet",
    )?;
    ensure_eq(
        &hex::encode(signable(
            vector.packet.timestamp_micros,
            &packet.encoded_packet(),
        )),
        &vector.packet.signable_hex,
        "signable bytes",
    )?;
    ensure_eq(
        &packet.timestamp().as_u64(),
        &vector.packet.timestamp_micros,
        "timestamp",
    )?;
    ensure_eq(
        &packet.ttl(300, 86_400),
        &vector.packet.ttl_default,
        "default TTL",
    )?;
    ensure_eq(
        &packet.ttl(0, 86_400),
        &vector.packet.ttl_unclamped,
        "unclamped TTL",
    )?;
    ensure_eq(
        &record_summaries(&packet),
        &vector.packet.records,
        "resource records",
    )?;
    for lookup in vector.packet.lookups {
        ensure_eq(
            &lookup_names(&packet, &lookup.name),
            &lookup.names,
            &format!("lookup {}", lookup.name),
        )?;
    }

    Ok(())
}

async fn publish_relay() -> Result<(), Box<dyn Error>> {
    let input: RelayPublishInput = read_stdin_json()?;
    let keypair = vector_keypair();
    let packet = vector_packet(&keypair)?;
    let client = relay_client(&input.relay_url)?;

    client.publish(&packet, None).await?;

    let vectors = NativeVectors {
        key: KeyVector {
            secret_key_hex: hex::encode(SECRET_KEY),
            public_key_hex: hex::encode(keypair.public_key().as_bytes()),
            z32: keypair.to_z32(),
            uri: keypair.to_uri_string(),
        },
        packet: packet_vector(packet),
    };
    println!("{}", serde_json::to_string_pretty(&vectors)?);
    Ok(())
}

async fn resolve_relay() -> Result<(), Box<dyn Error>> {
    let input: RelayResolveInput = read_stdin_json()?;
    let public_key_bytes = hex::decode(input.public_key_hex)?;
    let public_key = PublicKey::try_from(public_key_bytes.as_slice())?;
    let client = relay_client(&input.relay_url)?;
    let packet = client
        .resolve(&public_key)
        .await
        .ok_or("native client did not resolve packet")?;

    println!("{}", serde_json::to_string_pretty(&packet_vector(packet))?);
    Ok(())
}

fn read_stdin_json<T: for<'de> Deserialize<'de>>() -> Result<T, Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(serde_json::from_str(&input)?)
}

fn relay_client(relay_url: &str) -> Result<Client, Box<dyn Error>> {
    let mut builder = Client::builder();
    builder.relays(&[relay_url])?;
    Ok(builder.build()?)
}

fn vector_keypair() -> Keypair {
    Keypair::from_secret_key(&SECRET_KEY)
}

fn vector_packet(keypair: &Keypair) -> Result<SignedPacket, Box<dyn Error>> {
    Ok(SignedPacket::builder()
        .address(name(".")?, "1.2.3.4".parse::<IpAddr>()?, 30)
        .address(name("www")?, "::1".parse::<IpAddr>()?, 60)
        .cname(name("alias.")?, name("target.example.com")?, 70)
        .txt(name("_proto")?, TXT::new().with_string("foo=bar")?, 80)
        .https(name(".")?, https_binding()?, 90)
        .svcb(name("_svc")?, svcb_binding()?, 100)
        .timestamp(Timestamp::from(TIMESTAMP_MICROS))
        .sign(keypair)?)
}

fn packet_vector(mut packet: SignedPacket) -> PacketVector {
    packet.set_last_seen(&Timestamp::from(LAST_SEEN_MICROS));
    let encoded_packet = packet.encoded_packet();
    let timestamp = packet.timestamp().as_u64();

    PacketVector {
        timestamp_micros: timestamp,
        last_seen_micros: LAST_SEEN_MICROS,
        signature_hex: hex::encode(packet.signature().to_bytes()),
        signable_hex: hex::encode(signable(timestamp, &encoded_packet)),
        encoded_packet_hex: hex::encode(encoded_packet),
        signed_packet_hex: hex::encode(packet.as_bytes()),
        relay_payload_hex: hex::encode(packet.to_relay_payload()),
        serialized_hex: hex::encode(packet.serialize()),
        ttl_default: packet.ttl(300, 86_400),
        ttl_unclamped: packet.ttl(0, 86_400),
        records: record_summaries(&packet),
        lookups: vec![
            lookup_vector(&packet, "@"),
            lookup_vector(&packet, "_svc"),
            lookup_vector(&packet, &format!("*.{}", packet.public_key().to_z32())),
            lookup_vector(
                &packet,
                &format!("*.example.{}", packet.public_key().to_z32()),
            ),
        ],
    }
}

fn record_summaries(packet: &SignedPacket) -> Vec<RecordSummary> {
    packet
        .all_resource_records()
        .map(|record| RecordSummary {
            name: record.name.to_string(),
            record_type: record_type(&record.rdata).to_string(),
            ttl: record.ttl,
        })
        .collect()
}

const fn record_type(rdata: &RData<'_>) -> &'static str {
    match rdata {
        RData::A(_) => "A",
        RData::AAAA(_) => "AAAA",
        RData::CNAME(_) => "CNAME",
        RData::TXT(_) => "TXT",
        RData::HTTPS(_) => "HTTPS",
        RData::SVCB(_) => "SVCB",
        _ => "UNSUPPORTED",
    }
}

fn lookup_vector(packet: &SignedPacket, name: &str) -> LookupVector {
    LookupVector {
        name: name.to_string(),
        names: lookup_names(packet, name),
    }
}

fn lookup_names(packet: &SignedPacket, name: &str) -> Vec<String> {
    packet
        .resource_records(name)
        .map(|record| record.name.to_string())
        .collect()
}

fn https_binding() -> Result<SVCB<'static>, Box<dyn Error>> {
    let mut binding = SVCB::new(1, name("svc.example.com")?);
    binding.set_alpn(&["h2".try_into()?, "h3".try_into()?]);
    binding.set_port(443);
    binding.set_ipv4hint(&[u32::from(Ipv4Addr::new(192, 0, 2, 1))]);
    binding.set_ipv6hint(&[u128::from("2001:db8::1".parse::<Ipv6Addr>()?)]);
    Ok(binding.into_owned())
}

fn svcb_binding() -> Result<SVCB<'static>, Box<dyn Error>> {
    Ok(SVCB::new(0, name(".")?)
        .with_param(SVCParam::Unknown(667, b"hello\xd2qoo"[..].into()))
        .into_owned())
}

fn name(input: &str) -> Result<Name<'static>, Box<dyn Error>> {
    Ok(Name::new(input)?.into_owned())
}

fn signable(timestamp: u64, encoded_packet: &[u8]) -> Vec<u8> {
    let mut bytes = format!("3:seqi{}e1:v{}:", timestamp, encoded_packet.len()).into_bytes();
    bytes.extend_from_slice(encoded_packet);
    bytes
}

fn ensure_eq<T>(left: &T, right: &T, name: &str) -> Result<(), Box<dyn Error>>
where
    T: std::fmt::Debug + PartialEq,
{
    if left == right {
        return Ok(());
    }
    Err(format!("{name} mismatch: left={left:?} right={right:?}").into())
}
