use std::error::Error;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use enlace::{Config, ConfiguredTransport, Namespace, TransportKind};
use enlace_testkit::{DelayingTransport, InMemoryTransport, LossyTransport};

const SAMPLES: usize = 25;
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(2);
const SEED: [u8; 32] = [8; 32];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    for scenario in scenarios().await? {
        let stats = run_scenario(&scenario).await?;
        println!(
            "{:<24} min={:>5}us median={:>5}us p95={:>5}us max={:>5}us avg={:>5}us",
            scenario.name,
            stats.min.as_micros(),
            stats.median.as_micros(),
            stats.p95.as_micros(),
            stats.max.as_micros(),
            stats.avg_micros,
        );
    }

    Ok(())
}

struct Scenario {
    name: &'static str,
    sender: Namespace,
    receiver: Namespace,
}

struct Stats {
    min: Duration,
    median: Duration,
    p95: Duration,
    max: Duration,
    avg_micros: u128,
}

async fn scenarios() -> Result<Vec<Scenario>, Box<dyn Error>> {
    let single = InMemoryTransport::new();
    let delayed = InMemoryTransport::new();
    let fast = InMemoryTransport::new();
    let fanout_delayed = InMemoryTransport::new();
    let dropped = InMemoryTransport::new();
    let backup = InMemoryTransport::new();
    let duplicate = InMemoryTransport::new();

    Ok(vec![
        scenario(
            "single-memory",
            vec![transport(TransportKind::Http, single.clone())],
            vec![transport(TransportKind::Http, single)],
        )
        .await?,
        scenario(
            "single-delayed",
            vec![transport(
                TransportKind::Http,
                DelayingTransport::with_inner(delayed.clone())
                    .with_max_delay(Duration::from_millis(10)),
            )],
            vec![transport(
                TransportKind::Http,
                DelayingTransport::with_inner(delayed).with_max_delay(Duration::from_millis(10)),
            )],
        )
        .await?,
        scenario(
            "fanout-fast-delayed",
            vec![
                transport(TransportKind::Http, fast.clone()),
                transport(
                    TransportKind::Dht,
                    DelayingTransport::with_inner(fanout_delayed.clone())
                        .with_max_delay(Duration::from_millis(10)),
                ),
            ],
            vec![
                transport(TransportKind::Http, fast),
                transport(
                    TransportKind::Dht,
                    DelayingTransport::with_inner(fanout_delayed)
                        .with_max_delay(Duration::from_millis(10)),
                ),
            ],
        )
        .await?,
        scenario(
            "fanout-lossy-backup",
            vec![
                transport(
                    TransportKind::Http,
                    LossyTransport::with_inner(dropped.clone()).with_drop_percent(100),
                ),
                transport(
                    TransportKind::Dht,
                    DelayingTransport::with_inner(backup.clone())
                        .with_max_delay(Duration::from_millis(5)),
                ),
                transport(TransportKind::Pkarr, duplicate.clone()),
            ],
            vec![
                transport(
                    TransportKind::Http,
                    LossyTransport::with_inner(dropped).with_drop_percent(100),
                ),
                transport(
                    TransportKind::Dht,
                    DelayingTransport::with_inner(backup).with_max_delay(Duration::from_millis(5)),
                ),
                transport(TransportKind::Pkarr, duplicate),
            ],
        )
        .await?,
    ])
}

async fn scenario(
    name: &'static str,
    sender_transports: Vec<ConfiguredTransport>,
    receiver_transports: Vec<ConfiguredTransport>,
) -> Result<Scenario, Box<dyn Error>> {
    let sender = Namespace::open(&SEED, config(sender_transports)).await?;
    let receiver = Namespace::open(&SEED, config(receiver_transports)).await?;
    Ok(Scenario {
        name,
        sender,
        receiver,
    })
}

async fn run_scenario(scenario: &Scenario) -> Result<Stats, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        let mut name = String::with_capacity(32);
        write!(&mut name, "bench/{}/{}", scenario.name, i)?;
        let payload = vec![u8::try_from(i)?];
        let mailbox = scenario.receiver.mailbox(&name)?;
        let expected = payload.clone();
        let mut recv_task = tokio::spawn(async move {
            let received = mailbox.recv().await?;
            Ok::<_, enlace::RecvError>((Instant::now(), received.payload))
        });

        tokio::task::yield_now().await;
        let started = Instant::now();
        scenario.sender.mailbox(&name)?.send(&payload).await?;

        let (received_at, received) =
            match tokio::time::timeout(SAMPLE_TIMEOUT, &mut recv_task).await {
                Ok(joined) => joined??,
                Err(err) => {
                    recv_task.abort();
                    return Err(Box::new(err));
                }
            };
        assert_eq!(received, expected);
        samples.push(received_at.duration_since(started));
    }

    Ok(Stats::from_samples(samples))
}

fn config(transports: Vec<ConfiguredTransport>) -> Config {
    Config {
        transports,
        ..Config::default()
    }
}

fn transport<T>(kind: TransportKind, transport: T) -> ConfiguredTransport
where
    T: enlace::Transport + 'static,
{
    ConfiguredTransport::new(kind, Arc::new(transport))
}

impl Stats {
    fn from_samples(mut samples: Vec<Duration>) -> Self {
        samples.sort_unstable();
        let total_micros: u128 = samples.iter().map(Duration::as_micros).sum();
        let avg_micros = total_micros / samples.len() as u128;
        let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);

        Self {
            min: samples[0],
            median: samples[samples.len() / 2],
            p95: samples[p95_index],
            max: samples[samples.len() - 1],
            avg_micros,
        }
    }
}
