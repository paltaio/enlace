#![warn(clippy::all)]
#![warn(clippy::pedantic)]

mod harness;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    harness::run_from_args(std::env::args()).await
}
