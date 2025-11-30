mod bpf;
mod config;
mod telemetry;
mod utils;

use anyhow::Result;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Starting network monitor agent...");

    telemetry::run().await
}
