use anyhow::Result;
use log::info;

mod domains;
mod init;
mod maps;
mod metrics;
mod network;
mod telemetry;
mod types;
mod xxh64;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Starting network monitor agent...");

    telemetry::run().await
}
