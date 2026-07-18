mod bpf;
mod config;
mod domain_manager;
mod health;
mod telemetry;
mod utils;

use anyhow::Result;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!(
        "Starting NetStream-Core Agent v{}",
        env!("CARGO_PKG_VERSION")
    );

    health::start_health_server();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    health::mark_ready();
    info!("Health server started. Agent is ready.");

    let result = telemetry::run::run().await;

    health::shutdown_health_server().await;
    info!("Agent shutting down...");

    result
}
