mod bpf;
mod config;
mod dns;
mod domain_manager;
mod health;
mod reload;
mod response;
mod telemetry;
mod utils;

use anyhow::Result;
use config::Settings;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!(
        "Starting NetStream-Core Agent v{}",
        env!("CARGO_PKG_VERSION")
    );

    let settings = Settings::from_env()?;

    health::start_health_server(settings.health_addr);

    let result = telemetry::run::run(&settings).await;

    health::shutdown_health_server().await;
    info!("Agent shutting down...");

    result
}
