use anyhow::Result;
use log::info;

mod domains;
mod init;
mod maps;
mod metrics;
mod network;
mod server;
mod telemetry;
mod types;
mod xxh64;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Starting network monitor agent...");

    let server_handle = tokio::spawn(async {
        if let Err(e) = server::run_server("[::1]:50051").await {
            log::error!("Server error: {}", e);
        }
    });

    let telemetry_result = telemetry::run().await;

    server_handle.await?;

    telemetry_result
}
