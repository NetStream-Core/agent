use anyhow::Result;
use log::info;
use tokio::main;

#[main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("Agent started. Hello from logger!");
    Ok(())
}
