use anyhow::Result;
use tokio::main;

#[main]
async fn main() -> Result<()> {
    println!("Hello, async world!");
    Ok(())
}
