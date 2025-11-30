use anyhow::{Result, anyhow};
use pnet::datalink;

pub fn get_default_interface() -> Result<String> {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4()) {
            return Ok(iface.name);
        }
    }
    Err(anyhow!("No suitable network interface found"))
}
