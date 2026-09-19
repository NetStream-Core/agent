use anyhow::{Result, anyhow};
use pnet::datalink;
use std::process::Command;

fn default_route_interface() -> Option<String> {
    let probe_ip = "8.8.8.8";
    let sudo_uid = std::env::var("SUDO_UID").ok();

    if let Some(uid) = &sudo_uid
        && let Some(iface) = run_ip_route_get(probe_ip, Some(uid))
    {
        return Some(iface);
    }

    run_ip_route_get(probe_ip, None)
}

fn run_ip_route_get(ip: &str, uid: Option<&String>) -> Option<String> {
    let mut cmd = Command::new("ip");
    cmd.args(["route", "get", ip]);
    if let Some(uid) = uid {
        cmd.args(["uid", uid]);
    }

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_dev_from_route_output(&stdout)
}

fn parse_dev_from_route_output(output: &str) -> Option<String> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .iter()
        .position(|&t| t == "dev")
        .and_then(|i| tokens.get(i + 1))
        .map(|s| s.to_string())
}

pub fn get_default_interface() -> Result<String> {
    if let Ok(name) = std::env::var("NETWORK_INTERFACE") {
        return Ok(name);
    }

    if let Some(iface) = default_route_interface() {
        return Ok(iface);
    }

    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4()) {
            return Ok(iface.name);
        }
    }

    Err(anyhow!("No suitable network interface found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dev_from_typical_route_get_output() {
        let output = "8.8.8.8 dev neko-tun table 2022 src 172.19.0.1 uid 1000 \n    cache \n";
        assert_eq!(
            parse_dev_from_route_output(output),
            Some("neko-tun".to_string())
        );
    }

    #[test]
    fn parses_dev_from_route_with_via_gateway() {
        let output = "8.8.8.8 via 192.168.2.1 dev enp9s0 src 192.168.2.37 uid 1000 \n    cache \n";
        assert_eq!(
            parse_dev_from_route_output(output),
            Some("enp9s0".to_string())
        );
    }

    #[test]
    fn returns_none_when_no_dev_token() {
        assert_eq!(parse_dev_from_route_output("garbage output"), None);
    }
}
