use crate::config::Settings;
use common::{MODE_ENFORCE, MODE_GATEWAY, MODE_MONITOR};
use pnet::datalink;
use pnet::ipnetwork::IpNetwork;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Monitor,
    Enforce,
    Gateway,
}

impl ResponseMode {
    pub fn as_kernel_value(self) -> u8 {
        match self {
            Self::Monitor => MODE_MONITOR,
            Self::Enforce => MODE_ENFORCE,
            Self::Gateway => MODE_GATEWAY,
        }
    }
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Monitor => "monitor",
            Self::Enforce => "enforce",
            Self::Gateway => "gateway",
        })
    }
}

impl FromStr for ResponseMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "monitor" => Ok(Self::Monitor),
            "enforce" => Ok(Self::Enforce),
            "gateway" => Ok(Self::Gateway),
            other => Err(ParseError(format!(
                "unknown response mode {other:?}, expected monitor, enforce or gateway"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

impl Ipv4Prefix {
    pub fn host(addr: Ipv4Addr) -> Self {
        Self { addr, len: 32 }
    }
}

impl FromStr for Ipv4Prefix {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (addr, len) = match s.split_once('/') {
            Some((addr, len)) => (
                addr,
                len.parse::<u8>()
                    .map_err(|_| ParseError(format!("invalid prefix length in {s:?}")))?,
            ),
            None => (s, 32),
        };
        if len > 32 {
            return Err(ParseError(format!("prefix length above 32 in {s:?}")));
        }
        let addr = addr
            .parse::<Ipv4Addr>()
            .map_err(|_| ParseError(format!("invalid IPv4 address in {s:?}")))?;

        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Ok(Self {
            addr: Ipv4Addr::from(u32::from(addr) & mask),
            len,
        })
    }
}

pub fn parse_prefix_list(raw: &str) -> Result<Vec<Ipv4Prefix>, ParseError> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::parse)
        .collect()
}

pub fn nameservers(resolv_conf: &str) -> Vec<Ipv4Prefix> {
    resolv_conf
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().parse::<Ipv4Addr>().ok())
        .map(Ipv4Prefix::host)
        .collect()
}

pub fn default_gateway(proc_net_route: &str) -> Option<Ipv4Prefix> {
    const RTF_GATEWAY: u32 = 0x2;

    proc_net_route.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let destination = u32::from_str_radix(fields.get(1)?, 16).ok()?;
        let gateway = u32::from_str_radix(fields.get(2)?, 16).ok()?;
        let flags = u32::from_str_radix(fields.get(3)?, 16).ok()?;

        (destination == 0 && flags & RTF_GATEWAY != 0 && gateway != 0)
            .then(|| Ipv4Prefix::host(Ipv4Addr::from(gateway.to_ne_bytes())))
    })
}

fn local_addresses() -> Vec<Ipv4Prefix> {
    datalink::interfaces()
        .iter()
        .flat_map(|iface| iface.ips.iter())
        .filter_map(|network| match network {
            IpNetwork::V4(v4) => Some(Ipv4Prefix::host(v4.ip())),
            IpNetwork::V6(_) => None,
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct ResponseConfig {
    pub mode: ResponseMode,
    pub quarantine_ttl: Duration,
    pub allowlist: Vec<Ipv4Prefix>,
}

impl ResponseConfig {
    pub fn from_settings(settings: &Settings) -> Self {
        let resolv_conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let routes = std::fs::read_to_string("/proc/net/route").unwrap_or_default();

        let mut allowlist = local_addresses();
        allowlist.extend(nameservers(&resolv_conf));
        allowlist.extend(default_gateway(&routes));
        allowlist.extend(settings.allowlist_extra.iter().copied());
        allowlist.sort_by_key(|p| (u32::from(p.addr), p.len));
        allowlist.dedup();

        Self {
            mode: settings.response_mode,
            quarantine_ttl: settings.quarantine_ttl,
            allowlist,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(s: &str) -> Ipv4Prefix {
        s.parse().expect("valid prefix")
    }

    #[test]
    fn mode_parses_case_insensitively_and_maps_to_kernel_values() {
        assert_eq!("monitor".parse(), Ok(ResponseMode::Monitor));
        assert_eq!(" Enforce ".parse(), Ok(ResponseMode::Enforce));
        assert_eq!("GATEWAY".parse(), Ok(ResponseMode::Gateway));
        assert!("block".parse::<ResponseMode>().is_err());

        assert_eq!(ResponseMode::Monitor.as_kernel_value(), MODE_MONITOR);
        assert_eq!(ResponseMode::Enforce.as_kernel_value(), MODE_ENFORCE);
        assert_eq!(ResponseMode::Gateway.as_kernel_value(), MODE_GATEWAY);
    }

    #[test]
    fn prefix_parses_hosts_and_networks_and_masks_host_bits() {
        assert_eq!(
            prefix("10.0.0.1"),
            Ipv4Prefix::host(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            prefix("192.168.1.77/24"),
            Ipv4Prefix {
                addr: Ipv4Addr::new(192, 168, 1, 0),
                len: 24
            }
        );
        assert_eq!(prefix("1.2.3.4/0").len, 0);
    }

    #[test]
    fn invalid_prefixes_are_rejected() {
        for raw in ["", "10.0.0", "10.0.0.1/33", "10.0.0.1/x", "::1", "a.b.c.d"] {
            assert!(raw.parse::<Ipv4Prefix>().is_err(), "{raw:?}");
        }
    }

    #[test]
    fn prefix_list_skips_blank_entries_and_fails_on_bad_ones() {
        let list = parse_prefix_list("10.0.0.1, 192.168.0.0/16,,").unwrap();
        assert_eq!(list.len(), 2);
        assert!(parse_prefix_list("10.0.0.1,nope").is_err());
        assert!(parse_prefix_list("").unwrap().is_empty());
    }

    #[test]
    fn nameservers_are_read_from_resolv_conf() {
        let content =
            "# comment\nnameserver 1.1.1.1\nsearch lan\nnameserver ::1\nnameserver  192.168.2.1 \n";
        assert_eq!(
            nameservers(content),
            vec![
                Ipv4Prefix::host(Ipv4Addr::new(1, 1, 1, 1)),
                Ipv4Prefix::host(Ipv4Addr::new(192, 168, 2, 1)),
            ]
        );
    }

    #[test]
    fn default_gateway_is_read_from_proc_net_route() {
        let content = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             enp9s0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n\
             enp9s0\t00000000\t{:08X}\t0003\t0\t0\t100\t00000000\n",
            u32::from_ne_bytes([192, 168, 2, 1])
        );
        assert_eq!(
            default_gateway(&content),
            Some(Ipv4Prefix::host(Ipv4Addr::new(192, 168, 2, 1)))
        );
        assert_eq!(default_gateway("Iface\tDestination\n"), None);
    }
}
