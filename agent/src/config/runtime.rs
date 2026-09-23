use anyhow::{Context, Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use super::paths;
use crate::response::{Ipv4Prefix, ResponseMode, parse_prefix_list};

const DEFAULT_OTLP_ENDPOINT: &str = "http://127.0.0.1:4317";
const DEFAULT_REPORT_INTERVAL_MS: u64 = 1000;
const DEFAULT_HEALTH_HOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_HEALTH_PORT: u16 = 8081;
const DEFAULT_QUARANTINE_TTL_SECS: u64 = 60;
const DEFAULT_FLOW_TABLE_ENTRIES: u32 = 10240;
const MIN_FLOW_TABLE_ENTRIES: u32 = 1024;
const DEFAULT_FLOW_LOG_TOP_N: usize = 2000;
const DEFAULT_NEW_FLOWS_PER_SECOND: u32 = 100;
const MIN_NEW_FLOWS_PER_SECOND: u32 = 10;
const DEFAULT_RELOAD_POLL_MS: u64 = 5000;

#[derive(Debug, Clone)]
pub struct Settings {
    pub otlp_endpoint: String,
    pub report_interval: Duration,
    pub health_addr: SocketAddr,
    pub malware_domains_file: PathBuf,
    pub public_suffix_list_file: PathBuf,
    pub bpf_object_file: PathBuf,
    pub response_mode: ResponseMode,
    pub quarantine_ttl: Duration,
    pub allowlist_extra: Vec<Ipv4Prefix>,
    pub dns_events: bool,
    pub export_logs: bool,
    pub host_id: Option<String>,
    pub collapse_ephemeral_ports: bool,
    pub flow_table_entries: u32,
    pub flow_log_top_n: usize,
    pub new_flows_per_second: u32,
    pub bpf_stats: bool,
    pub reload_poll_interval: Duration,
}

impl Settings {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let otlp_endpoint = lookup("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_else(|| DEFAULT_OTLP_ENDPOINT.to_string());

        let interval_ms = parse_or(&lookup, "REPORT_INTERVAL_MS", DEFAULT_REPORT_INTERVAL_MS)?;
        if interval_ms == 0 {
            return Err(anyhow!("REPORT_INTERVAL_MS must be greater than zero"));
        }

        let health_host = parse_or(&lookup, "HEALTH_HOST", DEFAULT_HEALTH_HOST)?;
        let health_port = parse_or(&lookup, "HEALTH_PORT", DEFAULT_HEALTH_PORT)?;

        let malware_domains_file = lookup("MALWARE_DOMAINS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(paths::malware_domains);
        let public_suffix_list_file = lookup("PUBLIC_SUFFIX_LIST_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(paths::public_suffix_list);
        let bpf_object_file = lookup("BPF_OBJECT_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(paths::bpf_object);

        let response_mode = parse_or(&lookup, "RESPONSE_MODE", ResponseMode::Monitor)?;

        let quarantine_ttl_secs =
            parse_or(&lookup, "QUARANTINE_TTL_SECS", DEFAULT_QUARANTINE_TTL_SECS)?;
        if quarantine_ttl_secs == 0 {
            return Err(anyhow!("QUARANTINE_TTL_SECS must be greater than zero"));
        }

        let allowlist_extra = match lookup("QUARANTINE_ALLOWLIST") {
            Some(raw) => {
                parse_prefix_list(&raw).context("invalid value for QUARANTINE_ALLOWLIST")?
            }
            None => Vec::new(),
        };

        let dns_events = parse_or(&lookup, "DNS_EVENTS", true)?;
        let export_logs = parse_or(&lookup, "EXPORT_LOGS", true)?;
        let host_id = lookup("HOST_ID");
        let collapse_ephemeral_ports = parse_or(&lookup, "COLLAPSE_EPHEMERAL_PORTS", true)?;
        let flow_table_entries =
            parse_or(&lookup, "FLOW_TABLE_ENTRIES", DEFAULT_FLOW_TABLE_ENTRIES)?;
        if flow_table_entries < MIN_FLOW_TABLE_ENTRIES {
            return Err(anyhow!(
                "FLOW_TABLE_ENTRIES must be at least {MIN_FLOW_TABLE_ENTRIES}"
            ));
        }
        let flow_log_top_n = parse_or(&lookup, "FLOW_LOG_TOP_N", DEFAULT_FLOW_LOG_TOP_N)?;
        let new_flows_per_second =
            parse_or(&lookup, "FLOW_NEW_PER_SECOND", DEFAULT_NEW_FLOWS_PER_SECOND)?;
        if new_flows_per_second < MIN_NEW_FLOWS_PER_SECOND {
            return Err(anyhow!(
                "FLOW_NEW_PER_SECOND must be at least {MIN_NEW_FLOWS_PER_SECOND}"
            ));
        }

        let bpf_stats = parse_or(&lookup, "BPF_STATS", true)?;

        let reload_poll_ms = parse_or(&lookup, "RELOAD_POLL_MS", DEFAULT_RELOAD_POLL_MS)?;
        if reload_poll_ms == 0 {
            return Err(anyhow!("RELOAD_POLL_MS must be greater than zero"));
        }

        Ok(Self {
            otlp_endpoint,
            report_interval: Duration::from_millis(interval_ms),
            health_addr: SocketAddr::new(health_host, health_port),
            malware_domains_file,
            public_suffix_list_file,
            bpf_object_file,
            response_mode,
            quarantine_ttl: Duration::from_secs(quarantine_ttl_secs),
            allowlist_extra,
            dns_events,
            export_logs,
            host_id,
            collapse_ephemeral_ports,
            flow_table_entries,
            flow_log_top_n,
            new_flows_per_second,
            bpf_stats,
            reload_poll_interval: Duration::from_millis(reload_poll_ms),
        })
    }
}

fn parse_or<T>(lookup: &impl Fn(&str) -> Option<String>, key: &str, default: T) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match lookup(key) {
        Some(raw) => raw
            .trim()
            .parse()
            .with_context(|| format!("invalid value for {key}: {raw:?}")),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn settings(vars: &[(&str, &str)]) -> Result<Settings> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Settings::from_lookup(|key| vars.get(key).cloned())
    }

    #[test]
    fn defaults_bind_health_to_loopback() {
        let s = settings(&[]).expect("defaults");
        assert_eq!(s.otlp_endpoint, "http://127.0.0.1:4317");
        assert_eq!(s.report_interval, Duration::from_secs(1));
        assert_eq!(s.health_addr, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(s.malware_domains_file, paths::malware_domains());
        assert_eq!(s.public_suffix_list_file, paths::public_suffix_list());
        assert_eq!(s.bpf_object_file, paths::bpf_object());
        assert_eq!(s.response_mode, ResponseMode::Monitor);
        assert_eq!(s.quarantine_ttl, Duration::from_secs(60));
        assert!(s.allowlist_extra.is_empty());
        assert!(s.dns_events);
        assert!(s.export_logs);
        assert_eq!(s.host_id, None);
        assert!(s.collapse_ephemeral_ports);
        assert_eq!(s.flow_table_entries, 10240);
        assert_eq!(s.flow_log_top_n, 2000);
        assert_eq!(s.new_flows_per_second, 100);
        assert!(s.bpf_stats);
        assert_eq!(s.reload_poll_interval, Duration::from_secs(5));
    }

    #[test]
    fn new_flow_budget_is_configurable_and_validated() {
        assert_eq!(
            settings(&[("FLOW_NEW_PER_SECOND", "1000")])
                .unwrap()
                .new_flows_per_second,
            1000
        );
        assert!(settings(&[("FLOW_NEW_PER_SECOND", "5")]).is_err());
        assert!(settings(&[("FLOW_NEW_PER_SECOND", "lots")]).is_err());
    }

    #[test]
    fn flow_limits_are_configurable_and_validated() {
        let s = settings(&[
            ("COLLAPSE_EPHEMERAL_PORTS", "false"),
            ("FLOW_TABLE_ENTRIES", "65536"),
            ("FLOW_LOG_TOP_N", "0"),
        ])
        .unwrap();
        assert!(!s.collapse_ephemeral_ports);
        assert_eq!(s.flow_table_entries, 65536);
        assert_eq!(s.flow_log_top_n, 0);

        assert!(settings(&[("FLOW_TABLE_ENTRIES", "100")]).is_err());
        assert!(settings(&[("FLOW_TABLE_ENTRIES", "many")]).is_err());
        assert!(settings(&[("FLOW_LOG_TOP_N", "-1")]).is_err());
    }

    #[test]
    fn log_export_and_host_id_are_configurable() {
        let s = settings(&[("EXPORT_LOGS", "false"), ("HOST_ID", "sensor-7")]).unwrap();
        assert!(!s.export_logs);
        assert_eq!(s.host_id.as_deref(), Some("sensor-7"));
        assert!(settings(&[("EXPORT_LOGS", "sometimes")]).is_err());
    }

    #[test]
    fn bpf_stats_can_be_disabled() {
        assert!(!settings(&[("BPF_STATS", "false")]).unwrap().bpf_stats);
        assert!(settings(&[("BPF_STATS", "maybe")]).is_err());
    }

    #[test]
    fn reload_poll_interval_is_configurable_and_validated() {
        assert_eq!(
            settings(&[("RELOAD_POLL_MS", "1000")])
                .unwrap()
                .reload_poll_interval,
            Duration::from_secs(1)
        );
        assert!(settings(&[("RELOAD_POLL_MS", "0")]).is_err());
        assert!(settings(&[("RELOAD_POLL_MS", "soon")]).is_err());
    }

    #[test]
    fn dns_events_can_be_disabled() {
        assert!(!settings(&[("DNS_EVENTS", "false")]).unwrap().dns_events);
        assert!(settings(&[("DNS_EVENTS", "maybe")]).is_err());
    }

    #[test]
    fn response_settings_are_read_from_environment() {
        let s = settings(&[
            ("RESPONSE_MODE", "gateway"),
            ("QUARANTINE_TTL_SECS", "5"),
            ("QUARANTINE_ALLOWLIST", "10.0.0.1, 192.168.0.0/16"),
        ])
        .expect("response settings");

        assert_eq!(s.response_mode, ResponseMode::Gateway);
        assert_eq!(s.quarantine_ttl, Duration::from_secs(5));
        assert_eq!(s.allowlist_extra.len(), 2);
    }

    #[test]
    fn invalid_response_settings_are_rejected() {
        assert!(settings(&[("RESPONSE_MODE", "block")]).is_err());
        assert!(settings(&[("QUARANTINE_TTL_SECS", "0")]).is_err());
        assert!(settings(&[("QUARANTINE_ALLOWLIST", "10.0.0.1,nope")]).is_err());
    }

    #[test]
    fn environment_overrides_defaults() {
        let s = settings(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317"),
            ("REPORT_INTERVAL_MS", "1000"),
            ("HEALTH_HOST", "0.0.0.0"),
            ("HEALTH_PORT", "9090"),
            ("MALWARE_DOMAINS_FILE", "/etc/netstream/domains.txt"),
            (
                "PUBLIC_SUFFIX_LIST_FILE",
                "/etc/netstream/public_suffix_list.dat",
            ),
            ("BPF_OBJECT_FILE", "/usr/lib/netstream/prog.bpf.o"),
            ("RELOAD_POLL_MS", "2000"),
        ])
        .expect("overrides");

        assert_eq!(s.otlp_endpoint, "http://collector:4317");
        assert_eq!(s.report_interval, Duration::from_secs(1));
        assert_eq!(s.health_addr, "0.0.0.0:9090".parse().unwrap());
        assert_eq!(
            s.malware_domains_file,
            PathBuf::from("/etc/netstream/domains.txt")
        );
        assert_eq!(
            s.public_suffix_list_file,
            PathBuf::from("/etc/netstream/public_suffix_list.dat")
        );
        assert_eq!(
            s.bpf_object_file,
            PathBuf::from("/usr/lib/netstream/prog.bpf.o")
        );
        assert_eq!(s.reload_poll_interval, Duration::from_secs(2));
    }

    #[test]
    fn zero_report_interval_is_rejected() {
        assert!(settings(&[("REPORT_INTERVAL_MS", "0")]).is_err());
    }

    #[test]
    fn invalid_values_are_rejected_with_the_variable_name() {
        let err = settings(&[("HEALTH_PORT", "not-a-port")]).unwrap_err();
        assert!(err.to_string().contains("HEALTH_PORT"));

        assert!(settings(&[("HEALTH_HOST", "nope")]).is_err());
        assert!(settings(&[("REPORT_INTERVAL_MS", "-5")]).is_err());
    }
}
