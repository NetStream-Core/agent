use anyhow::{Context, Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use super::paths;

const DEFAULT_OTLP_ENDPOINT: &str = "http://127.0.0.1:4317";
const DEFAULT_REPORT_INTERVAL_MS: u64 = 1000;
const DEFAULT_HEALTH_HOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_HEALTH_PORT: u16 = 8081;

#[derive(Debug, Clone)]
pub struct Settings {
    pub otlp_endpoint: String,
    pub report_interval: Duration,
    pub health_addr: SocketAddr,
    pub malware_domains_file: PathBuf,
    pub bpf_object_file: PathBuf,
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
        let bpf_object_file = lookup("BPF_OBJECT_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(paths::bpf_object);

        Ok(Self {
            otlp_endpoint,
            report_interval: Duration::from_millis(interval_ms),
            health_addr: SocketAddr::new(health_host, health_port),
            malware_domains_file,
            bpf_object_file,
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
        assert_eq!(s.bpf_object_file, paths::bpf_object());
    }

    #[test]
    fn environment_overrides_defaults() {
        let s = settings(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317"),
            ("REPORT_INTERVAL_MS", "1000"),
            ("HEALTH_HOST", "0.0.0.0"),
            ("HEALTH_PORT", "9090"),
            ("MALWARE_DOMAINS_FILE", "/etc/netstream/domains.txt"),
            ("BPF_OBJECT_FILE", "/usr/lib/netstream/prog.bpf.o"),
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
            s.bpf_object_file,
            PathBuf::from("/usr/lib/netstream/prog.bpf.o")
        );
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
